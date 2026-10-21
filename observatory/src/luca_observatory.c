// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * luca-observatory - loads Luca's observatory BPF programs, attaches them to
 * one access-point interface and periodically writes a JSON snapshot of the
 * kernel's view of the device's traffic.
 *
 * Two BPF objects are used:
 *   luca_observatory.bpf.o  traffic classifiers; no CO-RE, loads without BTF;
 *   luca_drops.bpf.o        skb:kfree_skb drop reasons (raw tracepoint);
 *                           CO-RE, needs kernel BTF (or --btf). Optional: if
 *                           it cannot be loaded or attached, the classifiers
 *                           keep running and the snapshot says why.
 * They are separate because libbpf requires vmlinux BTF for every object
 * that carries CO-RE relocations, even for programs it does not load.
 *
 * Classifier attachment, in order of preference:
 *   1. TCX links (kernel >= 6.6, libbpf >= 1.3). Links belong to this
 *      process and disappear with it, even after a crash.
 *   2. A clsact qdisc with direct-action cls_bpf filters (any supported
 *      kernel). The filters use a fixed handle/priority, replace any stale
 *      instance left by a crashed run, and --detach-only removes them.
 *
 * Privileges: CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON (CAP_SYS_RESOURCE on
 * kernels < 5.11 for the memlock limit). Root is not required. --prog-stats
 * additionally needs CAP_SYS_ADMIN and is meant for overhead experiments.
 *
 * Timestamps measured by BPF are CLOCK_MONOTONIC nanoseconds and are written
 * unconverted. Each snapshot records one (CLOCK_REALTIME, CLOCK_MONOTONIC)
 * pair taken together, from which consumers may derive wall-clock times.
 *
 * The snapshot is always written, including when loading or attaching
 * fails, so that the analysis can report why kernel data is missing.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "luca_observatory.h"

#ifndef LIBBPF_MAJOR_VERSION
#error "libbpf >= 0.6 is required"
#endif

#if LIBBPF_MAJOR_VERSION > 1 || \
	(LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 3)
#define LUCA_HAVE_TCX 1
#endif

#ifndef LUCA_COMMIT
#define LUCA_COMMIT "unknown"
#endif

#define LUCA_VERSION "1.0.0"
#define LUCA_SCHEMA "luca.observatory/1"
#define LUCA_TC_HANDLE 0x4c55 /* "LU" */
#define LUCA_TC_PRIORITY 0x4c55
#define LUCA_MAX_SAMPLES 86400
#define LUCA_VMLINUX_BTF "/sys/kernel/btf/vmlinux"

_Static_assert(sizeof(struct luca_flow_key) == 40, "flow key layout");
_Static_assert(sizeof(struct luca_flow_dir) == 48, "flow dir layout");
_Static_assert(sizeof(struct luca_flow_value) == 128, "flow value layout");
_Static_assert(sizeof(struct luca_drop_key) == 28, "drop key layout");
_Static_assert(sizeof(struct luca_counter) == 16, "counter layout");

enum attach_pref { ATTACH_AUTO, ATTACH_TCX, ATTACH_TC };

/* Columns written for every timeline sample, after the two clocks. */
static const struct {
	const char *name;
	__u32 stat;
} timeline_cols[] = {
	{ "tx_skbs", LUCA_STAT_SKBS + LUCA_DIR_TX },
	{ "rx_skbs", LUCA_STAT_SKBS + LUCA_DIR_RX },
	{ "tx_segments", LUCA_STAT_SEGS + LUCA_DIR_TX },
	{ "rx_segments", LUCA_STAT_SEGS + LUCA_DIR_RX },
	{ "tx_bytes", LUCA_STAT_BYTES + LUCA_DIR_TX },
	{ "rx_bytes", LUCA_STAT_BYTES + LUCA_DIR_RX },
	{ "tx_pcap_filter_skbs", LUCA_STAT_PCAP_SKBS + LUCA_DIR_TX },
	{ "rx_pcap_filter_skbs", LUCA_STAT_PCAP_SKBS + LUCA_DIR_RX },
	{ "tx_pcap_filter_segments", LUCA_STAT_PCAP_SEGS + LUCA_DIR_TX },
	{ "rx_pcap_filter_segments", LUCA_STAT_PCAP_SEGS + LUCA_DIR_RX },
};
#define TIMELINE_COLS (sizeof(timeline_cols) / sizeof(timeline_cols[0]))

/* Per-direction counters written in the "counters" object. */
static const struct {
	const char *name;
	__u32 base;
} counter_names[] = {
	{ "skbs", LUCA_STAT_SKBS },
	{ "segments", LUCA_STAT_SEGS },
	{ "bytes", LUCA_STAT_BYTES },
	{ "ipv4", LUCA_STAT_IPV4 },
	{ "ipv6", LUCA_STAT_IPV6 },
	{ "arp", LUCA_STAT_ARP },
	{ "eapol", LUCA_STAT_EAPOL },
	{ "other_l2", LUCA_STAT_OTHER_L2 },
	{ "pcap_filter_skbs", LUCA_STAT_PCAP_SKBS },
	{ "pcap_filter_segments", LUCA_STAT_PCAP_SEGS },
	{ "parse_errors", LUCA_STAT_PARSE_ERR },
	{ "flows_not_recorded", LUCA_STAT_FLOW_FULL },
};
#define COUNTER_NAMES (sizeof(counter_names) / sizeof(counter_names[0]))

struct sample {
	double realtime;
	__u64 mono_ns;
	__u64 v[TIMELINE_COLS];
};

struct observatory {
	/* options */
	const char *iface;
	const char *output;
	const char *session;
	const char *bpf_dir;
	const char *btf_path;
	const char *ready_file;
	double interval;
	double flush_every;
	double duration;
	__u32 max_flows;
	__u32 max_drops;
	enum attach_pref pref;
	bool drops_wanted;
	bool prog_stats_wanted;
	bool verbose;

	/* runtime */
	int ifindex;
	int ncpus;
	void *percpu_buf;
	struct bpf_object *obj;      /* classifiers */
	struct bpf_object *drop_obj; /* drop reasons */
	struct bpf_program *prog_ingress, *prog_egress, *prog_drop;
	int fd_flows, fd_stats, fd_protocols;
	int fd_drops, fd_drop_stats, fd_config;
	struct bpf_link *link_ingress, *link_egress, *link_drop;
	bool tc_attached, tc_hook_created;
	struct btf *vmlinux_btf;
	bool btf_available;
	int stats_fd;
	char stats_note[160];
	__u64 stats[LUCA_STAT_MAX];
	__u64 drop_stats[LUCA_DROPSTAT_MAX];

	const char *status; /* starting | running | stopped | failed | interface_lost */
	const char *attach_mode; /* tcx | tc | none */
	char attach_note[256];
	const char *drop_status; /* attached | disabled | unavailable | failed */
	char drop_note[512];
	char error[512];

	/* health */
	double started_at;
	__u64 started_mono_ns;
	double rt_base;     /* CLOCK_REALTIME at the snapshot, seconds */
	__u64 mono_base_ns; /* CLOCK_MONOTONIC read immediately after */
	struct sample *samples;
	size_t n_samples, cap_samples;
	bool timeline_truncated;
	__u64 last_sample_ns;
	__u64 max_sample_gap_ns;
	unsigned snapshot_failures;
	size_t flow_entries, drop_entries;
};

static volatile sig_atomic_t stop_requested;
static bool verbose_libbpf;

static void on_signal(int sig)
{
	(void)sig;
	stop_requested = 1;
}

static int print_libbpf(enum libbpf_print_level level, const char *fmt,
			va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose_libbpf)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static double ts_seconds(const struct timespec *ts)
{
	return ts->tv_sec + ts->tv_nsec / 1e9;
}

static __u64 ts_ns(const struct timespec *ts)
{
	return (__u64)ts->tv_sec * 1000000000ULL + (__u64)ts->tv_nsec;
}

/* Reads CLOCK_REALTIME and CLOCK_MONOTONIC back to back. */
static void read_clocks(double *realtime, __u64 *mono_ns)
{
	struct timespec rt, mono;

	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_MONOTONIC, &mono);
	*realtime = ts_seconds(&rt);
	*mono_ns = ts_ns(&mono);
}

static void set_error(struct observatory *o, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(o->error, sizeof(o->error), fmt, ap);
	va_end(ap);
	fprintf(stderr, "luca-observatory: %s\n", o->error);
}

/* ---------------------------------------------------------------- JSON */

static void json_str(FILE *f, const char *s)
{
	if (!s) {
		fputs("null", f);
		return;
	}
	fputc('"', f);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			fprintf(f, "\\%c", c);
		else if (c < 0x20)
			fprintf(f, "\\u%04x", c);
		else
			fputc(c, f);
	}
	fputc('"', f);
}

static void json_ns(FILE *f, __u64 ns)
{
	if (ns)
		fprintf(f, "%llu", (unsigned long long)ns);
	else
		fputs("null", f);
}

static const char *dir_name(__u8 dir)
{
	return dir == LUCA_DIR_TX ? "tx" : "rx";
}

static void format_addr(__u8 family, const __u8 *addr, char *buf, size_t len)
{
	if (family == 4)
		inet_ntop(AF_INET, addr, buf, len);
	else if (family == 6)
		inet_ntop(AF_INET6, addr, buf, len);
	else
		snprintf(buf, len, "unknown");
}

/* ---------------------------------------------------- drop reason names */

static const struct btf_type *find_enum(const struct btf *btf, const char *name)
{
	int id = btf__find_by_name_kind(btf, name, BTF_KIND_ENUM);

	return id > 0 ? btf__type_by_id(btf, id) : NULL;
}

static const char *enum_name(const struct btf *btf, const struct btf_type *t,
			     __u32 value)
{
	const struct btf_enum *e = btf_enum(t);

	for (int i = 0; i < btf_vlen(t); i++, e++)
		if ((__u32)e->val == value)
			return btf__name_by_offset(btf, e->name_off);
	return NULL;
}

static const char *strip_prefix(const char *s, const char *prefix)
{
	size_t n = strlen(prefix);

	return s && strncmp(s, prefix, n) == 0 ? s + n : s;
}

/* Names drop reasons with the running kernel's own enums, because their
 * numeric values change between kernel versions. */
static bool drop_reason_name(const struct observatory *o, __u32 reason,
			     char *buf, size_t len)
{
	const struct btf_type *t;
	const char *name;
	__u32 subsys = reason >> 16;

	if (!o->vmlinux_btf || !reason)
		return false;

	if (subsys) {
		t = find_enum(o->vmlinux_btf, "skb_drop_reason_subsys");
		name = t ? enum_name(o->vmlinux_btf, t, subsys) : NULL;
		if (!name)
			return false;
		snprintf(buf, len, "%s:%u",
			 strip_prefix(name, "SKB_DROP_REASON_SUBSYS_"),
			 reason & 0xffff);
		return true;
	}

	t = find_enum(o->vmlinux_btf, "skb_drop_reason");
	name = t ? enum_name(o->vmlinux_btf, t, reason) : NULL;
	if (!name)
		return false;
	name = strip_prefix(name, "SKB_DROP_REASON_");
	snprintf(buf, len, "%s", strip_prefix(name, "SKB_"));
	return true;
}

/* -------------------------------------------------------- map reading */

static int read_percpu_u64(struct observatory *o, int fd, __u32 key, __u64 *out)
{
	__u64 *vals = o->percpu_buf;

	*out = 0;
	if (bpf_map_lookup_elem(fd, &key, vals))
		return -errno;
	for (int cpu = 0; cpu < o->ncpus; cpu++)
		*out += vals[cpu];
	return 0;
}

static int read_percpu_counter(struct observatory *o, int fd, __u32 key,
			       struct luca_counter *out)
{
	struct luca_counter *vals = o->percpu_buf;

	memset(out, 0, sizeof(*out));
	if (bpf_map_lookup_elem(fd, &key, vals))
		return -errno;
	for (int cpu = 0; cpu < o->ncpus; cpu++) {
		out->packets += vals[cpu].packets;
		out->bytes += vals[cpu].bytes;
	}
	return 0;
}

static void read_stats(struct observatory *o)
{
	for (__u32 i = 0; o->fd_stats >= 0 && i < LUCA_STAT_MAX; i++)
		read_percpu_u64(o, o->fd_stats, i, &o->stats[i]);
	for (__u32 i = 0; o->fd_drop_stats >= 0 && i < LUCA_DROPSTAT_MAX; i++)
		read_percpu_u64(o, o->fd_drop_stats, i, &o->drop_stats[i]);
}

static void take_sample(struct observatory *o)
{
	struct sample *s;
	double realtime;
	__u64 mono_ns;

	if (o->fd_stats < 0)
		return;
	read_stats(o);
	read_clocks(&realtime, &mono_ns);
	if (o->last_sample_ns && mono_ns - o->last_sample_ns > o->max_sample_gap_ns)
		o->max_sample_gap_ns = mono_ns - o->last_sample_ns;
	o->last_sample_ns = mono_ns;

	if (o->n_samples == LUCA_MAX_SAMPLES) {
		o->timeline_truncated = true;
		return;
	}
	if (o->n_samples == o->cap_samples) {
		size_t cap = o->cap_samples ? o->cap_samples * 2 : 256;
		struct sample *grown = realloc(o->samples, cap * sizeof(*grown));

		if (!grown) {
			o->timeline_truncated = true;
			return;
		}
		o->samples = grown;
		o->cap_samples = cap;
	}
	s = &o->samples[o->n_samples++];
	s->realtime = realtime;
	s->mono_ns = mono_ns;
	for (size_t i = 0; i < TIMELINE_COLS; i++)
		s->v[i] = o->stats[timeline_cols[i].stat];
}

/* Kernel-accounted memory of a map, from /proc/self/fdinfo. */
static unsigned long long map_memlock(int fd)
{
	char path[64], line[128];
	unsigned long long value = 0;
	FILE *f;

	if (fd < 0)
		return 0;
	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
	f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "memlock: %llu", &value) == 1)
			break;
	fclose(f);
	return value;
}

/* ------------------------------------------------------- snapshot */

static void write_addresses(FILE *f, const struct observatory *o)
{
	struct ifaddrs *ifas, *ifa;
	bool first = true;

	fputs("[", f);
	if (getifaddrs(&ifas) == 0) {
		for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
			char buf[INET6_ADDRSTRLEN];
			const unsigned char *mask = NULL;
			int prefix = 0, mlen;

			if (!ifa->ifa_addr || strcmp(ifa->ifa_name, o->iface))
				continue;
			if (ifa->ifa_addr->sa_family == AF_INET) {
				inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					  buf, sizeof(buf));
				if (ifa->ifa_netmask)
					mask = (const unsigned char *)&((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
				mlen = 4;
			} else if (ifa->ifa_addr->sa_family == AF_INET6) {
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
					  buf, sizeof(buf));
				if (ifa->ifa_netmask)
					mask = (const unsigned char *)&((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
				mlen = 16;
			} else {
				continue;
			}
			for (int i = 0; mask && i < mlen; i++)
				prefix += __builtin_popcount(mask[i]);
			fprintf(f, "%s\"%s/%d\"", first ? "" : ", ", buf, prefix);
			first = false;
		}
		freeifaddrs(ifas);
	}
	fputs("]", f);
}

/* Link-layer address of the interface, used to tell capture directions apart. */
static void write_mac(FILE *f, const struct observatory *o)
{
	struct ifaddrs *ifas, *ifa;
	bool found = false;

	if (getifaddrs(&ifas) == 0) {
		for (ifa = ifas; ifa && !found; ifa = ifa->ifa_next) {
			const struct sockaddr_ll *ll = (const void *)ifa->ifa_addr;

			if (!ll || ll->sll_family != AF_PACKET || strcmp(ifa->ifa_name, o->iface) ||
			    ll->sll_halen != 6)
				continue;
			fprintf(f, "\"%02x:%02x:%02x:%02x:%02x:%02x\"", ll->sll_addr[0],
				ll->sll_addr[1], ll->sll_addr[2], ll->sll_addr[3],
				ll->sll_addr[4], ll->sll_addr[5]);
			found = true;
		}
		freeifaddrs(ifas);
	}
	if (!found)
		fputs("null", f);
}

static void write_flow_dir(FILE *f, const struct luca_flow_dir *d)
{
	fprintf(f, "{\"packets\": %llu, \"bytes\": %llu, \"first_ns\": ",
		(unsigned long long)d->packets, (unsigned long long)d->bytes);
	json_ns(f, d->first_ns);
	fputs(", \"last_ns\": ", f);
	json_ns(f, d->last_ns);
	if (d->packets)
		fprintf(f, ", \"tcp_flags\": %u, \"ttl_min\": %u, \"ttl_max\": %u",
			d->tcp_flags, d->ttl_min, d->ttl_max);
	else
		fputs(", \"tcp_flags\": 0, \"ttl_min\": null, \"ttl_max\": null", f);
	fprintf(f, ", \"retrans_or_reorder\": %u, \"fragments\": %s}", d->retrans,
		d->fragments ? "true" : "false");
}

static void write_flows(FILE *f, struct observatory *o)
{
	struct luca_flow_key key, next;
	struct luca_flow_value val;
	char local[INET6_ADDRSTRLEN], remote[INET6_ADDRSTRLEN];
	const void *prev = NULL;
	size_t n = 0;

	fputs("[", f);
	while (o->fd_flows >= 0 && bpf_map_get_next_key(o->fd_flows, prev, &next) == 0) {
		key = next;
		prev = &key;
		if (bpf_map_lookup_elem(o->fd_flows, &key, &val))
			continue;
		format_addr(key.family, key.local_addr, local, sizeof(local));
		format_addr(key.family, key.remote_addr, remote, sizeof(remote));
		fprintf(f, "%s\n    {\"family\": %u, \"proto\": %u, \"local\": \"%s\", "
			"\"local_port\": %u, \"remote\": \"%s\", \"remote_port\": %u, "
			"\"first_dir\": \"%s\", \"tx\": ",
			n ? "," : "", key.family, key.proto, local, key.local_port,
			remote, key.remote_port, dir_name(val.first_dir));
		write_flow_dir(f, &val.dir[LUCA_DIR_TX]);
		fputs(", \"rx\": ", f);
		write_flow_dir(f, &val.dir[LUCA_DIR_RX]);
		if (key.proto == 6) {
			fputs(", \"tcp\": {\"syn_ns\": ", f);
			json_ns(f, val.syn_ns);
			fputs(", \"synack_ns\": ", f);
			json_ns(f, val.synack_ns);
			fputs(", \"ack_ns\": ", f);
			json_ns(f, val.ack_ns);
			fprintf(f, ", \"syn_count\": %u, \"syn_dir\": ", val.syn_count);
			json_str(f, val.syn_ns ? dir_name(val.syn_dir) : NULL);
			fputs("}", f);
		}
		fputs("}", f);
		n++;
	}
	fputs(n ? "\n  ]" : "]", f);
	o->flow_entries = n;
}

static void write_drops(FILE *f, struct observatory *o)
{
	struct luca_drop_key key, next;
	char addr[INET6_ADDRSTRLEN], name[96];
	const void *prev = NULL;
	__u64 count;
	size_t n = 0;

	fputs("[", f);
	while (o->fd_drops >= 0 && bpf_map_get_next_key(o->fd_drops, prev, &next) == 0) {
		key = next;
		prev = &key;
		if (bpf_map_lookup_elem(o->fd_drops, &key, &count))
			continue;
		fprintf(f, "%s\n    {\"reason\": %u, \"reason_name\": ", n ? "," : "",
			key.reason);
		json_str(f, drop_reason_name(o, key.reason, name, sizeof(name)) ? name : NULL);
		fprintf(f, ", \"subsystem\": %u, \"direction\": \"%s\", \"family\": %u, "
			"\"proto\": %u, \"remote\": ",
			key.reason >> 16, dir_name(key.dir), key.family, key.proto);
		if (key.family) {
			format_addr(key.family, key.remote_addr, addr, sizeof(addr));
			json_str(f, addr);
		} else {
			fputs("null", f);
		}
		fprintf(f, ", \"remote_port\": %u, \"count\": %llu}", key.remote_port,
			(unsigned long long)count);
		n++;
	}
	fputs(n ? "\n  ]" : "]", f);
	o->drop_entries = n;
}

static void write_protocols(FILE *f, struct observatory *o)
{
	struct luca_counter c;
	size_t n = 0;

	fputs("[", f);
	for (__u32 i = 0; o->fd_protocols >= 0 && i < LUCA_PROTO_SLOTS; i++) {
		if (read_percpu_counter(o, o->fd_protocols, i, &c) || !c.packets)
			continue;
		fprintf(f, "%s\n    {\"direction\": \"%s\", \"proto\": %u, "
			"\"packets\": %llu, \"bytes\": %llu}",
			n ? "," : "", i < 256 ? "tx" : "rx", i % 256,
			(unsigned long long)c.packets, (unsigned long long)c.bytes);
		n++;
	}
	fputs(n ? "\n  ]" : "]", f);
}

static void write_prog_stat(FILE *f, const char *name, struct bpf_program *prog,
			    bool *first)
{
	struct bpf_prog_info info;
	__u32 len = sizeof(info);
	int fd = prog ? bpf_program__fd(prog) : -1;

	if (fd < 0)
		return;
	memset(&info, 0, sizeof(info));
	if (bpf_obj_get_info_by_fd(fd, &info, &len))
		return;
	fprintf(f, "%s{\"name\": \"%s\", \"id\": %u, \"run_cnt\": %llu, \"run_time_ns\": %llu}",
		*first ? "" : ", ", name, info.id, (unsigned long long)info.run_cnt,
		(unsigned long long)info.run_time_ns);
	*first = false;
}

static void write_health(FILE *f, struct observatory *o)
{
	struct rusage ru;
	bool first = true;

	if (getrusage(RUSAGE_SELF, &ru))
		memset(&ru, 0, sizeof(ru));
	/* CPU time of the collector process itself; BPF programs run in the
	 * context of the packet and are measured by prog_stats instead. */
	fprintf(f, "  \"health\": {\"flow_entries\": %zu, \"flow_capacity\": %u, "
		"\"drop_entries\": %zu, \"drop_capacity\": %u, "
		"\"flows_not_recorded\": %llu, \"drops_not_keyed\": %llu, "
		"\"parse_errors\": %llu, \"samples\": %zu, \"timeline_truncated\": %s, "
		"\"max_sample_gap_ns\": %llu, \"snapshot_failures\": %u, "
		"\"map_memlock_bytes\": %llu, \"collector_cpu_seconds\": %.3f, "
		"\"collector_max_rss_kb\": %ld,\n    \"prog_stats\": {\"enabled\": %s, \"note\": ",
		o->flow_entries, o->max_flows, o->drop_entries, o->max_drops,
		(unsigned long long)(o->stats[LUCA_STAT_FLOW_FULL] + o->stats[LUCA_STAT_FLOW_FULL + 1]),
		(unsigned long long)(o->drop_stats[LUCA_DROPSTAT_NOT_KEYED] +
				     o->drop_stats[LUCA_DROPSTAT_NOT_KEYED + 1]),
		(unsigned long long)(o->stats[LUCA_STAT_PARSE_ERR] + o->stats[LUCA_STAT_PARSE_ERR + 1]),
		o->n_samples, o->timeline_truncated ? "true" : "false",
		(unsigned long long)o->max_sample_gap_ns, o->snapshot_failures,
		map_memlock(o->fd_flows) + map_memlock(o->fd_stats) +
			map_memlock(o->fd_protocols) + map_memlock(o->fd_drops) +
			map_memlock(o->fd_drop_stats) + map_memlock(o->fd_config),
		ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 +
			ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6,
		ru.ru_maxrss, o->stats_fd >= 0 ? "true" : "false");
	json_str(f, o->stats_note[0] ? o->stats_note : NULL);
	fputs(", \"programs\": [", f);
	if (o->stats_fd >= 0) {
		write_prog_stat(f, "luca_tc_ingress", o->prog_ingress, &first);
		write_prog_stat(f, "luca_tc_egress", o->prog_egress, &first);
		write_prog_stat(f, "luca_kfree_skb", o->prog_drop, &first);
	}
	fputs("]}}\n", f);
}

static void write_snapshot_body(FILE *f, struct observatory *o)
{
	struct utsname uts;

	read_clocks(&o->rt_base, &o->mono_base_ns);
	if (uname(&uts))
		memset(&uts, 0, sizeof(uts));

	fprintf(f, "{\n  \"schema\": \"%s\",\n", LUCA_SCHEMA);
	fprintf(f, "  \"generator\": {\"name\": \"luca-observatory\", \"version\": \"%s\", "
		"\"commit\": \"%s\", \"libbpf\": \"%d.%d\"},\n", LUCA_VERSION, LUCA_COMMIT,
		LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
	fputs("  \"session\": ", f);
	json_str(f, o->session);
	fputs(",\n  \"host\": {\"kernel\": ", f);
	json_str(f, uts.release);
	fputs(", \"machine\": ", f);
	json_str(f, uts.machine);
	fprintf(f, ", \"btf\": %s, \"btf_path\": ", o->btf_available ? "true" : "false");
	json_str(f, o->btf_path ? o->btf_path :
		 (o->btf_available ? LUCA_VMLINUX_BTF : NULL));
	fputs("},\n  \"interface\": {\"name\": ", f);
	json_str(f, o->iface);
	fprintf(f, ", \"ifindex\": %d, \"mac\": ", o->ifindex);
	write_mac(f, o);
	fputs(", \"addresses\": ", f);
	write_addresses(f, o);
	fputs("},\n  \"status\": ", f);
	json_str(f, o->status);
	fputs(",\n  \"attach\": {\"mode\": ", f);
	json_str(f, o->attach_mode);
	fputs(", \"note\": ", f);
	json_str(f, o->attach_note[0] ? o->attach_note : NULL);
	fputs(", \"drop_tracepoint\": ", f);
	json_str(f, o->drop_status);
	fputs(", \"drop_note\": ", f);
	json_str(f, o->drop_note[0] ? o->drop_note : NULL);
	fputs(", \"error\": ", f);
	json_str(f, o->error[0] ? o->error : NULL);
	fprintf(f, "},\n  \"clock\": {\"realtime\": %.6f, \"monotonic_ns\": %llu},\n",
		o->rt_base, (unsigned long long)o->mono_base_ns);
	fprintf(f, "  \"started_at\": %.6f,\n  \"started_monotonic_ns\": %llu,\n",
		o->started_at, (unsigned long long)o->started_mono_ns);
	fprintf(f, "  \"limits\": {\"max_flows\": %u, \"max_drops\": %u, "
		"\"sample_interval\": %.3f, \"flush_interval\": %.3f, \"max_samples\": %d},\n",
		o->max_flows, o->max_drops, o->interval, o->flush_every, LUCA_MAX_SAMPLES);

	fputs("  \"counters\": {", f);
	for (int dir = 0; dir < 2; dir++) {
		fprintf(f, "%s\"%s\": {", dir ? ", " : "", dir_name(dir));
		for (size_t i = 0; i < COUNTER_NAMES; i++)
			fprintf(f, "%s\"%s\": %llu", i ? ", " : "", counter_names[i].name,
				(unsigned long long)o->stats[counter_names[i].base + dir]);
		fprintf(f, ", \"drops\": %llu, \"drops_not_keyed\": %llu}",
			(unsigned long long)o->drop_stats[LUCA_DROPSTAT_EVENTS + dir],
			(unsigned long long)o->drop_stats[LUCA_DROPSTAT_NOT_KEYED + dir]);
	}
	fputs("},\n", f);

	fputs("  \"timeline\": {\"fields\": [\"realtime\", \"monotonic_ns\"", f);
	for (size_t i = 0; i < TIMELINE_COLS; i++)
		fprintf(f, ", \"%s\"", timeline_cols[i].name);
	fputs("], \"samples\": [", f);
	for (size_t s = 0; s < o->n_samples; s++) {
		fprintf(f, "%s\n    [%.6f, %llu", s ? "," : "", o->samples[s].realtime,
			(unsigned long long)o->samples[s].mono_ns);
		for (size_t i = 0; i < TIMELINE_COLS; i++)
			fprintf(f, ", %llu", (unsigned long long)o->samples[s].v[i]);
		fputs("]", f);
	}
	fputs(o->n_samples ? "\n  ]},\n" : "]},\n", f);

	fputs("  \"protocols\": ", f);
	write_protocols(f, o);
	fputs(",\n  \"flows\": ", f);
	write_flows(f, o);
	fputs(",\n  \"drops\": ", f);
	write_drops(f, o);
	fputs(",\n", f);
	write_health(f, o);
	fputs("}\n", f);
}

static int write_snapshot(struct observatory *o)
{
	char tmp[4096];
	FILE *f;
	int err = 0;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", o->output) >= (int)sizeof(tmp))
		return -ENAMETOOLONG;
	f = fopen(tmp, "w");
	if (!f) {
		err = -errno;
		fprintf(stderr, "luca-observatory: cannot write %s: %s\n", tmp,
			strerror(-err));
		o->snapshot_failures++;
		return err;
	}
	write_snapshot_body(f, o);
	if (fflush(f) || fsync(fileno(f)))
		err = -errno;
	if (fclose(f) && !err)
		err = -errno;
	if (!err && rename(tmp, o->output))
		err = -errno;
	if (err) {
		fprintf(stderr, "luca-observatory: snapshot failed: %s\n", strerror(-err));
		unlink(tmp);
		o->snapshot_failures++;
	}
	return err;
}

/* --------------------------------------------------- load and attach */

static struct bpf_object *open_object(struct observatory *o, const char *name,
				      char *err_buf, size_t err_len)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .btf_custom_path = o->btf_path);
	struct bpf_object *obj;
	char path[4096];

	snprintf(path, sizeof(path), "%s/%s", o->bpf_dir, name);
	obj = bpf_object__open_file(path, &opts);
	if (!obj)
		snprintf(err_buf, err_len, "cannot open %.400s: %s", path, strerror(errno));
	return obj;
}

static int load_object(struct bpf_object *obj, char *err_buf, size_t err_len)
{
	int err = bpf_object__load(obj);

	if (err) {
		err = err < 0 ? err : -errno;
		snprintf(err_buf, err_len,
			 "loading BPF programs failed: %s%s", strerror(-err),
			 err == -EPERM ? " (needs CAP_BPF, CAP_NET_ADMIN and CAP_PERFMON)" :
			 " (run with --verbose for the verifier log)");
	}
	return err;
}

#ifdef LUCA_HAVE_TCX
/* True on kernels >= 6.6, the first with TCX links. */
static bool kernel_has_tcx(void)
{
	struct utsname uts;
	int major = 0, minor = 0;

	if (uname(&uts) || sscanf(uts.release, "%d.%d", &major, &minor) != 2)
		return false;
	return major > 6 || (major == 6 && minor >= 6);
}
#endif

static int load_classifiers(struct observatory *o)
{
	struct bpf_map *map;
	int err;

	o->obj = open_object(o, "luca_observatory.bpf.o", o->error, sizeof(o->error));
	if (!o->obj)
		return -ENOENT;
	o->prog_ingress = bpf_object__find_program_by_name(o->obj, "luca_tc_ingress");
	o->prog_egress = bpf_object__find_program_by_name(o->obj, "luca_tc_egress");
	if (!o->prog_ingress || !o->prog_egress) {
		snprintf(o->error, sizeof(o->error),
			 "luca_observatory.bpf.o does not contain the classifiers");
		return -ENOENT;
	}
	map = bpf_object__find_map_by_name(o->obj, "luca_flows");
	if (map)
		bpf_map__set_max_entries(map, o->max_flows);
#ifdef LUCA_HAVE_TCX
	/* bpf_program__attach_tcx() attaches with the program's expected
	 * attach type, which SEC("tc") leaves at 0 (the kernel then answers
	 * EINVAL). It must be set before loading; cls_bpf ignores it, so the
	 * clsact fallback is unaffected. Older kernels load as before. */
	if (o->pref != ATTACH_TC && kernel_has_tcx()) {
		bpf_program__set_expected_attach_type(o->prog_ingress, BPF_TCX_INGRESS);
		bpf_program__set_expected_attach_type(o->prog_egress, BPF_TCX_EGRESS);
	}
#endif

	err = load_object(o->obj, o->error, sizeof(o->error));
	if (err)
		return err;
	o->fd_flows = bpf_object__find_map_fd_by_name(o->obj, "luca_flows");
	o->fd_stats = bpf_object__find_map_fd_by_name(o->obj, "luca_stats");
	o->fd_protocols = bpf_object__find_map_fd_by_name(o->obj, "luca_protocols");
	return 0;
}

/* Loads the optional drop-reason object. Failures only change drop_status. */
static void load_drops(struct observatory *o)
{
	struct luca_config cfg = { .ifindex = (__u32)o->ifindex };
	struct bpf_map *map;
	struct stat netns;
	__u32 zero = 0;

	if (!o->drops_wanted) {
		o->drop_status = "disabled";
		return;
	}
	if (!o->btf_available) {
		o->drop_status = "unavailable";
		snprintf(o->drop_note, sizeof(o->drop_note),
			 "kernel BTF not found at %s%s",
			 o->btf_path ? o->btf_path : LUCA_VMLINUX_BTF,
			 o->btf_path ? "" : "; pass --btf to enable drop reasons");
		return;
	}
	if (stat("/proc/self/ns/net", &netns) == 0)
		cfg.netns_ino = (__u32)netns.st_ino;

	o->drop_obj = open_object(o, "luca_drops.bpf.o", o->drop_note, sizeof(o->drop_note));
	if (!o->drop_obj)
		goto fail;
	map = bpf_object__find_map_by_name(o->drop_obj, "luca_drops");
	if (map)
		bpf_map__set_max_entries(map, o->max_drops);
	if (load_object(o->drop_obj, o->drop_note, sizeof(o->drop_note)))
		goto fail;
	o->prog_drop = bpf_object__find_program_by_name(o->drop_obj, "luca_kfree_skb");
	o->fd_drops = bpf_object__find_map_fd_by_name(o->drop_obj, "luca_drops");
	o->fd_drop_stats = bpf_object__find_map_fd_by_name(o->drop_obj, "luca_drop_stats");
	o->fd_config = bpf_object__find_map_fd_by_name(o->drop_obj, "luca_config");
	if (!o->prog_drop || o->fd_config < 0 ||
	    bpf_map_update_elem(o->fd_config, &zero, &cfg, BPF_ANY)) {
		snprintf(o->drop_note, sizeof(o->drop_note),
			 "cannot configure the drop-reason program: %s", strerror(errno));
		goto fail;
	}
	o->link_drop = bpf_program__attach(o->prog_drop);
	if (!o->link_drop) {
		snprintf(o->drop_note, sizeof(o->drop_note),
			 "attaching raw tracepoint kfree_skb failed: %s", strerror(errno));
		goto fail;
	}
	o->drop_status = "attached";
	return;
fail:
	fprintf(stderr, "luca-observatory: drop reasons unavailable: %s\n", o->drop_note);
	o->drop_status = "failed";
	bpf_object__close(o->drop_obj);
	o->drop_obj = NULL;
	o->prog_drop = NULL;
	o->fd_drops = o->fd_drop_stats = o->fd_config = -1;
}

static int detach_legacy_filters(int ifindex)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, d, .handle = LUCA_TC_HANDLE,
			    .priority = LUCA_TC_PRIORITY);
	int err_in, err_eg;

	hook.attach_point = BPF_TC_INGRESS;
	err_in = bpf_tc_detach(&hook, &d);
	hook.attach_point = BPF_TC_EGRESS;
	err_eg = bpf_tc_detach(&hook, &d);
	return !err_in || !err_eg ? 0 : err_in;
}

static int attach_legacy_tc(struct observatory *o)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = o->ifindex,
			    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, in_opts, .handle = LUCA_TC_HANDLE,
			    .priority = LUCA_TC_PRIORITY, .flags = BPF_TC_F_REPLACE,
			    .prog_fd = bpf_program__fd(o->prog_ingress));
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, eg_opts, .handle = LUCA_TC_HANDLE,
			    .priority = LUCA_TC_PRIORITY, .flags = BPF_TC_F_REPLACE,
			    .prog_fd = bpf_program__fd(o->prog_egress));
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, del_opts, .handle = LUCA_TC_HANDLE,
			    .priority = LUCA_TC_PRIORITY);
	int err;

	err = bpf_tc_hook_create(&hook);
	if (!err)
		o->tc_hook_created = true;
	else if (err != -EEXIST)
		goto fail;

	hook.attach_point = BPF_TC_INGRESS;
	err = bpf_tc_attach(&hook, &in_opts);
	if (err)
		goto fail;
	hook.attach_point = BPF_TC_EGRESS;
	err = bpf_tc_attach(&hook, &eg_opts);
	if (err) {
		hook.attach_point = BPF_TC_INGRESS;
		bpf_tc_detach(&hook, &del_opts);
		goto fail;
	}
	o->tc_attached = true;
	o->attach_mode = "tc";
	return 0;
fail:
	set_error(o, "attaching tc filters to %s failed: %s%s", o->iface, strerror(-err),
		  err == -EPERM ? " (needs CAP_NET_ADMIN)" : "");
	if (o->tc_hook_created) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&hook);
		o->tc_hook_created = false;
	}
	return err;
}

static int attach_classifiers(struct observatory *o)
{
#ifdef LUCA_HAVE_TCX
	int err;

	if (o->pref != ATTACH_TC) {
		o->link_ingress = bpf_program__attach_tcx(o->prog_ingress, o->ifindex, NULL);
		err = o->link_ingress ? 0 : -errno;
		if (!err) {
			o->link_egress = bpf_program__attach_tcx(o->prog_egress, o->ifindex, NULL);
			err = o->link_egress ? 0 : -errno;
			if (err) {
				bpf_link__destroy(o->link_ingress);
				o->link_ingress = NULL;
			}
		}
		if (!err) {
			o->attach_mode = "tcx";
			return 0;
		}
		if (o->pref == ATTACH_TCX) {
			set_error(o, "tcx attach to %s failed: %s", o->iface, strerror(-err));
			return err;
		}
		snprintf(o->attach_note, sizeof(o->attach_note),
			 "tcx unavailable (%s); used a clsact qdisc", strerror(-err));
	}
#else
	if (o->pref == ATTACH_TCX) {
		set_error(o, "built against libbpf %d.%d, which has no tcx support",
			  LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
		return -EOPNOTSUPP;
	}
	if (o->pref == ATTACH_AUTO)
		snprintf(o->attach_note, sizeof(o->attach_note),
			 "built against libbpf %d.%d without tcx; used a clsact qdisc",
			 LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
#endif
	return attach_legacy_tc(o);
}

static void enable_prog_stats(struct observatory *o)
{
	o->stats_fd = -1;
	if (!o->prog_stats_wanted)
		return;
	o->stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
	if (o->stats_fd < 0) {
		snprintf(o->stats_note, sizeof(o->stats_note),
			 "BPF_ENABLE_STATS failed: %s (needs CAP_SYS_ADMIN, kernel >= 5.8)",
			 strerror(errno));
		o->stats_fd = -1;
	} else {
		snprintf(o->stats_note, sizeof(o->stats_note),
			 "run-time accounting enabled for this collector's lifetime");
	}
}

static void detach(struct observatory *o)
{
	bpf_link__destroy(o->link_drop);
	bpf_link__destroy(o->link_egress);
	bpf_link__destroy(o->link_ingress);
	o->link_drop = o->link_egress = o->link_ingress = NULL;

	if (o->tc_attached) {
		detach_legacy_filters(o->ifindex);
		/* Only remove the clsact qdisc when this process created it. */
		if (o->tc_hook_created) {
			DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = o->ifindex,
					    .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);

			bpf_tc_hook_destroy(&hook);
		}
		o->tc_attached = false;
	}
}

static void cleanup(struct observatory *o)
{
	detach(o);
	if (o->stats_fd >= 0)
		close(o->stats_fd);
	o->stats_fd = -1;
	bpf_object__close(o->drop_obj);
	bpf_object__close(o->obj);
	o->drop_obj = o->obj = NULL;
	btf__free(o->vmlinux_btf);
	o->vmlinux_btf = NULL;
	free(o->samples);
	o->samples = NULL;
	free(o->percpu_buf);
	o->percpu_buf = NULL;
}

/* ------------------------------------------------------------- main */

static void usage(FILE *f)
{
	fputs("Usage: luca-observatory --iface IFACE --output FILE [options]\n"
	      "       luca-observatory --iface IFACE --detach-only\n"
	      "\n"
	      "  -i, --iface IFACE      access-point interface to observe\n"
	      "  -o, --output FILE      JSON snapshot path (written atomically)\n"
	      "  -s, --session ID       session identifier recorded in the snapshot\n"
	      "      --bpf-dir DIR      directory holding the .bpf.o files\n"
	      "                         (default: the directory of this binary)\n"
	      "      --btf PATH         kernel BTF file when " LUCA_VMLINUX_BTF " is absent\n"
	      "  -a, --attach MODE      auto (default), tcx or tc\n"
	      "  -n, --interval SEC     counter sampling interval (default 1)\n"
	      "  -f, --flush SEC        snapshot interval (default 10)\n"
	      "  -d, --duration SEC     stop after SEC seconds (default: until SIGTERM)\n"
	      "      --max-flows N      flow table size (default 65536)\n"
	      "      --max-drops N      drop-reason table size (default 4096)\n"
	      "      --no-drops         do not load the kfree_skb drop program\n"
	      "      --prog-stats       record BPF run time (needs CAP_SYS_ADMIN)\n"
	      "      --ready-file PATH  create PATH once the classifiers are attached\n"
	      "      --detach-only      remove tc filters left by a crashed run, then exit\n"
	      "  -v, --verbose          print libbpf debug output and the verifier log\n"
	      "  -h, --help\n"
	      "\n"
	      "Exit status: 0 stopped, 1 usage, 2 load/attach failure,\n"
	      "             3 final snapshot failed, 4 interface disappeared.\n", f);
}

static char *binary_dir(void)
{
	char self[4096];
	ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	char *slash;

	if (n <= 0)
		return strdup(".");
	self[n] = '\0';
	slash = strrchr(self, '/');
	if (!slash)
		return strdup(".");
	*slash = '\0';
	return strdup(self[0] ? self : "/");
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
		{ "iface", required_argument, NULL, 'i' },
		{ "output", required_argument, NULL, 'o' },
		{ "session", required_argument, NULL, 's' },
		{ "bpf-dir", required_argument, NULL, 'b' },
		{ "btf", required_argument, NULL, 'B' },
		{ "attach", required_argument, NULL, 'a' },
		{ "interval", required_argument, NULL, 'n' },
		{ "flush", required_argument, NULL, 'f' },
		{ "duration", required_argument, NULL, 'd' },
		{ "max-flows", required_argument, NULL, 'M' },
		{ "max-drops", required_argument, NULL, 'm' },
		{ "no-drops", no_argument, NULL, 'D' },
		{ "prog-stats", no_argument, NULL, 'P' },
		{ "ready-file", required_argument, NULL, 'R' },
		{ "detach-only", no_argument, NULL, 'X' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};
	struct observatory o = {
		.interval = 1.0, .flush_every = 10.0, .max_flows = LUCA_DEFAULT_MAX_FLOWS,
		.max_drops = LUCA_DEFAULT_MAX_DROPS, .pref = ATTACH_AUTO, .drops_wanted = true,
		.fd_flows = -1, .fd_stats = -1, .fd_protocols = -1, .fd_drops = -1,
		.fd_drop_stats = -1, .fd_config = -1, .stats_fd = -1, .status = "starting",
		.attach_mode = "none", .drop_status = "disabled",
	};
	struct sigaction sa = { .sa_handler = on_signal };
	struct rlimit unlimited = { RLIM_INFINITY, RLIM_INFINITY };
	struct timespec next, start;
	bool detach_only = false;
	int exit_code = 0;
	long long step_ns;
	double since_flush = 0;
	int c, err;

	while ((c = getopt_long(argc, argv, "i:o:s:a:n:f:d:vh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'i': o.iface = optarg; break;
		case 'o': o.output = optarg; break;
		case 's': o.session = optarg; break;
		case 'b': o.bpf_dir = optarg; break;
		case 'B': o.btf_path = optarg; break;
		case 'a':
			if (!strcmp(optarg, "auto"))
				o.pref = ATTACH_AUTO;
			else if (!strcmp(optarg, "tcx"))
				o.pref = ATTACH_TCX;
			else if (!strcmp(optarg, "tc"))
				o.pref = ATTACH_TC;
			else {
				usage(stderr);
				return 1;
			}
			break;
		case 'n': o.interval = atof(optarg); break;
		case 'f': o.flush_every = atof(optarg); break;
		case 'd': o.duration = atof(optarg); break;
		case 'M': o.max_flows = (__u32)strtoul(optarg, NULL, 10); break;
		case 'm': o.max_drops = (__u32)strtoul(optarg, NULL, 10); break;
		case 'D': o.drops_wanted = false; break;
		case 'P': o.prog_stats_wanted = true; break;
		case 'R': o.ready_file = optarg; break;
		case 'X': detach_only = true; break;
		case 'v': o.verbose = true; break;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 1;
		}
	}

	verbose_libbpf = o.verbose;
	libbpf_set_print(print_libbpf);
#if LIBBPF_MAJOR_VERSION < 1
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
#endif

	if (detach_only) {
		if (!o.iface) {
			usage(stderr);
			return 1;
		}
		o.ifindex = (int)if_nametoindex(o.iface);
		if (!o.ifindex) {
			fprintf(stderr, "luca-observatory: interface %s not found\n", o.iface);
			return 2;
		}
		err = detach_legacy_filters(o.ifindex);
		printf("%s\n", err ? "no luca tc filters attached" : "removed luca tc filters");
		return 0;
	}

	if (!o.iface || !o.output || o.interval < 0.01 || o.flush_every <= 0 ||
	    o.max_flows == 0 || o.max_drops == 0) {
		usage(stderr);
		return 1;
	}
	if (!o.bpf_dir)
		o.bpf_dir = binary_dir();
	if (!o.bpf_dir)
		return 1;

	/* Kernels before 5.11 charge BPF memory to RLIMIT_MEMLOCK. */
	setrlimit(RLIMIT_MEMLOCK, &unlimited);

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	read_clocks(&o.started_at, &o.started_mono_ns);
	o.ncpus = libbpf_num_possible_cpus();
	o.percpu_buf = calloc(o.ncpus > 0 ? o.ncpus : 1, sizeof(struct luca_counter));
	o.ifindex = (int)if_nametoindex(o.iface);
	o.btf_available = access(o.btf_path ? o.btf_path : LUCA_VMLINUX_BTF, R_OK) == 0;

	if (o.ncpus <= 0 || !o.percpu_buf) {
		set_error(&o, "cannot determine the number of possible CPUs");
		goto fail;
	}
	if (!o.ifindex) {
		set_error(&o, "interface %s not found", o.iface);
		goto fail;
	}
	if (o.btf_available) /* names drop reasons; NULL leaves them unnamed */
		o.vmlinux_btf = o.btf_path ? btf__parse(o.btf_path, NULL) : btf__load_vmlinux_btf();

	err = load_classifiers(&o);
	if (err) {
		fprintf(stderr, "luca-observatory: %s\n", o.error);
		goto fail;
	}
	enable_prog_stats(&o);
	err = attach_classifiers(&o);
	if (err)
		goto fail;
	load_drops(&o);

	o.status = "running";
	take_sample(&o);
	write_snapshot(&o);
	if (o.ready_file) {
		FILE *rf = fopen(o.ready_file, "w");

		if (rf) {
			fprintf(rf, "%s\n", o.attach_mode);
			fclose(rf);
		}
	}
	fprintf(stderr, "luca-observatory: observing %s (attach=%s, drops=%s)\n",
		o.iface, o.attach_mode, o.drop_status);

	step_ns = (long long)(o.interval * 1e9);
	clock_gettime(CLOCK_MONOTONIC, &start);
	next = start;
	while (!stop_requested) {
		struct timespec now;

		next.tv_sec += step_ns / 1000000000LL;
		next.tv_nsec += step_ns % 1000000000LL;
		if (next.tv_nsec >= 1000000000L) {
			next.tv_sec++;
			next.tv_nsec -= 1000000000L;
		}
		while (!stop_requested &&
		       clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL) == EINTR)
			;
		take_sample(&o);
		/* A removed or renamed interface takes its hooks with it. */
		if ((int)if_nametoindex(o.iface) != o.ifindex) {
			set_error(&o, "interface %s (ifindex %d) disappeared", o.iface, o.ifindex);
			o.status = "interface_lost";
			exit_code = 4;
			break;
		}
		since_flush += o.interval;
		if (since_flush >= o.flush_every) {
			write_snapshot(&o);
			since_flush = 0;
		}
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (o.duration > 0 && ts_seconds(&now) - ts_seconds(&start) >= o.duration)
			break;
	}

	if (!exit_code) {
		take_sample(&o);
		o.status = "stopped";
	}
	err = write_snapshot(&o);
	cleanup(&o);
	return exit_code ? exit_code : (err ? 3 : 0);

fail:
	o.status = "failed";
	detach(&o);
	write_snapshot(&o);
	cleanup(&o);
	return 2;
}
