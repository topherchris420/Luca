// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Luca Kernel-Native Network Observatory - traffic classifiers.
 *
 * Two classifiers are attached to the access-point interface (TCX links on
 * kernels >= 6.6, a clsact qdisc otherwise). They never alter traffic: both
 * return TC_ACT_UNSPEC (== TCX_NEXT), so the next program or the default
 * action decides. They maintain:
 *   - luca_flows:     per-flow counters, TTL range, TCP handshake timing;
 *   - luca_stats:     per-CPU interface totals, incl. what a "tcp or udp"
 *                     capture filter would have matched;
 *   - luca_protocols: per-CPU packets/bytes per IP protocol and direction.
 *
 * This object deliberately uses no CO-RE relocation: it only reads the
 * stable __sk_buff UAPI context, so it loads on kernels without BTF.
 * Kernel drop reasons live in luca_drops.bpf.c, which does need BTF.
 *
 * Header parsing uses bpf_skb_load_bytes() so that non-linear buffers are
 * handled without pulling or otherwise modifying the packet.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "luca_observatory.h"
#include "luca_bpf_common.h"

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

#define LUCA_IPV6_MAX_EXT 4

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LUCA_DEFAULT_MAX_FLOWS);
	__type(key, struct luca_flow_key);
	__type(value, struct luca_flow_value);
} luca_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LUCA_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} luca_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LUCA_PROTO_SLOTS);
	__type(key, __u32);
	__type(value, struct luca_counter);
} luca_protocols SEC(".maps");

struct luca_parsed {
	__u8 family;
	__u8 proto;          /* L4 protocol after extension headers */
	__u8 fixed_proto;    /* protocol field of the fixed IP header */
	__u8 ttl;
	__u8 tcp_flags;
	__u8 fragment;       /* packet is an IP fragment */
	__u8 later_fragment; /* fragment without the L4 header */
	__u8 tagged;         /* carried an in-band 802.1Q/802.1ad tag */
	__u16 sport;
	__u16 dport;
	__u32 tcp_seq;
	__u32 tcp_payload;   /* bytes after the TCP header in this buffer */
	__u8 tcp_parsed;
	__u8 pad[3];
	__u8 saddr[16];
	__u8 daddr[16];
};

/* Fixed IPv6 fragment header (RFC 8200, section 4.5). */
struct luca_frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

static __always_inline void stat_add(__u32 idx, __u64 value)
{
	__u64 *slot = bpf_map_lookup_elem(&luca_stats, &idx);

	if (slot)
		*slot += value; /* per-CPU slot: no atomic needed */
}

static __always_inline void proto_add(__u32 dir, __u8 proto, __u64 packets,
				      __u64 bytes)
{
	__u32 idx = dir * 256 + proto;
	struct luca_counter *c = bpf_map_lookup_elem(&luca_protocols, &idx);

	if (c) {
		c->packets += packets;
		c->bytes += bytes;
	}
}

/* Returns 0 when an IPv4/IPv6 header was parsed, 1 for other L2 payloads
 * and -1 on a malformed or truncated header. */
static __always_inline int parse_packet(struct __sk_buff *skb, __u32 dir,
					struct luca_parsed *p)
{
	struct ethhdr eth;
	__u32 off = sizeof(struct ethhdr);
	__u32 l3_end = skb->len; /* end of the IP datagram, link padding excluded */
	__u16 h_proto;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
		return -1;
	h_proto = bpf_ntohs(eth.h_proto);

	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		__be16 inner[2];

		if (bpf_skb_load_bytes(skb, off, inner, sizeof(inner)))
			return -1;
		h_proto = bpf_ntohs(inner[1]);
		off += sizeof(inner);
		p->tagged = 1;
	}

	if (h_proto == ETH_P_IP) {
		struct iphdr ip;
		__u16 frag;

		if (bpf_skb_load_bytes(skb, off, &ip, sizeof(ip)))
			return -1;
		if (ip.version != 4 || ip.ihl < 5)
			return -1;
		stat_add(LUCA_STAT_IPV4 + dir, 1);

		p->family = 4;
		p->proto = ip.protocol;
		p->fixed_proto = ip.protocol;
		p->ttl = ip.ttl;
		__builtin_memcpy(p->saddr, &ip.saddr, 4);
		__builtin_memcpy(p->daddr, &ip.daddr, 4);

		frag = bpf_ntohs(ip.frag_off);
		if (frag & (LUCA_IP_MF | LUCA_IP_OFFSET))
			p->fragment = 1;
		if (frag & LUCA_IP_OFFSET)
			p->later_fragment = 1;
		/* tot_len is 0 for BIG TCP super-packets; keep skb->len then. */
		if (ip.tot_len)
			l3_end = off + bpf_ntohs(ip.tot_len);
		off += ip.ihl * 4;
	} else if (h_proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;
		__u8 nh;

		if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)))
			return -1;
		if (ip6.version != 6)
			return -1;
		stat_add(LUCA_STAT_IPV6 + dir, 1);

		p->family = 6;
		p->fixed_proto = ip6.nexthdr;
		p->ttl = ip6.hop_limit;
		__builtin_memcpy(p->saddr, &ip6.saddr, 16);
		__builtin_memcpy(p->daddr, &ip6.daddr, 16);
		if (ip6.payload_len)
			l3_end = off + sizeof(ip6) + bpf_ntohs(ip6.payload_len);
		off += sizeof(ip6);
		nh = ip6.nexthdr;

#pragma unroll
		for (int i = 0; i < LUCA_IPV6_MAX_EXT; i++) {
			if (nh == LUCA_IPPROTO_HOPOPTS || nh == LUCA_IPPROTO_ROUTING ||
			    nh == LUCA_IPPROTO_DSTOPTS) {
				__u8 ext[2];

				if (bpf_skb_load_bytes(skb, off, ext, sizeof(ext)))
					return -1;
				nh = ext[0];
				off += (ext[1] + 1) * 8;
			} else if (nh == LUCA_IPPROTO_FRAGMENT) {
				struct luca_frag_hdr fh;

				if (bpf_skb_load_bytes(skb, off, &fh, sizeof(fh)))
					return -1;
				p->fragment = 1;
				if (bpf_ntohs(fh.frag_off) & 0xfff8)
					p->later_fragment = 1;
				nh = fh.nexthdr;
				off += sizeof(fh);
			} else {
				break;
			}
		}
		p->proto = nh;
	} else {
		if (h_proto == ETH_P_ARP)
			stat_add(LUCA_STAT_ARP + dir, 1);
		else if (h_proto == ETH_P_PAE)
			stat_add(LUCA_STAT_EAPOL + dir, 1);
		else
			stat_add(LUCA_STAT_OTHER_L2 + dir, 1);
		return 1;
	}

	if (p->later_fragment)
		return 0;

	if (p->proto == LUCA_IPPROTO_TCP) {
		__u8 tcp[14];
		__u32 hdr_end;

		if (bpf_skb_load_bytes(skb, off, tcp, sizeof(tcp)))
			return 0; /* keep the IP-level observation */
		p->sport = (tcp[0] << 8) | tcp[1];
		p->dport = (tcp[2] << 8) | tcp[3];
		p->tcp_seq = ((__u32)tcp[4] << 24) | ((__u32)tcp[5] << 16) |
			     ((__u32)tcp[6] << 8) | tcp[7];
		p->tcp_flags = tcp[13];
		/* Offsets count from the link-layer header at both TC hooks; for
		 * GSO/GRO buffers the IP length spans all segments. */
		if (l3_end > skb->len)
			l3_end = skb->len;
		hdr_end = off + (tcp[12] >> 4) * 4;
		p->tcp_payload = l3_end > hdr_end ? l3_end - hdr_end : 0;
		p->tcp_parsed = 1;
	} else if (p->proto == LUCA_IPPROTO_UDP || p->proto == LUCA_IPPROTO_UDPLITE ||
		   p->proto == LUCA_IPPROTO_SCTP) {
		__u8 ports[4];

		if (bpf_skb_load_bytes(skb, off, ports, sizeof(ports)))
			return 0;
		p->sport = (ports[0] << 8) | ports[1];
		p->dport = (ports[2] << 8) | ports[3];
	}
	return 0;
}

static __always_inline void track_flow(const struct luca_parsed *p, __u32 dir,
				       __u64 segs, __u64 len, __u64 now)
{
	struct luca_flow_key key = {};
	struct luca_flow_value *v;
	struct luca_flow_dir *d;

	key.family = p->family;
	key.proto = p->proto;
	if (dir == LUCA_DIR_TX) {
		__builtin_memcpy(key.local_addr, p->saddr, 16);
		__builtin_memcpy(key.remote_addr, p->daddr, 16);
		key.local_port = p->sport;
		key.remote_port = p->dport;
	} else {
		__builtin_memcpy(key.local_addr, p->daddr, 16);
		__builtin_memcpy(key.remote_addr, p->saddr, 16);
		key.local_port = p->dport;
		key.remote_port = p->sport;
	}

	v = bpf_map_lookup_elem(&luca_flows, &key);
	if (!v) {
		struct luca_flow_value init = {};
		long err;

		init.first_dir = dir;
		init.dir[LUCA_DIR_TX].ttl_min = 255;
		init.dir[LUCA_DIR_RX].ttl_min = 255;
		err = bpf_map_update_elem(&luca_flows, &key, &init, BPF_NOEXIST);
		if (err && err != -LUCA_EEXIST) {
			stat_add(LUCA_STAT_FLOW_FULL + dir, 1);
			return;
		}
		v = bpf_map_lookup_elem(&luca_flows, &key);
		if (!v)
			return;
	}

	/*
	 * Each direction's fields are written only by the hook for that
	 * direction, so ordinary stores are single-writer in practice. The
	 * counters use atomic adds because a hook may run on several CPUs.
	 */
	d = &v->dir[dir];
	__sync_fetch_and_add(&d->packets, segs);
	__sync_fetch_and_add(&d->bytes, len);
	if (!d->first_ns)
		d->first_ns = now;
	d->last_ns = now;
	d->tcp_flags |= p->tcp_flags;
	if (p->ttl < d->ttl_min)
		d->ttl_min = p->ttl;
	if (p->ttl > d->ttl_max)
		d->ttl_max = p->ttl;
	if (p->fragment)
		d->fragments = 1;

	if (!p->tcp_parsed)
		return;

	/*
	 * Passive retransmission estimate: a data segment that starts below
	 * the highest sequence end already seen in this direction was either
	 * retransmitted or reordered. Serial-number arithmetic handles wrap.
	 */
	if (p->tcp_payload) {
		__u32 end = p->tcp_seq + p->tcp_payload;

		if (d->seq_valid && (__s32)(p->tcp_seq - d->seq_max) < 0)
			__sync_fetch_and_add(&d->retrans, 1);
		if (!d->seq_valid || (__s32)(end - d->seq_max) > 0) {
			d->seq_max = end;
			d->seq_valid = 1;
		}
	}

	if ((p->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN) {
		if (!v->synack_ns) {
			v->syn_ns = now;
			v->syn_dir = dir;
			if (v->syn_count < 255)
				v->syn_count++;
		}
	} else if ((p->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
		   (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
		if (v->syn_ns && !v->synack_ns && dir != v->syn_dir)
			v->synack_ns = now;
	} else if ((p->tcp_flags & TCP_FLAG_ACK) && v->synack_ns &&
		   !v->ack_ns && dir == v->syn_dir) {
		v->ack_ns = now;
	}
}

static __always_inline int observe(struct __sk_buff *skb, const __u32 dir)
{
	struct luca_parsed p = {};
	__u64 now = bpf_ktime_get_ns();
	__u64 segs = skb->gso_segs ? skb->gso_segs : 1;
	__u64 len = skb->len;
	int ret;

	stat_add(LUCA_STAT_SKBS + dir, 1);
	stat_add(LUCA_STAT_SEGS + dir, segs);
	stat_add(LUCA_STAT_BYTES + dir, len);

	ret = parse_packet(skb, dir, &p);
	if (ret < 0) {
		stat_add(LUCA_STAT_PARSE_ERR + dir, 1);
		return TC_ACT_UNSPEC;
	}
	if (ret > 0)
		return TC_ACT_UNSPEC;

	/* libpcap's "tcp or udp" checks the fixed header's protocol field of
	 * untagged frames, fragments included. */
	if (!p.tagged && (p.fixed_proto == LUCA_IPPROTO_TCP ||
			  p.fixed_proto == LUCA_IPPROTO_UDP)) {
		stat_add(LUCA_STAT_PCAP_SKBS + dir, 1);
		stat_add(LUCA_STAT_PCAP_SEGS + dir, segs);
	}

	proto_add(dir, p.proto, segs, len);
	track_flow(&p, dir, segs, len, now);
	return TC_ACT_UNSPEC;
}

SEC("tc")
int luca_tc_ingress(struct __sk_buff *skb)
{
	return observe(skb, LUCA_DIR_TX);
}

SEC("tc")
int luca_tc_egress(struct __sk_buff *skb)
{
	return observe(skb, LUCA_DIR_RX);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
