// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Luca Kernel-Native Network Observatory - kernel drop reasons.
 *
 * Counts skb:kfree_skb events for packets that arrived on the access-point
 * interface (skb->skb_iif) or were leaving through it (skb->dev), keyed by
 * drop reason and the remote end of the packet.
 *
 * The program is a raw tracepoint: it attaches by name through the bpf()
 * syscall, so the collector needs neither tracefs access nor root, only
 * CAP_BPF and CAP_PERFMON. Its arguments are the TP_PROTO parameters:
 *   (struct sk_buff *skb, void *location[, enum skb_drop_reason reason
 *    [, struct sock *rx_sk]])
 * The reason argument exists since 5.17, together with the enum; its
 * presence is detected with a CO-RE type check so that older kernels never
 * read past the arguments they provide (the kernel rejects the attach if
 * the program could).
 *
 * struct sk_buff is internal and changes between kernels, so its fields
 * are read through CO-RE relocations, resolved against kernel BTF at load
 * time. This object is optional: without BTF the collector skips it and
 * the classifiers still run.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "luca_observatory.h"
#include "luca_bpf_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LUCA_DEFAULT_MAX_DROPS);
	__type(key, struct luca_drop_key);
	__type(value, __u64);
} luca_drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LUCA_DROPSTAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} luca_drop_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct luca_config);
} luca_config SEC(".maps");

/* Minimal CO-RE views of kernel types; only these fields are relocated. */
struct ns_common___luca {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net___luca {
	struct ns_common___luca ns;
} __attribute__((preserve_access_index));

typedef struct {
	struct net___luca *net;
} __attribute__((preserve_access_index)) possible_net_t___luca;

struct net_device___luca {
	int ifindex;
	possible_net_t___luca nd_net; /* empty without CONFIG_NET_NS */
} __attribute__((preserve_access_index));

struct sock_common___luca {
	possible_net_t___luca skc_net;
} __attribute__((preserve_access_index));

struct sock___luca {
	struct sock_common___luca __sk_common;
} __attribute__((preserve_access_index));

struct sk_buff___luca {
	struct net_device___luca *dev;
	struct sock___luca *sk;
	int skb_iif;
	unsigned char *head;
	__u16 network_header;
	__u16 protocol; /* __be16 */
} __attribute__((preserve_access_index));

enum skb_drop_reason___luca {
	SKB_DROP_REASON_NOT_SPECIFIED___luca = 2,
};

static __always_inline void drop_stat_add(__u32 idx)
{
	__u64 *slot = bpf_map_lookup_elem(&luca_drop_stats, &idx);

	if (slot)
		*slot += 1;
}

static __always_inline void drop_parse(struct luca_drop_key *key,
				       const unsigned char *head, __u16 nh,
				       __u16 l3proto)
{
	__u16 ports[2];

	if (!head || nh == 0xffff) /* network header not set yet */
		return;

	if (l3proto == ETH_P_IP) {
		struct iphdr ip;

		if (bpf_probe_read_kernel(&ip, sizeof(ip), head + nh) ||
		    ip.version != 4)
			return;
		key->family = 4;
		key->proto = ip.protocol;
		if (key->dir == LUCA_DIR_TX)
			__builtin_memcpy(key->remote_addr, &ip.daddr, 4);
		else
			__builtin_memcpy(key->remote_addr, &ip.saddr, 4);
		if (bpf_ntohs(ip.frag_off) & LUCA_IP_OFFSET)
			return;
		if (ip.protocol != LUCA_IPPROTO_TCP && ip.protocol != LUCA_IPPROTO_UDP)
			return;
		if (bpf_probe_read_kernel(ports, sizeof(ports), head + nh + ip.ihl * 4))
			return;
	} else if (l3proto == ETH_P_IPV6) {
		struct ipv6hdr ip6;

		if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + nh) ||
		    ip6.version != 6)
			return;
		key->family = 6;
		key->proto = ip6.nexthdr;
		if (key->dir == LUCA_DIR_TX)
			__builtin_memcpy(key->remote_addr, &ip6.daddr, 16);
		else
			__builtin_memcpy(key->remote_addr, &ip6.saddr, 16);
		if (ip6.nexthdr != LUCA_IPPROTO_TCP && ip6.nexthdr != LUCA_IPPROTO_UDP)
			return;
		if (bpf_probe_read_kernel(ports, sizeof(ports), head + nh + sizeof(ip6)))
			return;
	} else {
		return;
	}
	key->remote_port = bpf_ntohs(key->dir == LUCA_DIR_TX ? ports[1] : ports[0]);
}

SEC("raw_tracepoint/kfree_skb")
int luca_kfree_skb(struct bpf_raw_tracepoint_args *ctx)
{
	struct sk_buff___luca *skb = (struct sk_buff___luca *)ctx->args[0];
	struct luca_drop_key key = {};
	struct net_device___luca *dev;
	struct luca_config *cfg;
	__u32 zero = 0;
	__u64 one = 1;
	__u64 *count;
	int iif, oif;
	long err;

	cfg = bpf_map_lookup_elem(&luca_config, &zero);
	if (!cfg || !cfg->ifindex || !skb)
		return 0;

	dev = BPF_CORE_READ(skb, dev);
	iif = BPF_CORE_READ(skb, skb_iif);
	oif = dev ? BPF_CORE_READ(dev, ifindex) : 0;
	if (iif == cfg->ifindex)
		key.dir = LUCA_DIR_TX;
	else if (oif == cfg->ifindex)
		key.dir = LUCA_DIR_RX;
	else
		return 0;

	/* An ifindex is only unique within a network namespace, so the
	 * packet must be in ours: skb->dev's namespace (a forwarded packet
	 * stays in the namespace it arrived in) or, once a socket has queued
	 * the packet and cleared skb->dev, the socket's. A packet with
	 * neither cannot be placed and is not attributed. */
	if (cfg->netns_ino && bpf_core_field_exists(dev->nd_net.net)) {
		struct sock___luca *sk = BPF_CORE_READ(skb, sk);
		unsigned int inum = 0;

		if (dev)
			inum = BPF_CORE_READ(dev, nd_net.net, ns.inum);
		else if (sk)
			inum = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		if (inum != cfg->netns_ino)
			return 0;
	}

	if (bpf_core_type_exists(enum skb_drop_reason___luca))
		key.reason = (__u32)ctx->args[2];

	drop_parse(&key, BPF_CORE_READ(skb, head),
		   BPF_CORE_READ(skb, network_header),
		   bpf_ntohs(BPF_CORE_READ(skb, protocol)));

	drop_stat_add(LUCA_DROPSTAT_EVENTS + key.dir);

	count = bpf_map_lookup_elem(&luca_drops, &key);
	if (count) {
		__sync_fetch_and_add(count, 1);
		return 0;
	}
	err = bpf_map_update_elem(&luca_drops, &key, &one, BPF_NOEXIST);
	if (err == -LUCA_EEXIST) {
		count = bpf_map_lookup_elem(&luca_drops, &key);
		if (count)
			__sync_fetch_and_add(count, 1);
	} else if (err) {
		drop_stat_add(LUCA_DROPSTAT_NOT_KEYED + key.dir);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
