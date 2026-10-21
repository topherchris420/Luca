/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/*
 * Luca Kernel-Native Network Observatory - types shared by the BPF
 * programs and the userspace collector.
 *
 * Every structure is laid out with explicit padding so that the BPF
 * target and the host compiler (64- or 32-bit) agree on sizes and
 * offsets; the collector checks the sizes with static assertions.
 */
#ifndef LUCA_OBSERVATORY_H
#define LUCA_OBSERVATORY_H

#include <linux/types.h>

/*
 * Directions are expressed from the point of view of the device under
 * inspection, which sits behind Luca's access-point interface:
 *   TX = device -> network, seen at the interface's TC ingress hook;
 *   RX = network -> device, seen at the interface's TC egress hook.
 */
#define LUCA_DIR_TX 0
#define LUCA_DIR_RX 1

#define LUCA_DEFAULT_MAX_FLOWS 65536
#define LUCA_DEFAULT_MAX_DROPS 4096
#define LUCA_PROTO_SLOTS 512 /* 256 IP protocol numbers per direction */

/* Per-CPU global counters. Each base index is followed by its RX slot. */
enum luca_stat {
	LUCA_STAT_SKBS = 0,          /* socket buffers seen by the hook */
	LUCA_STAT_SEGS = 2,          /* GSO/GRO segments those buffers carry */
	LUCA_STAT_BYTES = 4,         /* skb->len, link-layer header included */
	LUCA_STAT_IPV4 = 6,
	LUCA_STAT_IPV6 = 8,
	LUCA_STAT_ARP = 10,
	LUCA_STAT_EAPOL = 12,
	LUCA_STAT_OTHER_L2 = 14,
	LUCA_STAT_PCAP_SKBS = 16,    /* buffers a "tcp or udp" capture filter matches */
	LUCA_STAT_PCAP_SEGS = 18,    /* segments inside those buffers */
	LUCA_STAT_PARSE_ERR = 20,
	LUCA_STAT_FLOW_FULL = 22,    /* packets not attributed: flow table full */
	LUCA_STAT_MAX = 24,
};

/* Per-CPU counters of the drop-reason object, with the same +dir layout. */
enum luca_drop_stat {
	LUCA_DROPSTAT_EVENTS = 0,    /* kfree_skb events attributed to the interface */
	LUCA_DROPSTAT_NOT_KEYED = 2, /* events not keyed: drop table full */
	LUCA_DROPSTAT_MAX = 4,
};

/* Flow identity, normalised to device-side ("local") and remote ends. */
struct luca_flow_key {
	__u8 family;           /* 4 or 6 */
	__u8 proto;            /* final L4 protocol (after IPv6 extension headers) */
	__u16 pad;
	__u16 local_port;      /* host byte order; 0 when the protocol has no ports */
	__u16 remote_port;
	__u8 local_addr[16];   /* IPv4 addresses use the first 4 bytes */
	__u8 remote_addr[16];
};

struct luca_flow_dir {
	__u64 packets;         /* segments */
	__u64 bytes;
	__u64 first_ns;        /* bpf_ktime_get_ns(), CLOCK_MONOTONIC */
	__u64 last_ns;
	__u32 seq_max;         /* highest TCP sequence end seen (seq + payload) */
	__u32 retrans;         /* TCP data segments starting below seq_max:
				  retransmitted or reordered */
	__u8 tcp_flags;        /* union of TCP flags observed */
	__u8 ttl_min;          /* IPv4 TTL / IPv6 hop limit */
	__u8 ttl_max;
	__u8 fragments;        /* 1 when an IP fragment was observed */
	__u8 seq_valid;        /* seq_max holds a value */
	__u8 pad[3];
};

struct luca_flow_value {
	struct luca_flow_dir dir[2];
	__u64 syn_ns;          /* last SYN before the SYN-ACK */
	__u64 synack_ns;       /* first SYN-ACK answering it */
	__u64 ack_ns;          /* first ACK completing the handshake */
	__u8 first_dir;        /* direction of the packet that created the entry */
	__u8 syn_dir;          /* direction the SYN travelled */
	__u8 syn_count;        /* SYNs seen; > 1 means retransmitted (RTT ambiguous) */
	__u8 pad0;
	__u32 pad1;
};

struct luca_counter {
	__u64 packets;
	__u64 bytes;
};

struct luca_drop_key {
	__u32 reason;          /* enum skb_drop_reason, 0 when the kernel has none */
	__u8 dir;              /* LUCA_DIR_TX: arrived on the interface; RX: leaving via it */
	__u8 family;           /* 0 when the packet carried no parsable IP header */
	__u8 proto;
	__u8 pad;
	__u16 remote_port;
	__u16 pad2;
	__u8 remote_addr[16];
};

struct luca_config {
	__u32 ifindex;         /* the monitored access-point interface */
	__u32 netns_ino;       /* its network namespace (ifindex is per-netns) */
};

#endif /* LUCA_OBSERVATORY_H */
