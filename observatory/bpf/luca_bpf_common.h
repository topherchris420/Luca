/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Constants shared by the observatory BPF objects (not by userspace). */
#ifndef LUCA_BPF_COMMON_H
#define LUCA_BPF_COMMON_H

#define LUCA_EEXIST 17

/* IP protocol numbers, defined here to avoid libc/UAPI header clashes. */
#define LUCA_IPPROTO_HOPOPTS 0
#define LUCA_IPPROTO_TCP 6
#define LUCA_IPPROTO_UDP 17
#define LUCA_IPPROTO_ROUTING 43
#define LUCA_IPPROTO_FRAGMENT 44
#define LUCA_IPPROTO_DSTOPTS 60
#define LUCA_IPPROTO_SCTP 132
#define LUCA_IPPROTO_UDPLITE 136

#define LUCA_IP_MF 0x2000
#define LUCA_IP_OFFSET 0x1fff

#endif /* LUCA_BPF_COMMON_H */
