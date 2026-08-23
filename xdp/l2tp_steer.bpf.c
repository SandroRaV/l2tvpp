// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Default Gateway GmbH
/*
 * l2tp_steer: XDP program that spreads incoming L2TPv2 data packets over
 * CPU cores by tunnel ID + session ID, using a CPUMAP redirect.
 *
 * Problem it solves: all tunnels from one LAC share the same UDP 4-tuple
 * (LAC:1701 -> LNS:1701), so NIC RSS puts every session behind that LAC on
 * a single RX queue / core. This program runs before the kernel L2TP code,
 * parses the L2TPv2 header and hands the frame to a per-core CPUMAP entry.
 * The normal kernel stack (l2tp_core, pppol2tp, ppp, routing, tc) then runs
 * on that core. Control messages (T bit set) and everything that is not
 * L2TPv2 data are passed untouched.
 *
 * No CO-RE / vmlinux.h needed: only UAPI headers and helpers are used.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define L2TP_UDP_PORT 1701
#define MAX_CPUS      256

/* L2TPv2 header flag bits (RFC 2661, section 3.1) */
#define L2TP_HDR_T    0x8000 /* 1 = control message */
#define L2TP_HDR_L    0x4000 /* length field present */
#define L2TP_HDR_S    0x0800 /* Ns/Nr present */
#define L2TP_HDR_O    0x0200 /* offset size present */
#define L2TP_HDR_VER  0x000F

/* Target map for bpf_redirect_map(): key = cpu id, value = queue size */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, MAX_CPUS);
} cpu_map SEC(".maps");

/* Dense list of usable cpu ids, index 0..cpu_count-1 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_CPUS);
} cpus_available SEC(".maps");

/* Single entry: number of valid entries in cpus_available */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} cpu_count SEC(".maps");

enum stat_idx {
	STAT_PASS_OTHER = 0, /* not L2TPv2 data (or unparsable) */
	STAT_PASS_CTRL,      /* L2TP control message */
	STAT_REDIRECT,       /* data packet redirected to another core */
	STAT_REDIRECT_FAIL,  /* cpumap lookup failed, passed instead */
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		(*v)++;
}

static __always_inline int pass(__u32 idx)
{
	count(idx);
	return XDP_PASS;
}

SEC("xdp")
int l2tp_steer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *cur      = data;
	__u16 proto;
	__u8  l4proto;
	int   i;

	/* Ethernet */
	struct ethhdr *eth = cur;
	if ((void *)(eth + 1) > data_end)
		return pass(STAT_PASS_OTHER);
	proto = eth->h_proto;
	cur   = eth + 1;

	/* Up to two VLAN tags (QinQ). NICs with HW VLAN strip hide the tag. */
#pragma unroll
	for (i = 0; i < 2; i++) {
		if (proto == bpf_htons(ETH_P_8021Q) ||
		    proto == bpf_htons(ETH_P_8021AD)) {
			struct vlan_hdr *vh = cur;
			if ((void *)(vh + 1) > data_end)
				return pass(STAT_PASS_OTHER);
			proto = vh->h_vlan_encapsulated_proto;
			cur   = vh + 1;
		}
	}

	/* IPv4 / IPv6 outer header */
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = cur;
		if ((void *)(iph + 1) > data_end)
			return pass(STAT_PASS_OTHER);
		if (iph->ihl < 5)
			return pass(STAT_PASS_OTHER);
		/* Non-first fragments carry no UDP header: let the kernel
		 * reassemble them wherever they land. */
		if (iph->frag_off & bpf_htons(0x1FFF))
			return pass(STAT_PASS_OTHER);
		l4proto = iph->protocol;
		cur = (void *)iph + iph->ihl * 4;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = cur;
		if ((void *)(ip6h + 1) > data_end)
			return pass(STAT_PASS_OTHER);
		/* No extension header walking: L2TP over plain IPv6/UDP only */
		l4proto = ip6h->nexthdr;
		cur = ip6h + 1;
	} else {
		return pass(STAT_PASS_OTHER);
	}

	if (l4proto != IPPROTO_UDP)
		return pass(STAT_PASS_OTHER);

	/* UDP */
	struct udphdr *udph = cur;
	if ((void *)(udph + 1) > data_end)
		return pass(STAT_PASS_OTHER);
	if (udph->dest != bpf_htons(L2TP_UDP_PORT))
		return pass(STAT_PASS_OTHER);
	cur = udph + 1;

	/* L2TPv2 header: flags/version, [length], tunnel id, session id, ... */
	__u16 *flagsp = cur;
	if ((void *)(flagsp + 1) > data_end)
		return pass(STAT_PASS_OTHER);
	__u16 flags = bpf_ntohs(*flagsp);

	if ((flags & L2TP_HDR_VER) != 2)
		return pass(STAT_PASS_OTHER);   /* L2TPv3 or garbage */
	if (flags & L2TP_HDR_T)
		return pass(STAT_PASS_CTRL);    /* control channel: stay put */

	__u16 *idp = flagsp + 1;
	if (flags & L2TP_HDR_L)
		idp++;                          /* skip optional Length */
	if ((void *)(idp + 2) > data_end)
		return pass(STAT_PASS_OTHER);

	__u32 tunnel_id  = bpf_ntohs(idp[0]);
	__u32 session_id = bpf_ntohs(idp[1]);

	/* Hash tunnel+session. Multiplicative hash is enough here: the goal is
	 * "same session -> same core" plus a reasonable spread. */
	__u32 h = ((tunnel_id << 16) | session_id) * 0x9E3779B1u;
	h ^= h >> 16;

	__u32 zero = 0;
	__u32 *n = bpf_map_lookup_elem(&cpu_count, &zero);
	if (!n || *n == 0)
		return pass(STAT_REDIRECT_FAIL);

	__u32 idx = h % *n;
	__u32 *cpu = bpf_map_lookup_elem(&cpus_available, &idx);
	if (!cpu)
		return pass(STAT_REDIRECT_FAIL);

	long ret = bpf_redirect_map(&cpu_map, *cpu, 0);
	if (ret != XDP_REDIRECT)
		return pass(STAT_REDIRECT_FAIL);

	count(STAT_REDIRECT);
	return XDP_REDIRECT;
}

char _license[] SEC("license") = "GPL";
