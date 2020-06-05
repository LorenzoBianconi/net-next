/*  XDP redirect to CPUs via cpumap (BPF_MAP_TYPE_CPUMAP)
 *
 *  GPLv2, Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "hash_func01.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} tx_port SEC(".maps");

SEC("xdp_redirect")
int xdp_redirect_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int *ifindex, port = 0;

	ifindex = bpf_map_lookup_elem(&tx_port, &port);
	if (!ifindex)
		return XDP_DROP;

	return bpf_redirect(*ifindex, 0);
}

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
