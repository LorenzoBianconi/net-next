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

#define MAX_CPUS NR_CPUS

/* CPUMAP value */
struct bpf_cpumap_val {
	u32 qsize;
	union {
		int fd;
		u32 id;
	} bpf_prog;
};

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, NR_CPUS);
} cpu_map SEC(".maps");

/* Set of maps controlling available CPU, and for iterating through
 * selectable redirect CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cpu_id SEC(".maps");

SEC("xdp_cpu_map")
int xdp_prog_cpumap(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 *cpu_selected;
	u32 cpu_dest;
	u32 key = 0;

	cpu_selected = bpf_map_lookup_elem(&cpu_id, &key);
	if (!cpu_selected)
		return XDP_ABORTED;

	cpu_dest = *cpu_selected;
	if (cpu_dest >= MAX_CPUS)
		return XDP_ABORTED;

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

char _license[] SEC("license") = "GPL";

