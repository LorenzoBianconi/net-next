// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__ =
	" XDP redirect with a CPU-map type \"BPF_MAP_TYPE_CPUMAP\"";

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <getopt.h>
#include <net/if.h>
#include <time.h>
#include <linux/limits.h>

#include <arpa/inet.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_util.h"

/* CPUMAP value */
struct bpf_cpumap_val {
	__u32 qsize;
	union {
		int fd;
		__u32 id;
	} bpf_prog;
};

static int ifindex = -1;
static char *ifname;
static __u32 prog_id;

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int n_cpus;
static int cpu_map_fd;
static int cpu_map_id;

static const struct option long_options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "dev",	required_argument,	NULL, 'd' },
	{ "progname",	required_argument,	NULL, 'p' },
	{ "qsize",	required_argument,	NULL, 'q' },
	{ "cpu",	required_argument,	NULL, 'c' },
	{ "filename",	required_argument,	NULL, 'f' },
	{ "redirect-device", required_argument,	NULL, 'D' },
	{ "redirect-map", required_argument,	NULL, 'm' },
	{ 0, 0, NULL,  0 }
};

static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(-1);
	}

	if (prog_id == curr_prog_id) {
		fprintf(stderr,
			"Interrupted: Removing XDP program on ifindex:%d device:%s\n",
			ifindex, ifname);
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	} else if (!curr_prog_id) {
		printf("couldn't find a prog id on a given iface\n");
	} else {
		printf("program on interface changed, not removing\n");
	}

	exit(0);
}

static void print_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__is_xdp(pos))
			printf(" %s\n", bpf_program__title(pos, false));
	}
}

static void usage(char *argv[], struct bpf_object *obj)
{
	int i;

	printf("\nDOCUMENTATION:\n%s\n", __doc__);
	printf("\n");
	printf(" Usage: %s (options-see-below)\n", argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
				*long_options[i].flag);
		else
			printf(" short-option: -%c",
				long_options[i].val);
		printf("\n");
	}
	printf("\n Programs to be used for --progname:\n");
	print_avail_progs(obj);
	printf("\n");
}

static int create_cpu_entry(__u32 cpu, struct bpf_cpumap_val *value,
			    __u32 avail_idx)
{
	int ret;

	ret = bpf_map_update_elem(cpu_map_fd, &cpu, value, 0);
	if (ret) {
		fprintf(stderr, "Create CPU entry failed (err:%d)\n", ret);
		exit(ret);
	}

	ret = bpf_map_update_elem(cpu_map_id, &avail_idx, &cpu, 0);
	if (ret) {
		fprintf(stderr, "Add to avail CPUs failed\n");
		exit(ret);
	}

	return 0;
}

static void stats_poll(int interval)
{
	while (1) {
		sleep(interval);
	}
}

static int init_map_fds(struct bpf_object *obj)
{
	cpu_map_fd = bpf_object__find_map_fd_by_name(obj, "cpu_map");
	if (cpu_map_fd < 0)
		return cpu_map_fd;

	cpu_map_id = bpf_object__find_map_fd_by_name(obj, "cpu_id");
	if (cpu_map_id < 0)
		return cpu_map_id;

	return 0;
}

static int load_cpumap_prog(char *file_name, char *prog_name,
			    char *redir_interface, char *redir_map_name)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type		= BPF_PROG_TYPE_XDP,
		.expected_attach_type	= BPF_XDP_CPUMAP,
		.file = file_name,
	};
	struct bpf_program *prog;
	struct bpf_object *obj;
	int fd;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &fd))
		return -1;

	if (fd < 0) {
		fprintf(stderr, "ERR: bpf_prog_load_xattr: %s\n",
			strerror(errno));
		return fd;
	}

	if (redir_interface && redir_map_name) {
		int err, map_fd, ifindex_out, key = 0;

		map_fd = bpf_object__find_map_fd_by_name(obj, redir_map_name);
		if (map_fd < 0)
			return map_fd;

		ifindex_out = if_nametoindex(redir_interface);
		if (!ifindex_out)
			return -1;

		err = bpf_map_update_elem(map_fd, &key, &ifindex_out, 0);
		if (err < 0)
			return err;
	}

	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "bpf_object__find_program_by_title failed\n");
		return -1;
	}

	return bpf_program__fd(prog);
}

int main(int argc, char **argv)
{
	struct rlimit r = {10 * 1024 * 1024, RLIM_INFINITY};
	char *prog_filename = "xdp_cpumap_redirect_kern_prog.o";
	char filename[256] = {}, *prog_name = "xdp_pass";
	char *redir_interface = NULL, *redir_map_name = NULL;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_UNSPEC,
	};
	int cpu_id = 0, fd, opt, err, longindex = 0;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_cpumap_val value;
	struct bpf_program *prog;
	struct bpf_object *obj;
	__u32 qsize = 128 + 64;

	n_cpus = get_nprocs_conf();

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &fd))
		return -1;

	if (fd < 0) {
		fprintf(stderr, "ERR: bpf_prog_load_xattr: %s\n",
			strerror(errno));
		return fd;
	}

	err = init_map_fds(obj);
	if (err < 0) {
		fprintf(stderr, "bpf_object__find_map_fd_by_name failed\n");
		return err;
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "d:c:p:f:q:h:D:m:", long_options,
				  &longindex)) != -1) {
		switch (opt) {
		case 'd': {
			char ifname_buf[IF_NAMESIZE];

			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		}
		case 'D':
			redir_interface = optarg;
			break;
		case 'm':
			redir_map_name = optarg;
			break;
		case 'p':
			/* Selecting eBPF prog to load */
			prog_name = optarg;
			break;
		case 'f':
			prog_filename = optarg;
			break;
		case 'c':
			/* Add multiple CPUs */
			cpu_id = strtoul(optarg, NULL, 0);
			if (cpu_id >= n_cpus) {
				fprintf(stderr,
				"--cpu nr too large for cpumap err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'q':
			qsize = atoi(optarg);
			break;
		case 'h':
		error:
		default:
			usage(argv, obj);
			return -1;
		}
	}

	/* Required option */
	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv, obj);
		return -1;
	}

	value.qsize = qsize;
	value.bpf_prog.fd = load_cpumap_prog(prog_filename, prog_name,
					     redir_interface, redir_map_name);
	if (value.bpf_prog.fd < 0)
		return value.bpf_prog.fd;

	err = create_cpu_entry(cpu_id, &value, 0);
	if (err)
		return err;

	/* Remove XDP program when program is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	prog = bpf_object__find_program_by_title(obj, "xdp_cpu_map");
	if (!prog) {
		fprintf(stderr, "bpf_object__find_program_by_title failed\n");
		return -1;
	}

	fd = bpf_program__fd(prog);
	if (fd < 0) {
		fprintf(stderr, "bpf_program__fd failed\n");
		return fd;
	}

	err = bpf_set_link_xdp_fd(ifindex, fd, xdp_flags);
	if (err < 0) {
		fprintf(stderr, "link set xdp fd failed\n");
		return err;
	}

	err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	stats_poll(2);

	return 0;
}
