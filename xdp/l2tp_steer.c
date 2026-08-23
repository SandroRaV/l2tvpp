// SPDX-License-Identifier: GPL-2.0
/*
 * l2tp_steer loader: attaches l2tp_steer.bpf.o to an interface, fills the
 * CPUMAP with the chosen cores, pins the maps under /sys/fs/bpf/l2tp_steer
 * and exits. The XDP program keeps the maps alive while attached.
 *
 *   l2tp_steer -i eth8 -c 1-7            attach, steer to cpus 1..7
 *   l2tp_steer -i eth8 -c 1-7 -q 4096    larger per-cpu queue
 *   l2tp_steer -i eth8 -S                generic/skb mode (testing only)
 *   l2tp_steer -s                        print counters once
 *   l2tp_steer -s -w 1                   print counters every second
 *   l2tp_steer -i eth8 -d                detach and unpin
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <net/if.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PIN_DIR   "/sys/fs/bpf/l2tp_steer"
#define MAX_CPUS  256
#define STAT_MAX  4

static const char *stat_names[STAT_MAX] = {
	"pass_other", "pass_ctrl", "redirect", "redirect_fail",
};

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: %s -i IFACE -c CPULIST [-q QSIZE] [-S] [-o OBJ]\n"
		"       %s -i IFACE -d\n"
		"       %s -s [-w SECONDS]\n"
		"  -i IFACE     interface facing the LAC(s)\n"
		"  -c CPULIST   cpus to steer to, e.g. 1-7 or 2,4,6-11\n"
		"  -q QSIZE     cpumap queue size per cpu (default 2048)\n"
		"  -S           generic (skb) XDP mode instead of native\n"
		"  -o OBJ       path to l2tp_steer.bpf.o (default: next to binary)\n"
		"  -d           detach from IFACE and remove pinned maps\n"
		"  -s           show counters (needs attached program)\n"
		"  -w SECONDS   repeat counters every SECONDS\n",
		p, p, p);
	exit(1);
}

/* "1-3,5,8-9" -> cpus[], returns count */
static int parse_cpulist(const char *s, unsigned *cpus, int max)
{
	int n = 0;
	char *dup = strdup(s), *tok, *save;

	for (tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		unsigned a, b;
		if (sscanf(tok, "%u-%u", &a, &b) == 2) {
		} else if (sscanf(tok, "%u", &a) == 1) {
			b = a;
		} else {
			fprintf(stderr, "bad cpu list item '%s'\n", tok);
			exit(1);
		}
		for (unsigned c = a; c <= b; c++) {
			if (n >= max) { fprintf(stderr, "too many cpus\n"); exit(1); }
			cpus[n++] = c;
		}
	}
	free(dup);
	return n;
}

static int show_stats(int interval)
{
	int fd = bpf_obj_get(PIN_DIR "/stats");
	if (fd < 0) {
		fprintf(stderr, "cannot open pinned stats map %s/stats: %s "
			"(is the program attached?)\n", PIN_DIR, strerror(errno));
		return 1;
	}
	int ncpu = libbpf_num_possible_cpus();
	__u64 vals[ncpu], prev[STAT_MAX], cur[STAT_MAX];
	memset(prev, 0, sizeof(prev));

	for (;;) {
		for (__u32 k = 0; k < STAT_MAX; k++) {
			if (bpf_map_lookup_elem(fd, &k, vals)) {
				perror("lookup stats");
				return 1;
			}
			cur[k] = 0;
			for (int c = 0; c < ncpu; c++)
				cur[k] += vals[c];
		}
		for (__u32 k = 0; k < STAT_MAX; k++) {
			if (interval)
				printf("%-14s %14llu (%llu/s)\n", stat_names[k],
				       (unsigned long long)cur[k],
				       (unsigned long long)((cur[k] - prev[k]) / interval));
			else
				printf("%-14s %14llu\n", stat_names[k],
				       (unsigned long long)cur[k]);
			prev[k] = cur[k];
		}
		if (!interval)
			break;
		printf("\n");
		sleep(interval);
	}
	return 0;
}

static int detach(int ifindex, __u32 flags)
{
	int err = bpf_xdp_detach(ifindex, flags, NULL);
	if (err)
		fprintf(stderr, "detach: %s\n", strerror(-err));
	const char *maps[] = { "cpu_map", "cpus_available", "cpu_count", "stats" };
	for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
		char path[256];
		snprintf(path, sizeof(path), PIN_DIR "/%s", maps[i]);
		unlink(path);
	}
	rmdir(PIN_DIR);
	return err ? 1 : 0;
}

int main(int argc, char **argv)
{
	const char *iface = NULL, *cpulist = NULL, *objpath = NULL;
	unsigned qsize = 2048;
	int opt, do_detach = 0, do_stats = 0, interval = 0;
	__u32 xdp_flags = XDP_FLAGS_DRV_MODE;

	while ((opt = getopt(argc, argv, "i:c:q:So:dsw:h")) != -1) {
		switch (opt) {
		case 'i': iface = optarg; break;
		case 'c': cpulist = optarg; break;
		case 'q': qsize = atoi(optarg); break;
		case 'S': xdp_flags = XDP_FLAGS_SKB_MODE; break;
		case 'o': objpath = optarg; break;
		case 'd': do_detach = 1; break;
		case 's': do_stats = 1; break;
		case 'w': interval = atoi(optarg); break;
		default: usage(argv[0]);
		}
	}

	if (do_stats)
		return show_stats(interval);

	if (!iface)
		usage(argv[0]);
	int ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "unknown interface %s\n", iface);
		return 1;
	}

	if (do_detach)
		return detach(ifindex, xdp_flags);

	if (!cpulist)
		usage(argv[0]);
	unsigned cpus[MAX_CPUS];
	int ncpus = parse_cpulist(cpulist, cpus, MAX_CPUS);
	int possible = libbpf_num_possible_cpus();
	for (int i = 0; i < ncpus; i++) {
		if ((int)cpus[i] >= possible) {
			fprintf(stderr, "cpu %u does not exist (%d possible)\n",
				cpus[i], possible);
			return 1;
		}
	}

	char objbuf[512];
	if (!objpath) {
		/* default: l2tp_steer.bpf.o next to the binary */
		ssize_t n = readlink("/proc/self/exe", objbuf, sizeof(objbuf) - 32);
		if (n < 0) { perror("readlink"); return 1; }
		objbuf[n] = 0;
		char *slash = strrchr(objbuf, '/');
		strcpy(slash ? slash + 1 : objbuf, "l2tp_steer.bpf.o");
		objpath = objbuf;
	}

	struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
	if (!obj) {
		fprintf(stderr, "open %s: %s\n", objpath, strerror(errno));
		return 1;
	}
	int err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load: %s\n", strerror(-err));
		return 1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "l2tp_steer");
	struct bpf_map *m_cpu   = bpf_object__find_map_by_name(obj, "cpu_map");
	struct bpf_map *m_avail = bpf_object__find_map_by_name(obj, "cpus_available");
	struct bpf_map *m_count = bpf_object__find_map_by_name(obj, "cpu_count");
	if (!prog || !m_cpu || !m_avail || !m_count) {
		fprintf(stderr, "object file is missing program or maps\n");
		return 1;
	}

	/* Fill cpumap and the dense cpu list */
	for (int i = 0; i < ncpus; i++) {
		struct bpf_cpumap_val val = { .qsize = qsize };
		__u32 key = cpus[i], idx = i;
		err = bpf_map_update_elem(bpf_map__fd(m_cpu), &key, &val, 0);
		if (err) {
			fprintf(stderr, "cpumap add cpu %u: %s\n", key, strerror(errno));
			return 1;
		}
		bpf_map_update_elem(bpf_map__fd(m_avail), &idx, &key, 0);
	}
	__u32 zero = 0, count = ncpus;
	bpf_map_update_elem(bpf_map__fd(m_count), &zero, &count, 0);

	/* Pin maps so "-s" and "-d" can find them later */
	mkdir("/sys/fs/bpf", 0755);
	err = bpf_object__pin_maps(obj, PIN_DIR);
	if (err) {
		fprintf(stderr, "pin maps to %s: %s (already attached? use -d first)\n",
			PIN_DIR, strerror(-err));
		return 1;
	}

	err = bpf_xdp_attach(ifindex, bpf_program__fd(prog), xdp_flags, NULL);
	if (err) {
		fprintf(stderr, "attach to %s: %s\n", iface, strerror(-err));
		bpf_object__unpin_maps(obj, PIN_DIR);
		return 1;
	}

	printf("l2tp_steer attached to %s (%s mode), %d cpus [%s], qsize %u\n",
	       iface, xdp_flags == XDP_FLAGS_SKB_MODE ? "generic" : "native",
	       ncpus, cpulist, qsize);
	return 0;
}
