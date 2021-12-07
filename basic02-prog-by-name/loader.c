/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Specify BPF-object --filename to load \n"
	" - and select BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/resource.h> // CAN

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"


#define LOAD_BPF_NETWORK
#define PIN_PROGS

#ifdef LOAD_BPF_NETWORK

// enum bpf_prog_type all_types[] = {
// 		BPF_PROG_TYPE_UNSPEC,			( 0 )
// 		BPF_PROG_TYPE_SOCKET_FILTER,    ( 1 ) 
// 		BPF_PROG_TYPE_KPROBE,			( ... )
// 		BPF_PROG_TYPE_SCHED_CLS,
// 		BPF_PROG_TYPE_SCHED_ACT,
// 		BPF_PROG_TYPE_TRACEPOINT,
// 		BPF_PROG_TYPE_XDP,
// 		BPF_PROG_TYPE_PERF_EVENT,
// 		BPF_PROG_TYPE_CGROUP_SKB,
// 		BPF_PROG_TYPE_CGROUP_SOCK,
// 		BPF_PROG_TYPE_LWT_IN,			( 10 )
// 		BPF_PROG_TYPE_LWT_OUT,
// 		BPF_PROG_TYPE_LWT_XMIT,
// 		BPF_PROG_TYPE_SOCK_OPS,
// 		BPF_PROG_TYPE_SK_SKB,
// 		BPF_PROG_TYPE_CGROUP_DEVICE,
// 		BPF_PROG_TYPE_SK_MSG,
// 		BPF_PROG_TYPE_RAW_TRACEPOINT,
// 		BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
// 		BPF_PROG_TYPE_LWT_SEG6LOCAL,
// 		BPF_PROG_TYPE_LIRC_MODE2,		( 20 )
// 		BPF_PROG_TYPE_SK_REUSEPORT,
// 		BPF_PROG_TYPE_FLOW_DISSECTOR,
// 		BPF_PROG_TYPE_CGROUP_SYSCTL,
// 		BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
// 		BPF_PROG_TYPE_CGROUP_SOCKOPT,
// };
static struct bpf_progs_desc progs[] = {
	// can have type 1,3,4,8,10,11,12,19
	{"from-network", BPF_PROG_TYPE_SCHED_CLS, NULL},
};
static int prog_count = 1;
#endif



static const char *default_filename = "xdp_prog_kern.o";  // unused
static const char *default_progsec = "xdp_pass";  // unused

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"offload-mode",no_argument,		NULL, 3 },
	 "Hardware offload XDP program to NIC"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

/* Lesson#1: More advanced load_bpf_object_file and bpf_object */
struct bpf_object *__load_bpf_object_file(const char *filename, int ifindex)
{
	/* In next assignment this will be moved into ../common/ */
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* Lesson#3: This struct allow us to set ifindex, this features is used
	 * for hardware offloading XDP programs.
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.ifindex	= ifindex,
	};
	prog_load_attr.file = filename;


#ifdef LOAD_BPF_XDP
	char* outer_map_names[] = {"test_cilium_lb6_maglev_outer", "test_cilium_lb4_maglev_outer"};
	int num_outer_maps = 2;
#endif
#ifdef LOAD_BPF_HOST
	char* outer_map_names[] = {};
	int num_outer_maps = 0;
#endif
#ifdef LOAD_BPF_NETWORK
	char* outer_map_names[] = {};
	int num_outer_maps = 0;
#endif

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr_w_inner_maps(&prog_load_attr, &obj, &first_prog_fd, outer_map_names, num_outer_maps, progs, prog_count);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

/* Lesson#2: This is a central piece of this lesson:
 * - Notice how BPF-ELF obj can have several programs
 * - Find by sec name via: bpf_object__find_program_by_title()
 */
struct bpf_object *__load_bpf_and_xdp_attach(struct config *cfg)
{
	/* In next assignment this will be moved into ../common/ */
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int err;

	/* If flags indicate hardware offload, supply ifindex */
	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
		offload_ifindex = cfg->ifindex;

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
	bpf_obj = __load_bpf_object_file(cfg->filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	/* Find a matching BPF prog section name */
	bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: finding progsec: %s\n", cfg->progsec);
		exit(EXIT_FAIL_BPF);
	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

#ifdef PIN_PROGS
#define PATH_MAX 4096
#define BPF_SYSFS_ROOT "/sys/fs/bpf"
	char filename[PATH_MAX];
	for (int i = 0; i < prog_count; i++) {

		int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, progs[i].name);
		if (len < 0) {
			fprintf(stderr, "Error: Program name '%s' is invalid\n", progs[i].name);
			return NULL;
		} else if (len >= PATH_MAX) {
			fprintf(stderr, "Error: Program name '%s' is too long\n", progs[i].name);
			return NULL;
		}
retry:
		if (bpf_program__pin_instance(progs[i].prog, filename, 0)) {
			fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", progs[i].name, filename);
			if (errno == EEXIST) {
				fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", progs[i].name);
				if (bpf_program__unpin_instance(progs[i].prog, filename, 0)) {
					fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", progs[i].name, filename);
					return NULL;
				}
				goto retry;
			}
			return NULL;
		}
		
	}
#endif

#ifdef ATTACH_TO_XDP_HOOK
	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
	if (err) {
		fprintf(stderr, "ERR: xdp_link_attach failed\n");
		exit(err);
	}
#else
	/* To attach a pinned program manually, use one of the following:
	 * 
	 * tc qdisc add dev <interface_name> clsact
	 * sudo tc filter add dev <interface_name> {ingress/egress} bpf object-pinned /sys/fs/bpf/<prog_name>		(for tc programs)
	 * 
	 * sudo ip link set dev <interface_name> xdpgeneric pinned /sys/fs/bpf/<prog_name>							(for xdp programs, have to check again if this was the exact command)
	 * 
	 * To list attached programs:
	 * tc -s -d filter show dev <interface_name> {ingress/egress}
	 * ip link show dev <interface_name>
	 */
	fprintf(stderr, "Not attaching to an XDP hook, done.\n");
	exit(0);
#endif

	return bpf_obj;
}

static void list_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	printf("BPF object (%s) listing avail --progsec names\n",
	       bpf_object__name(obj));

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__is_xdp(pos))
			printf(" %s\n", bpf_program__title(pos, false));
	}
}

int main(int argc, char **argv)
{
	// --- (see https://github.com/xdp-project/xdp-tutorial/issues/63) --- //
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
			perror("setrlimit(RLIMIT_MEMLOCK)");
			return 1;
	}
	// ------------------------------------------------------------------- //

	struct bpf_object *bpf_obj;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change these */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	bpf_obj = __load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose)
		list_avail_progs(bpf_obj);

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}
	/* Other BPF section programs will get freed on exit */
	return EXIT_OK;
}
