import os

types = "socket kprobe/ uprobe/ kretprobe/ uretprobe/ classifier action tracepoint/ tp/ raw_tracepoint/ raw_tp/ tp_btf/ xdp perf_event lwt_in lwt_out lwt_xmit lwt_seg6local cgroup_skb/ingress cgroup_skb/egress cgroup/skb cgroup/sock cgroup/post_bind4 cgroup/post_bind6 cgroup/dev sockops sk_skb/stream_parser sk_skb/stream_verdict sk_skb sk_msg lirc_mode2 flow_dissector cgroup/bind4 cgroup/bind6 cgroup/connect4 cgroup/connect6 cgroup/sendmsg4 cgroup/sendmsg6 cgroup/recvmsg4 cgroup/recvmsg6 cgroup/sysctl cgroup/getsockopt cgroup/setsockopt"
for t in types.split():
    os.system(f"echo \"Trying with type {t}\"")
    f = open("bpf_prog_type.h", "w")
    f.write(f"#define BPF_PROG_TYPE \"{t}_\"")
    f.close()
    os.system("make clean")
    os.system("make")
    os.system("sudo ./loader --dev veth-basic02 --force  --filename bpf_network.o --progsec {t}_from-network")