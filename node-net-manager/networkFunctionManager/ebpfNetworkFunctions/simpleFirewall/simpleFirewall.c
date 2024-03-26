#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 256);
} allowed_ports SEC(".maps");

static inline int check_port(__u32 port, void *data_end) {
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ports, &port);
    if (allowed) {
        return XDP_PASS;
    }
    return XDP_DROP;
}

SEC("xdp_prog")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + sizeof(*iph);
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;
        return check_port(udph->dest, data_end);
    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;
        return check_port(tcph->dest, data_end);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";