#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

// stores next ebpf program in the chain or nothing if this is the last one.
struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} next_prog SEC(".maps");

// Hashmap to store allowed ports. For example 443 -> 1 (allow TCP traffic on port 443)
// 0 -> block
// 1 -> allow TCP
// 2 -> allow UDP
// 3 -> allow TCP and UDP
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 256);
} allowed_ports SEC(".maps");

static inline int check_port_protocol(__u16 port, __u8 protocol)
{
    __u8 *allowed = bpf_map_lookup_elem(&allowed_ports, &port);

    if (!allowed)
    {
        // 0 or nor found -> block port
        return XDP_DROP;
    }

    if (*allowed == 1 && protocol == IPPROTO_TCP)
    {
        return XDP_PASS;
    }
    else if (*allowed == 2 && protocol == IPPROTO_UDP)
    {
        return XDP_PASS;
    }
    else if (*allowed == 3 && (protocol == IPPROTO_UDP || protocol == IPPROTO_TCP))
    {
        return XDP_PASS;
    }

    return XDP_DROP;
}

SEC("xdp_prog")
int simple_firewall(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // check enough space for ethernet header in packet
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP; // abort or drop?

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udph = (void *)iph + sizeof(*iph);
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;
        return check_port_protocol(udph->dest, iph->protocol);
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (void *)iph + sizeof(*iph);
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;
        return check_port_protocol(tcph->dest, iph->protocol);
    }

    // calls next program in chain, if set
    bpf_tail_call(ctx, &next_prog, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";