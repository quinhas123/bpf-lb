
//go:build ignore

#include "lb.h"

// TODO: ip and mac addresses should be passed via ebpf maps
#define IP(x) (172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

#define CIRC_ARRAY_SIZE 2

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CIRC_ARRAY_SIZE);
} backend_circ_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} index_map SEC(".maps");

SEC("xdp") 
int lb(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    // TODO: review in future
    // curl -> TCP 
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (iph->saddr == IP(CLIENT)) {
        //round-robin per packet == broken for any multi-packet flow.
        bpf_printk("client packet - request");

        __u32 key    = 0; 
        __u32 *idx = bpf_map_lookup_elem(&index_map, &key);

        if (idx == NULL)
            return XDP_PASS;

        bpf_printk("map index %u", *idx);
        __u32 *backend_n = bpf_map_lookup_elem(&backend_circ_array, idx);

        if (backend_n == NULL) 
            return XDP_PASS;
        
        bpf_printk("backend %u", *backend_n);

        iph->daddr = IP(*backend_n);
        eth->h_dest[5] = *backend_n;

        __u32 pos = (*idx + 1) % CIRC_ARRAY_SIZE;
        bpf_map_update_elem(&index_map, &key, &pos, BPF_ANY);
    } else {
        bpf_printk("server packet - response");

        iph->daddr = IP(CLIENT);
        eth->h_dest[5] = CLIENT;
    }
    iph->saddr = IP(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);

    return XDP_TX; 
}

char __license[] SEC("license") = "Dual MIT/GPL";    