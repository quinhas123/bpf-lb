
//go:build ignore

#include "lb.h"

// TODO: ip and mac addresses should be passed via ebpf maps
#define IP(x) (172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

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
        bpf_printk("client packet - request");

        iph->daddr = IP(BACKEND_A);
        eth->h_dest[5] = BACKEND_A;
    } else {
        bpf_printk("server packet - response");

        iph->daddr = IP(CLIENT);
        eth->h_dest[5] = CLIENT;
    }
    iph->saddr = IP(LB);
    eth->h_source[5] = LB;

    iph->check = iph_csum(iph);
    //__u32 key    = 0; 
    //__u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    //if (count) { 
    //    __sync_fetch_and_add(count, 1); 
    //}

    return XDP_TX; 
}

char __license[] SEC("license") = "Dual MIT/GPL";