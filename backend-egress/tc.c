//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>   // struct ethhdr, ETH_P_IP
#include <linux/ip.h>         // struct iphdr (IPv4)
#include <linux/tcp.h>        // struct tcphdr
#include <linux/udp.h>        // struct udphdr
#include <linux/in.h>         // IPPROTO_TCP, IPPROTO_UDP
#include <linux/pkt_cls.h>    // TC_ACT_OK
#include <bpf/bpf_helpers.h>  // SEC(), bpf_skb_store_bytes(), bpf_l3/l4_csum_replace()
#include <bpf/bpf_endian.h>   // bpf_htons

// DSR
// VIP must match the address the LB owns. Encoded little-endian so the
// network-order bytes land in memory unchanged, matching the bpfel target and
// the XDP program's IP() macro convention.
#define IP(a, b, c, d) ((__be32)((a) | ((b) << 8) | ((c) << 16) | ((d) << 24)))
#define VIP          IP(10, 0, 0, 1)
#define SERVICE_PORT 8080

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return TC_ACT_OK;

    void *l4hdr = (void *)iph + ihl;
    if (l4hdr > data_end)
        return TC_ACT_OK;

    __u8   proto     = iph->protocol;
    __be32 old_saddr = iph->saddr;

    __be16 sport;
    __u16  udp_check = 0;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *th = l4hdr;
        if ((void *)(th + 1) > data_end)
            return TC_ACT_OK;
        sport = th->source;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *uh = l4hdr;
        if ((void *)(uh + 1) > data_end)
            return TC_ACT_OK;
        sport = uh->source;
        udp_check = uh->check;
    } else {
        return TC_ACT_OK;
    }

    if (sport != bpf_htons(SERVICE_PORT))
        return TC_ACT_OK;

    __be32 new_saddr = VIP;
    if (old_saddr == new_saddr)
        return TC_ACT_OK;

    const int l3_off    = sizeof(struct ethhdr);
    const int saddr_off = l3_off + __builtin_offsetof(struct iphdr, saddr);
    const int ipsum_off = l3_off + __builtin_offsetof(struct iphdr, check);

    // rewrite packet source address
    if (bpf_skb_store_bytes(skb, saddr_off, &new_saddr, sizeof(new_saddr), 0) < 0)
        return TC_ACT_OK;
    // recompute L3 csum
    if (bpf_l3_csum_replace(skb, ipsum_off, old_saddr, new_saddr, sizeof(new_saddr)) < 0)
        return TC_ACT_OK;

    // recompute L4 csum
    if (proto == IPPROTO_TCP) {
        int l4sum_off = l3_off + ihl + __builtin_offsetof(struct tcphdr, check);
        bpf_l4_csum_replace(skb, l4sum_off, old_saddr, new_saddr,
                            BPF_F_PSEUDO_HDR | sizeof(new_saddr));
    } else if (udp_check != 0) {
        // A zero UDP checksum means "no checksum" in IPv4; leave it alone.
        // BPF_F_MARK_MANGLED_0 keeps a computed-to-zero result as 0xffff.
        int l4sum_off = l3_off + ihl + __builtin_offsetof(struct udphdr, check);
        bpf_l4_csum_replace(skb, l4sum_off, old_saddr, new_saddr,
                            BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(new_saddr));
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
