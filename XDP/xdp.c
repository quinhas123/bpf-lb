//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>   // struct ethhdr, ETH_P_IP, ETH_P_IPV6, ETH_ALEN
#include <linux/ip.h>         // struct iphdr (IPv4)
#include <linux/ipv6.h>       // struct ipv6hdr
#include <linux/tcp.h>        // struct tcphdr
#include <linux/udp.h>        // struct udphdr
#include <linux/in.h>         // IPPROTO_TCP, IPPROTO_UDP
#include <bpf/bpf_helpers.h>  // SEC(), bpf_printk(), bpf_csum_diff()
#include <bpf/bpf_endian.h>   // bpf_htons / bpf_ntohs (network <-> host byte order)

#define MAX_BACKENDS 256

struct backend {
    __be32 ip;
    __u8   mac[6];
};

struct flow_key {
    __be32 saddr;
    __be16 sport;
    __u8   proto;
};

// initialize whole struct with 0 so trash bytes dont occupy the padding byte and potentially ruin hashmap lookups
static __always_inline struct flow_key flow_key_of(__be32 saddr, __u16 sport, __u8 proto) {
    struct flow_key fk;
    __builtin_memset(&fk, 0, sizeof(fk));
    fk.saddr = saddr;
    fk.sport = bpf_htons(sport);
    fk.proto = proto;
    return fk;
}

enum l7_proto {
    L7_UNKNOWN = 0,
    L7_HTTP,
    L7_HTTPS,
    L7_DNS,
    L7_SSH,
    L7_QUIC,
    L7_SMTP,
    L7_FTP,
    L7_MAX,  // keep last: number of L7 protocols, sizes the per-protocol maps
};

struct inner_backends {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct backend));
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, L7_MAX);
    __type(key, enum l7_proto);
    __array(values, struct inner_backends);
} backend_pools SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, enum l7_proto);
    __type(value, __u32);
    __uint(max_entries, L7_MAX);
} rr_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, enum l7_proto);
    __type(value, __u32);
    __uint(max_entries, L7_MAX);
} backend_count SEC(".maps");

static __always_inline enum l7_proto l7_from_ports(__u8 l4, __u16 sport, __u16 dport) {
    // sort the two ports for symmetrical protocol identification in request and response
    __u16 p1 = sport < dport ? sport : dport;
    __u16 p2 = sport < dport ? dport : sport;

    if (l4 == IPPROTO_TCP) {
        if (p1 == 80   || p2 == 80)   return L7_HTTP;
        if (p1 == 8080 || p2 == 8080) return L7_HTTP;
        if (p1 == 443  || p2 == 443)  return L7_HTTPS;
        if (p1 == 22   || p2 == 22)   return L7_SSH;
        if (p1 == 53   || p2 == 53)   return L7_DNS;
    } else if (l4 == IPPROTO_UDP) {
        if (p1 == 53  || p2 == 53)  return L7_DNS;
    }
    return L7_UNKNOWN;
}

// basically linux kernel csum_fold
static __always_inline __u16 csum_fold(__u64 csum) {
    csum = (csum & 0xffffffff) + (csum >> 32);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16 csum_replace32(__u16 old_check, __be32 old, __be32 new) {
    __u64 sum = bpf_csum_diff(&old, sizeof(old), &new, sizeof(new),
                              (__u32)(~old_check & 0xffff));
    return csum_fold(sum);
}

static __always_inline int rewrite_to_backend(struct ethhdr *eth, struct iphdr *iph,
                                               void *l4hdr, void *data_end,
                                               struct backend *b) {
    // rearrange MAC addresses
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, b->mac, ETH_ALEN);

    // utilize DNAT translation (for now)
    __be32 old_daddr = iph->daddr;
    iph->daddr = b->ip;
    iph->check = csum_replace32(iph->check, old_daddr, iph->daddr);
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4hdr;
        if ((void *)(th + 1) > data_end)
            return XDP_PASS;
        th->check = csum_replace32(th->check, old_daddr, iph->daddr);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4hdr;
        if ((void *)(uh + 1) > data_end)
            return XDP_PASS;
        // zero UDP checksum means "no checksum" in IPv4; leave it alone.
        if (uh->check) {
            __u16 c = csum_replace32(uh->check, old_daddr, iph->daddr);
            uh->check = c ? c : 0xffff;  // 0 is reserved, use the equivalent 0xffff
        }
    }

    return XDP_TX;
}

// FNV-1a simple hashing for consistent hashing (no remapping supported)
static __always_inline __u32 flow_hash(const struct flow_key *fk) {
    __u32 offset = 2166136261u;
    __u32 prime  = 16777619u;
    offset = (offset ^ (fk->saddr         & 0xff)) * prime;
    offset = (offset ^ ((fk->saddr >> 8)  & 0xff)) * prime;
    offset = (offset ^ ((fk->saddr >> 16) & 0xff)) * prime;
    offset = (offset ^ ((fk->saddr >> 24) & 0xff)) * prime;
    offset = (offset ^ (fk->sport         & 0xff)) * prime;
    offset = (offset ^ ((fk->sport >> 8)  & 0xff)) * prime;
    offset = (offset ^ fk->proto)                  * prime;
    return offset;
}

static __always_inline int hash_balance(struct ethhdr *eth, struct iphdr *iph,
                                         void *l4hdr, void *data_end,
                                         struct flow_key *fk, enum l7_proto l7) {
    __u32 *count = bpf_map_lookup_elem(&backend_count, &l7);
    if (!count || *count == 0)
        return XDP_PASS;

    void *pool = bpf_map_lookup_elem(&backend_pools, &l7);
    if (!pool)
        return XDP_PASS;

    __u32 slot = flow_hash(fk) % *count;

    struct backend *b = bpf_map_lookup_elem(pool, &slot);
    if (!b)
        return XDP_PASS;

    return rewrite_to_backend(eth, iph, l4hdr, data_end, b);
}

static __always_inline int round_robin(struct ethhdr *eth, struct iphdr *iph,
                                        void *l4hdr, void *data_end, enum l7_proto l7) {
    __u32 *count = bpf_map_lookup_elem(&backend_count, &l7);
    if (!count || *count == 0)
        return XDP_PASS;

    void *pool = bpf_map_lookup_elem(&backend_pools, &l7);
    if (!pool)
        return XDP_PASS;

    __u32 *counter = bpf_map_lookup_elem(&rr_counter, &l7);
    if (!counter)
        return XDP_PASS;

    __u32 slot = *counter % *count;
    *counter += 1;

    struct backend *b = bpf_map_lookup_elem(pool, &slot);
    if (!b)
        return XDP_PASS;

    return rewrite_to_backend(eth, iph, l4hdr, data_end, b);
}

static __always_inline int balance(struct ethhdr *eth, struct iphdr *iph,
                                    void *l4hdr, void *data_end,
                                    struct flow_key *fk, enum l7_proto l7) {
    switch (l7) {
    case L7_HTTP:
    case L7_HTTPS:
    case L7_SSH:
        return hash_balance(eth, iph, l4hdr, data_end, fk, l7);
    default:
        return round_robin(eth, iph, l4hdr, data_end, l7);
    }
}

SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *iph = NULL;  // ipv4 only
    __u8 l4proto;
    void *l4hdr;

    // IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        iph = (void *)(eth + 1);
        // next byte of iph (struct iphdr) is beyond data_end memory address
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }


        __u32 ihl = iph->ihl * 4;
        // header length (represented in 4-byte increments) is smaller than iphdr struct byte size
        if (ihl < sizeof(*iph)) {
            return XDP_PASS;
        }

        // start of packet content
        l4hdr = (void *)iph + ihl;
        if (l4hdr > data_end) {
            return XDP_PASS;
        }

        l4proto = iph->protocol;
    }  else {
        return XDP_PASS;
    }

    __u16 sport = 0, dport = 0;
    if (l4proto == IPPROTO_TCP) {
        // conversion to tpc header
        struct tcphdr *th = l4hdr;
        if ((void *)(th + 1) > data_end) {
            return XDP_PASS;
        }

        sport = bpf_ntohs(th->source);
        dport = bpf_ntohs(th->dest);
    } else if (l4proto == IPPROTO_UDP) {
        // conversion to udp header
        struct udphdr *uh = l4hdr;
        if ((void *)(uh + 1) > data_end) {
            return XDP_PASS;
        }
        sport = bpf_ntohs(uh->source);
        dport = bpf_ntohs(uh->dest);
    } else {
        return XDP_PASS;
    }

    enum l7_proto l7 = l7_from_ports(l4proto, sport, dport);

    // only ipv4 tcp/udp is balanced
    if (l7 != L7_UNKNOWN) {
        struct flow_key client_fk = flow_key_of(iph->saddr, sport, l4proto);
 
        return balance(eth, iph, l4hdr, data_end, &client_fk, l7);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
