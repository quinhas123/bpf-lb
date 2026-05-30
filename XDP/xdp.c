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
#define MAX_CONNTRACK_ENTRIES 1024

// The test topology runs entirely on the loopback interface, so every address
// is in 127.0.0.0/8. IP(x) -> 127.0.0.x in network byte order (the constant is
// laid out little-endian, matching this VM and the bpfel target).
#define IP(x) (127 + (0 << 8) + (0 << 16) + (x << 24))
#define BACKEND_A 2
#define BACKEND_B 3

// The single virtual IP clients connect to (the loopback address the LB is
// attached to). Backend replies have their source restored to this so the
// client sees one consistent address.
#define VIP IP(1)

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

struct ct_entry {
    struct backend backend;                      // forward path
    struct backend original_destination_server;  // reverse path
};

// TODO: delete the entry on FIN/RST instead of relying on LRU eviction.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct ct_entry);
    __uint(max_entries, MAX_CONNTRACK_ENTRIES);
} conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct backend);
    __uint(max_entries, MAX_BACKENDS);
} backends SEC(".maps");

// TODO: consequences of PERCPU, even though its safer
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} rr_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} backend_count SEC(".maps");

enum l7_proto {
    L7_UNKNOWN = 0,
    L7_HTTP,
    L7_HTTPS,
    L7_DNS,
    L7_SSH,
    L7_QUIC,
    L7_SMTP,
    L7_FTP,
};

static __always_inline enum l7_proto l7_from_ports(__u8 l4, __u16 sport, __u16 dport) {
    // sort the two ports for symmetrical protocol identification in request and response
    __u16 p1 = sport < dport ? sport : dport;
    __u16 p2 = sport < dport ? dport : sport;

    if (l4 == IPPROTO_TCP) {
        if (p1 == 80   || p2 == 80)   return L7_HTTP;
        if (p1 == 8080 || p2 == 8080) return L7_HTTP;
        if (p1 == 443  || p2 == 443)  return L7_HTTPS;
        if (p1 == 22   || p2 == 22)   return L7_SSH;
        if (p1 == 25   || p2 == 25)   return L7_SMTP;
        if (p1 == 21   || p2 == 21)   return L7_FTP;
        if (p1 == 53   || p2 == 53)   return L7_DNS;
    } else if (l4 == IPPROTO_UDP) {
        if (p1 == 53  || p2 == 53)  return L7_DNS;
        if (p1 == 443 || p2 == 443) return L7_QUIC;
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

// constant VIP
static __always_inline int rewrite_to_client(struct ethhdr *eth, struct iphdr *iph,
                                              void *l4hdr, void *data_end,
                                              struct backend *original_destination_server) {
    // rearrange MAC addresses
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, original_destination_server->mac, ETH_ALEN);

    // src IP is LB IP
    __be32 old_saddr = iph->saddr;
    iph->saddr = original_destination_server->ip;
    iph->check = csum_replace32(iph->check, old_saddr, iph->saddr);

    // L4: the src IP is part of the TCP/UDP pseudo-header, so patch those too.
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4hdr;
        if ((void *)(th + 1) > data_end)
            return XDP_PASS;
        th->check = csum_replace32(th->check, old_saddr, iph->saddr);
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4hdr;
        if ((void *)(uh + 1) > data_end)
            return XDP_PASS;
        // A zero UDP checksum means "no checksum" in IPv4; leave it alone.
        if (uh->check) {
            __u16 c = csum_replace32(uh->check, old_saddr, iph->saddr);
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
                                         struct flow_key *fk) {
    __u32 zero = 0;

    __u32 *count = bpf_map_lookup_elem(&backend_count, &zero);
    if (!count || *count == 0)
        return XDP_PASS;

    __u32 slot = flow_hash(fk) % *count;

    struct backend *b = bpf_map_lookup_elem(&backends, &slot);
    if (!b)
        return XDP_PASS;

    struct ct_entry e = { .backend = *b };
    __builtin_memcpy(e.original_destination_server.mac, eth->h_source, ETH_ALEN);
    e.original_destination_server.ip = iph->daddr;
    // TODO: do not ignore return
    bpf_map_update_elem(&conntrack, fk, &e, BPF_ANY);

    return rewrite_to_backend(eth, iph, l4hdr, data_end, b);
}

static __always_inline int round_robin(struct ethhdr *eth, struct iphdr *iph,
                                        void *l4hdr, void *data_end,
                                        struct flow_key *fk) {
    __u32 zero = 0;

    __u32 *count = bpf_map_lookup_elem(&backend_count, &zero);
    if (!count || *count == 0)
        return XDP_PASS;

    __u32 *counter = bpf_map_lookup_elem(&rr_counter, &zero);
    if (!counter)
        return XDP_PASS;

    __u32 slot = *counter % *count;
    *counter += 1;

    struct backend *b = bpf_map_lookup_elem(&backends, &slot);
    if (!b)
        return XDP_PASS;
    
    struct ct_entry e = { .backend = *b };
    __builtin_memcpy(e.original_destination_server.mac, eth->h_source, ETH_ALEN);
    e.original_destination_server.ip = iph->daddr;
    // TODO: do not ignore return
    bpf_map_update_elem(&conntrack, fk, &e, BPF_ANY);

    return rewrite_to_backend(eth, iph, l4hdr, data_end, b);
}

static __always_inline int balance(struct ethhdr *eth, struct iphdr *iph,
                                    void *l4hdr, void *data_end,
                                    struct flow_key *fk, enum l7_proto l7) {
    switch (l7) {
    case L7_HTTPS:
        return hash_balance(eth, iph, l4hdr, data_end, fk);
    default:
        return round_robin(eth, iph, l4hdr, data_end, fk);
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
    } else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        // todo: remove ipv6 support
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        l4hdr = (void *)(ip6 + 1);
        l4proto = ip6->nexthdr;
    } else {
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
        bpf_printk("xdp ingress: l4=%u (no ports)", l4proto);
        return XDP_PASS;
    }

    enum l7_proto l7 = l7_from_ports(l4proto, sport, dport);

    bpf_printk("xdp ingress: l4=%u sport=%u dport=%u l7=%u",
               l4proto, sport, dport, l7);

    // TODO: move logic to TC_egress hook
    if (iph != NULL && (iph->saddr == IP(BACKEND_A) || iph->saddr == IP(BACKEND_B))) {
        struct flow_key client_fk = flow_key_of(iph->daddr, dport, l4proto);

        struct ct_entry *e = bpf_map_lookup_elem(&conntrack, &client_fk);
        if (e == NULL)
            return XDP_PASS;

        return rewrite_to_client(eth, iph, l4hdr, data_end, &e->original_destination_server);
    }

    // only ipv4 tcp/udp is balanced for now
    if (iph) {
        struct flow_key client_fk = flow_key_of(iph->saddr, sport, l4proto);

        struct ct_entry *e = bpf_map_lookup_elem(&conntrack, &client_fk);
        if (e == NULL) {
            return balance(eth, iph, l4hdr, data_end, &client_fk, l7);
        }

        return rewrite_to_backend(eth, iph, l4hdr, data_end, &e->backend);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
