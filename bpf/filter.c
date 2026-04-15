#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#undef SEC
#define SEC(name) __attribute__((section(name), used))

// Define Map for XDP socket
SEC(".maps")
struct {
    int type; 
    int key_size;
    int val_size;
    int max_entry;
} xsk_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = 4,
    .val_size = 4,
    .max_entry = 64
};

SEC("xdp")
int dns_filter_dual_stack(struct xdp_md *ctx) 
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    __u16 h_proto = eth->h_proto;
    void *l4_header = NULL;

    // IPv4
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_DROP;
        if (ip->protocol == IPPROTO_UDP) {
            l4_header = (void *)ip + (ip->ihl * 4);
        }
    } 
    // IPv6
    else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end) return XDP_DROP;
        if (ipv6->nexthdr == IPPROTO_UDP) {
            l4_header = (void *)(ipv6 + 1);
        }
    }

    // check UDP port 53
    if (l4_header) {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end) return XDP_DROP;
        if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
            return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        }
    }

    return XDP_DROP;
}

SEC("license")
char _license[]  = "GPL";
