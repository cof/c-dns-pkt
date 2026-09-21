#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

// Fix for bpf-gcc pragma parsing bug
#undef SEC
#define SEC(name) __attribute__((section(name), used))


/* Define Map for XDP socket
 *
 * This is a raw/legacy BPF map definition struct read directly 
 * by our custom loader. This is NOT a libbpf/BTF map defintion.
 */
SEC(".maps")
struct {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
} xsk_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 64
};

SEC("xdp")
int dns_filter_dual_stack(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    struct udphdr *udp = NULL;

    if (h_proto == ETH_P_IP) {
        // IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_DROP;
        // check the header length
        if (ip->ihl < 5) return XDP_DROP;
        void *payload = (void *)ip + (ip->ihl * 4);
        if (payload > data_end) return XDP_DROP;
        if (ip->protocol == IPPROTO_UDP) {
            udp = payload;
        }
    }
    else if (h_proto == ETH_P_IPV6) {
        // IPv6
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        void *payload = (void *)(ipv6 + 1);
        if (payload > data_end) return XDP_DROP;
        if (ipv6->nexthdr == IPPROTO_UDP) {
            udp = payload;
        }
    }

    // check UDP port is 53 (DNS)
    if (udp && (void *)(udp + 1) <= data_end) {
        __u16 dns_port = bpf_htons(53);
        if (udp->dest == dns_port || udp->source == dns_port) {
            return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, 0);
        }
    }

    // drop everthing that not DNS
    return XDP_DROP;
}

SEC("license")
char _license[]  = "GPL";
