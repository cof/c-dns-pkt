/*
 * dns-inpect : DNS packet sniffer
 * Usage:     : ./dns-inspect --help
 * Example    : ./dns-inpsect capture --interface eth0
 *
 * Overview
 * --------
 * Implements a DNS message packet sniffer on a network interface.
 * Basicaly attachs to a network interface and validates DNS messages.
 *
 * Type:
 * -----
 * raw  : AF_PACKET + SOCK_RAW + cBPF + recvmmsg()
 * mmap : AF_PACKET + SOCK_RAW + cBPF + PACKET_RX_RING (TPACKET_V3)
 * xdp  : AF_XDP + eBPF + UMEM (RX + Fill Rings)
 *
 * Notes
 * -----
 * - cBPF is a classic BPF
 * - eBPF is extended BFP
 * - Uses DNS code api to decode/validate/print DNS messages
 * - Uses PCAP api to read/write/trace pcap files
 */
#include <stdbool.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/if_xdp.h>
#include <linux/bpf.h>
#include <netinet/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <poll.h>
#include <errno.h>

#include "util.h"
#include "log.h"
#include "pcap.h"
#include "dns_proto.h"

#define SNIFF_LOGLEVEL LOG_INFO

// supported cmds
#define MODE_NONE      0
#define MODE_CAPTURE   1
#define MODE_READPCAP  2
#define MODE_TRACEPCAP 3

// capture types
#define TYPE_RAW  1  // AF_PACKET + recvmmsg
#define TYPE_MMAP 2  // PACKET_MMAP
#define TYPE_XDP  3  // XDP

// Packet size limits
#define PKT_MAXSIZE 2048 // max packet size (aka snaplen)
#define PKT_NUMSLOT 4096 // max packet slots
#define PKT_MAXRECV 10
#define PKT_MIN_LEN (14 + 20 + 8)

#define RCVBUF_SIZE (2 * 1024 * 1024)
#define MAX_EVENTS 10

#define IS_POW2(n) ((n) && ((n) & ((n) - 1)) == 0)

struct membuf {
    void *mem;
    size_t len;
};

struct xsk_ring {
    struct membuf buf;
    uint32_t *producer;  // ptr to shared producer index
    uint32_t *consumer;  // ptr to shared consumer index
    void *descs;         // ptr to descriptor array 
    uint32_t max_size;
    uint32_t num_slot;
    uint32_t mask;
};

// inspect state
struct dns_sniff {
    // config
    struct simple_sig sig;
    pid_t pid;
    // state
    struct cmd_mode *cmd;
    int type;
    char *filename;
    struct pcap_file *pcap;
    char dev_name[IFNAMSIZ]; 
    int dev_index;
    int sock_fd; // AF_PACKET/AF_XDP
    int bpf_fd;  // BPF_PROG_LOAD
    int map_fd;  // BPF_MAP_CREATE
    struct membuf umem;
    struct xsk_ring fill_ring;
    struct xsk_ring rx_ring;
    uint8_t *bd_ptr;
    uint8_t *bd_end;
    union {
        struct tpacket_req3 req;
        struct xdp_umem_reg reg;
    };
    unsigned int use_pcapng : 1; // use pcapng output fmt
    // packet counters
    uint64_t rcv_pkts;
    uint64_t dns_pkts;
    uint64_t dns_okay;
    uint64_t dns_fail;
    // validate emsg
    char emsg[DNS_EMSG_MAXLEN];
    // packet read buffers
    struct mmsghdr msgs[PKT_MAXRECV];
    struct iovec   vecs[PKT_MAXRECV];
    uint8_t        bufs[PKT_MAXRECV][PKT_MAXSIZE];
};

// cBPF : tcpdump -i any udp port 53 -dd
static struct sock_filter dns_filter[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00000035 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00000035 },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000035 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000035 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

// eBPF - make gen-bpf - build/bpf_filter.h
static uint64_t bpf_filter[] = {
    0x0000000000041361ULL, // [00]ldxw %r3,[%r1+4] 
    0x0000000000001061ULL, // [01]ldxw %r0,[%r1+0] 
    0x00000000000002bfULL, // [02]mov %r2,%r0 
    0x0000000e00000207ULL, // [03]add %r2,0xe 
    0x00000000000623adULL, // [04]jlt %r3,%r2,6 
    0x00000000000d0571ULL, // [05]ldxb %r5,[%r0+0xd] 
    0x0000000800000567ULL, // [06]lsh %r5,8 
    0x00000000000c0471ULL, // [07]ldxb %r4,[%r0+0xc] 
    0x000000000000454fULL, // [08]or %r5,%r4 
    0x0000000800170516ULL, // [09]jeq32 %r5,8,23 
    0x0000dd8600020516ULL, // [10]jeq32 %r5,0xdd86,2 
    0x00000002000000b7ULL, // [11]mov %r0,2 
    0x0000000000000095ULL, // [12]exit 
    0x00000000000002bfULL, // [13]mov %r2,%r0 
    0x0000003600000207ULL, // [14]add %r2,0x36 
    0x00000000fffb322dULL, // [15]jgt %r2,%r3,-5 
    0x0000000000140071ULL, // [16]ldxb %r0,[%r0+0x14] 
    0x00000011fff90055ULL, // [17]jne %r0,0x11,-7 
    0x00000000000020bfULL, // [18]mov %r0,%r2 
    0x0000000800000007ULL, // [19]add %r0,8 
    0x00000000fff603adULL, // [20]jlt %r3,%r0,-10 
    0x0000000000022369ULL, // [21]ldxh %r3,[%r2+2] 
    0x0000350000020315ULL, // [22]jeq %r3,0x3500,2 
    0x0000000000002269ULL, // [23]ldxh %r2,[%r2+0] 
    0x00003500fff20255ULL, // [24]jne %r2,0x3500,-14 
    0x00000000000003b7ULL, // [25]mov %r3,0 
    0x0000000000101261ULL, // [26]ldxw %r2,[%r1+0x10] 
    0x0000000000000118ULL, // [27] <--- MAP_RELOC lddw %r1,0 
    0x0000000000000000ULL, // [28]
    0x0000003300000085ULL, // [29]call 51 
    0x0000002000000067ULL, // [30]lsh %r0,0x20 
    0x00000020000000c7ULL, // [31]arsh %r0,0x20 
    0x0000000000000095ULL, // [32]exit 
    0x00000000000005bfULL, // [33]mov %r5,%r0 
    0x0000002200000507ULL, // [34]add %r5,0x22 
    0x00000000ffe753adULL, // [35]jlt %r3,%r5,-25 
    0x0000000000170471ULL, // [36]ldxb %r4,[%r0+0x17] 
    0x00000011ffe50455ULL, // [37]jne %r4,0x11,-27 
    0x00000000000e0461ULL, // [38]ldxw %r4,[%r0+0xe] 
    0x0000000f00000457ULL, // [39]and %r4,0xf 
    0x0000000200000467ULL, // [40]lsh %r4,2 
    0x0000000e00000407ULL, // [41]add %r4,0xe 
    0x000000000000400fULL, // [42]add %r0,%r4 
    0x00000000000002bfULL, // [43]mov %r2,%r0 
    0x00000000ffe50005ULL, // [44]ja -27 
};

static inline void membuf_init(struct membuf *buf, void *mem, size_t len)
{
    buf->mem = mem;
    buf->len = len;
}

static void membuf_deinit(struct membuf *buf)
{
    if (buf->mem) {
        munmap(buf->mem, buf->len);
        buf->mem = NULL;
    }
}

static int str_totype(const char *str)
{
    if (!strcasecmp(str, "raw"))  return TYPE_RAW;
    if (!strcasecmp(str, "mmap")) return TYPE_MMAP;
    if (!strcasecmp(str, "xdp"))  return TYPE_XDP;

    return 0;
}

static inline bool is_vlan(uint16_t type)
{
    switch(type) {
    case 0x8100:
    case 0x88a8:
    case 0x9100:
    case 0x9200:
    case 0x9300:
        return true;
    default:
        return false;
    }
}

static inline uint16_t u16_dec(const void *buf)
{
    const uint8_t *ptr = buf;
    return (ptr[0] << 8) | ptr[1];
}

static int sniff_process_pkt(struct dns_sniff *sniff, void *pkt, size_t plen)
{
    uint8_t *ptr = pkt;
    uint8_t *end = ptr + plen;

    sniff->rcv_pkts++;

    // Ethernet layer
    if (ptr + 14 > end) return 0;
    uint16_t type = u16_dec(ptr + 12);
    ptr += 14;
    while (is_vlan(type)) {
        if (ptr + 4 > end) return 0;
        type = dec_u16(ptr + 2);
        ptr += 4;
    }

    // IP layer
    int hdr_len = 0;
    int proto = 0;
    if (type == ETH_P_IP) {
        if (ptr + sizeof(struct iphdr) > end) return 0;
        struct iphdr *ip = (void *) ptr;
        if (ip->version != 4) return 0;
        hdr_len = ip->ihl * 4;
        proto = ip->protocol;
    }
    else if (type == ETH_P_IPV6) {
        if (ptr + sizeof(struct ipv6hdr) > end) return 0;
        struct ipv6hdr *ip6 = (void *) ptr;
        if (ip6->version != 6) return 0;
        proto = ip6->nexthdr;
        hdr_len = 40;
    }
    else {
        // unknown type
        return 0;
    }
    ptr += hdr_len;  
    if (proto != IPPROTO_UDP) return 0;

    // UDP layer
    if (ptr + sizeof(struct udphdr) > end) return 0;
    struct udphdr *udp = (void *) ptr;
    ptr += sizeof(*udp);
    uint16_t src_port = u16_dec(&udp->source);
    uint16_t dst_port = u16_dec(&udp->dest);
    if (src_port != 53 && dst_port != 53) return 0;

    // call into api
    sniff->dns_pkts++;
    int rc = dns_validate(ptr, end - ptr, sniff->emsg, sizeof(sniff->emsg));
    int is_error = (rc < 0);
    sniff->dns_okay += !is_error;
    sniff->dns_fail += is_error;

    fputs(sniff->emsg, stderr);

    // all done
    return rc;
}

static int sniff_process_msg(struct dns_sniff *sniff, struct mmsghdr *msg)
{
    uint8_t *pkt_data = msg->msg_hdr.msg_iov->iov_base;
    uint32_t pkt_len = msg->msg_len;

    if (sniff->pcap) {
        pcap_write(sniff->pcap, pkt_data, pkt_len);
    }

    sniff_process_pkt(sniff, pkt_data, pkt_len);

    return 0;
}


/* type:RAW code */

static int sniff_raw(struct dns_sniff *sniff)
{
    log_debug("Starting capture %s", sniff->dev_name);

    while (sniff->sig.run) {
        // read a block
        int nr = recvmmsg(sniff->sock_fd, sniff->msgs, PKT_MAXRECV, MSG_WAITFORONE, NULL);
        if (nr < 0) {
            if (errno == EINTR) continue;
            return log_errno_rf("recvmmsg fd %d on dev %s failed", sniff->sock_fd, sniff->dev_name);
        }
        for (int i = 0; i < nr; i++) {
            int rc = sniff_process_msg(sniff, &sniff->msgs[i]);
            if (rc) return rc;
        }
    }

    if (sniff->sig.signo) {
        log_msg("\n");
        log_info("dns-sniff", 
            "PID:%d shutting down: got signal %d (%s) from UID:%d PID:%d ",
            sniff->pid,
            sniff->sig.signo, strsignal(sniff->sig.signo), 
            sniff->sig.uid, sniff->sig.pid);
    }

    return 0;
}

int setup_raw(struct dns_sniff *sniff)
{
    log_debug("Seting up %s", sniff->dev_name);

    // setup buffers
    for (int i = 0; i < PKT_MAXRECV; i++) {
        sniff->vecs[i].iov_base = sniff->bufs[i];
        sniff->vecs[i].iov_len  = sizeof(sniff->bufs[i]);
        sniff->msgs[i].msg_hdr.msg_iov  = &sniff->vecs[i];
        sniff->msgs[i].msg_hdr.msg_iovlen  = 1;
    }

    // socket
    sniff->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sniff->sock_fd == -1) return log_errno_rf("open AF_PACKET");

    // bind to interface - kernel will start sending us pkts
    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = sniff->dev_index,
        .sll_protocol = htons(ETH_P_ALL)
    };
    int rc = bind(sniff->sock_fd, (struct sockaddr *) &sll, sizeof(sll));
    if (rc) return log_errno_rf("bind to %s failed", sniff->dev_name);

    // attach DNS filter
    struct sock_fprog bpf = {
        .len =   sizeof(dns_filter) / sizeof(struct sock_filter),
        .filter = dns_filter
    };
    rc = setsockopt(sniff->sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (rc) return log_errno_rf("Attach DNS filter to %s failed", sniff->dev_name);

    // set receive buffer size
    int size = RCVBUF_SIZE;
    rc = setsockopt(sniff->sock_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if (rc) log_errno_rf("Set RCVBUF size %d failed", size);

    // promisc mode
    struct packet_mreq mreq = {
        .mr_ifindex = sniff->dev_index,
        .mr_type    = PACKET_MR_PROMISC
    };
    rc = setsockopt(sniff->sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (rc < 0) return log_errno_rf("setsockopt PACKET_MR_PROMISC");

    log_info("dns-sniff", "DNS active on %s", sniff->dev_name);

    // all done
    return 0;
}

/* type:MMAP code */

static int sniff_mmap(struct dns_sniff *sniff)
{
    log_debug("Starting capture %s", sniff->dev_name);

    sniff->bd_ptr = sniff->umem.mem;
    sniff->bd_end = sniff->bd_ptr + sniff->umem.len;

    struct pollfd pfd = { .fd = sniff->sock_fd, .events = POLLIN };

    while (sniff->sig.run) {

        struct tpacket_block_desc *bd = mkptr(sniff->bd_ptr, 0);
        if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) {
            // wait for kernel to fill block
            int rc = poll(&pfd, 1, -1); 
            if (rc <= 0) {
                if (rc == 0 || errno == EINTR) continue;
                log_errno("poll %d failed", sniff->sock_fd);
                break;
            }
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                int ec = 0;
                socklen_t eclen = sizeof(ec);
                rc = getsockopt(sniff->sock_fd, SOL_SOCKET, SO_ERROR, &ec, &eclen);
                if (rc) ec = errno;
                log_ec(ec, "fd %d socket error", sniff->sock_fd);
                break;
            }
            // must be POLLIN
            continue;
        }
        
        // jump to first pkt in block
        struct tpacket3_hdr *hdr = mkptr(bd, bd->hdr.bh1.offset_to_first_pkt);
        for (size_t i = 0; i <  bd->hdr.bh1.num_pkts; i++) {
            uint8_t *pkt = mkptr(hdr, hdr->tp_mac);
            sniff_process_pkt(sniff, pkt, hdr->tp_len);
            hdr = mkptr(hdr, hdr->tp_next_offset);
        }

        // release block back to kernel
        bd->hdr.bh1.block_status = TP_STATUS_KERNEL;

        // next block
        sniff->bd_ptr += sniff->req.tp_block_size;
        if (sniff->bd_ptr >= sniff->bd_end) {
            sniff->bd_ptr = sniff->umem.mem;
        }
    }

    return 0;
}

static int setup_mmap(struct dns_sniff *sniff)
{
    log_debug("Setting up %s", sniff->dev_name);

    // create raw socket
    sniff->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sniff->sock_fd == -1) return log_errno_rf("open AF_PACKET");

    // bind to interface
    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = sniff->dev_index,
        .sll_protocol = htons(ETH_P_ALL)
    };
    int rc = bind(sniff->sock_fd, (struct sockaddr *) &sll, sizeof(sll));
    if (rc) return log_errno_rf("bind to %s failed", sniff->dev_name);

    // attach DNS filter
    struct sock_fprog bpf = {
        .len =   sizeof(dns_filter) / sizeof(struct sock_filter),
        .filter = dns_filter
    };
    rc = setsockopt(sniff->sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (rc) return log_errno_rf("Attach DNS filter to %s failed", sniff->dev_name);

    // init tpacket request
    struct tpacket_req3 *req = &sniff->req;
    req->tp_block_size = 4096 * 128; // Must be power of 2 and page-aligned (e.g., 512KB)
    req->tp_block_nr = 100;          // number of blocks in ring
    req->tp_frame_size = PKT_MAXSIZE;
    req->tp_frame_nr = (req->tp_block_size * req->tp_block_nr) / req->tp_frame_size;
    req->tp_retire_blk_tov = 60;  // 60ms timeout to prevent "stuck" packets

    // setup TPACKET_V3
    int ver = TPACKET_V3;
    rc = setsockopt(sniff->sock_fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
    if (rc) return log_errno_rf("set PACKET_VERSION failed");

    // ask kernel to allocate ring buffer
    rc = setsockopt(sniff->sock_fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));
    if (rc) return log_errno_rf("set PACKET_RX_RING failed");

    // map ring buffer to userspace
    size_t ring_len = req->tp_block_size * req->tp_block_nr;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED;
    void *ring_mem = mmap(NULL, ring_len, prot, flags, sniff->sock_fd, 0);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap ring failed");
    membuf_init(&sniff->umem, ring_mem, ring_len);

    log_info("dns-sniff", "DNS active on %s", sniff->dev_name);

    return 0;
}

/* type:XDP code */

static int xsk_map_create(int maxq)
{
    union bpf_attr attr = {
        .map_type    = BPF_MAP_TYPE_XSKMAP,
        .key_size    = sizeof(int),   // queue ID
        .value_size  = sizeof(int),   // socket FD 
        .max_entries = maxq          // NIC queues
    };

    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int xsk_map_update(int map_fd, int qid, int xsk_fd)
{
    union bpf_attr attr = {
        .map_fd = map_fd,
        .key    = (uintptr_t) &qid,
        .value  = (uintptr_t) &xsk_fd,
        .flags  = BPF_ANY  // create or update entry
    };

    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

// look for 
static bool bpf_patch_map(int map_fd, size_t len, uint64_t bpf[static len])
{
    bool patched = false;

    for (size_t i = 0; i < len; i++) {
        // look for lddw instruction  (opcode 0x18)
        uint64_t insn = bpf[i];
        if ((insn & 0xff) != 0x18) continue;
        // set src_reg=1, clear val, set val
        insn |= (1ULL << 12);
        insn &= 0x00000000FFFFFFFFULL;
        insn |= ((uint64_t) map_fd << 32);
        bpf[i] = insn;
        i++;
        patched = true;
    }

    return patched;
}

// attach BPF fd to device
static int bpf_attach_dev(int bpf_fd, int dev_index) 
{
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd < 0) return -1;

    struct {
        struct nlmsghdr  n;
        struct ifinfomsg i;
        char             buf[64]; 
    } req = {
        .n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .n.nlmsg_type  = RTM_SETLINK,
        .i.ifi_family  = AF_UNSPEC,
        .i.ifi_index   = dev_index,
    };

    // attr: XDP Nested
    struct rtattr *rta = mkptr(&req, NLMSG_ALIGN(req.n.nlmsg_len));
    rta->rta_type = IFLA_XDP | NLA_F_NESTED;

    // sub-attr: FD
    struct rtattr *sub = mkptr(rta, NLA_HDRLEN);
    sub->rta_type = IFLA_XDP_FD;
    sub->rta_len = NLA_HDRLEN + sizeof(int);
    memcpy(RTA_DATA(sub), &bpf_fd, sizeof(int));
    
    // Sub-attribute: Flags (Generic/SKB mode for maximum compatibility)
    struct rtattr *flg = mkptr(sub, sub->rta_len);
    flg->rta_type = IFLA_XDP_FLAGS;
    flg->rta_len = NLA_HDRLEN + sizeof(uint32_t);
    uint32_t flags = XDP_FLAGS_SKB_MODE; 
    memcpy(RTA_DATA(flg), &flags, sizeof(flags));

    // Fix up lengths for nested structure
    rta->rta_len = (char *)flg + flg->rta_len - (char *)rta;
    req.n.nlmsg_len = (char *)rta + rta->rta_len - (char *)&req;

    // send msg via netlink
    int rc = send(sock_fd, &req, req.n.nlmsg_len, 0);
    int _errno = errno;
    close(sock_fd);
    errno = _errno;

    return rc;
}


static void ring_init(struct xsk_ring *ring, 
    void *mem, size_t len, 
    size_t num_slot, size_t max_size,
    struct xdp_ring_offset *offset)
{
    membuf_init(&ring->buf, mem, len);

    ring->producer = mkptr(mem, offset->producer);
    ring->consumer = mkptr(mem, offset->consumer);
    ring->descs    = mkptr(mem, offset->desc);
    ring->max_size = max_size;
    ring->num_slot = num_slot;
    ring->mask     = num_slot - 1;
}

static void ring_deinit(struct xsk_ring *ring)
{
    membuf_deinit(&ring->buf);
}

static void xsk_ring_fill(struct xsk_ring *ring)
{
    uint64_t offset = 0;
    uint32_t idx = 0;

    for (size_t i = 0; i < ring->num_slot; i++) {
        uint64_t *slot = (uint64_t *) ring->descs + (idx & ring->mask);
        *slot = offset;
        offset += ring->max_size;
        idx++;
    }

    // mem barrier : ensure offsets are written before kernel see them
    __sync_synchronize();

    // tell kernel it can fill slots up to idx
    *ring->producer = idx;
}

static int sniff_xdp(struct dns_sniff *sniff)
{
    log_debug("Starting capture %s", sniff->dev_name);

    struct membuf *umem = &sniff->umem;
    struct xsk_ring *fill = &sniff->fill_ring;
    struct xsk_ring *rx   = &sniff->rx_ring;
    xsk_ring_fill(fill);

    //recvfrom(sniff->sock_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    //sendto(sniff->sock_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);

    struct pollfd pfd = { .fd = sniff->sock_fd, .events = POLLIN };

    while (sniff->sig.run) {
        // wait for pkt
        int rc = poll(&pfd, 1, -1);
        if (rc <= 0) {
            if (rc == 0 || errno == EINTR) continue;
            log_errno("poll %d failed", sniff->sock_fd);
            break;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            int ec = 0;
            socklen_t eclen = sizeof(ec);
            rc = getsockopt(sniff->sock_fd, SOL_SOCKET, SO_ERROR, &ec, &eclen);
            if (rc) ec = errno;
            log_ec(ec, "fd %d socket error", sniff->sock_fd);
            break;
        }
        if (!(pfd.revents & POLLIN)) continue;

        uint32_t rx_ridx = *rx->consumer;
        uint32_t rx_widx = *rx->producer;
        uint32_t fill_idx = *fill->producer;

        while (rx_ridx != rx_widx) {
            // get addr
            struct xdp_desc *desc = (struct xdp_desc *) rx->descs + (rx_ridx & rx->mask);
            uint8_t *pkt = mkptr(umem->mem, desc->addr);
            sniff_process_pkt(sniff, pkt, desc->len);
            // refill addr
            uint64_t *slot = (uint64_t *) fill->descs + (fill_idx & fill->mask);
            *slot = desc->addr;
            // next pkt
            fill_idx++;
            rx_ridx++;
        }
        __sync_synchronize();
        *fill->producer = fill_idx;
        *rx->consumer = rx_ridx;
    }

    return 0;
}

static int setup_xdp(struct dns_sniff *sniff)
{
    log_debug("Setting up %s", sniff->dev_name);

    // allocate UMEM buffer to store packets
    size_t ring_len = PKT_NUMSLOT * PKT_MAXSIZE;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    off_t offset = 0;
    void *ring_mem = mmap(NULL, ring_len, prot, flags, -1, offset);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap UMEM failed");
    membuf_init(&sniff->umem, ring_mem, ring_len);

    // create XDP socket
    sniff->sock_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (sniff->sock_fd == -1) return log_errno_rf("open AF_XDP");

    // register UMEM with kernel
    struct xdp_umem_reg *reg = &sniff->reg;
    reg->addr = (uintptr_t) sniff->umem.mem;
    reg->len = sniff->umem.len;
    reg->chunk_size = PKT_MAXSIZE;
    int rc = setsockopt(sniff->sock_fd, SOL_XDP, XDP_UMEM_REG, reg, sizeof(*reg));
    if (rc) return log_errno_rf("set XDP_UMEM_REG failed");

    // create kernel space control rings
    uint32_t nslot = PKT_NUMSLOT;
    rc = setsockopt(sniff->sock_fd, SOL_XDP, XDP_UMEM_FILL_RING, &nslot, sizeof(nslot));
    if (rc) return log_errno_rf("set XDP_UMEM_FILL_RING failed");
    nslot = PKT_NUMSLOT;
    rc = setsockopt(sniff->sock_fd, SOL_XDP, XDP_RX_RING, &nslot, sizeof(nslot));
    if (rc) return log_errno_rf("set XDP_RX_RING failed");
    nslot = PKT_NUMSLOT;
    rc = setsockopt(sniff->sock_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &nslot, sizeof(nslot));
    if (rc) return log_errno_rf("set XDP_UMEM_COMPLETION_RING failed");

    // get control ring offsets
    struct xdp_mmap_offsets xdp_off;
    socklen_t optlen = sizeof(xdp_off);
    rc = getsockopt(sniff->sock_fd, SOL_XDP, XDP_MMAP_OFFSETS, &xdp_off, &optlen);
    if (rc) return log_errno_rf("get XDP_MMAP_OFFSETS failed");

    // map fill-ring into userspace
    ring_len = xdp_off.fr.desc + PKT_NUMSLOT * sizeof(uint64_t);
    prot = PROT_READ | PROT_WRITE;
    flags = MAP_SHARED;
    offset = XDP_UMEM_PGOFF_FILL_RING;
    ring_mem = mmap(NULL, ring_len, prot, flags, sniff->sock_fd, offset);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap fill-ring failed");
    ring_init(&sniff->fill_ring, ring_mem, ring_len, PKT_NUMSLOT, PKT_MAXSIZE, &xdp_off.fr);

    // map rx-ring into userspace
    ring_len = xdp_off.rx.desc + PKT_NUMSLOT * sizeof(struct xdp_desc);
    prot = PROT_READ | PROT_WRITE;
    flags = MAP_SHARED;
    offset = XDP_PGOFF_RX_RING;
    ring_mem = mmap(NULL, ring_len, prot, flags, sniff->sock_fd, offset);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap rx-ring failed");
    ring_init(&sniff->rx_ring, ring_mem, ring_len, PKT_NUMSLOT, PKT_MAXSIZE, &xdp_off.rx);

    // create map
    sniff->map_fd = xsk_map_create(1);
    if (sniff->map_fd == -1) return log_errno_rf("map_create failed");
    if (!bpf_patch_map(sniff->map_fd, ARR_LEN(bpf_filter), bpf_filter)) {
        return log_error_rf("patch_map %d failed", sniff->map_fd);
    }

    // load eBPF program
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .insns = (uintptr_t) bpf_filter,
        .insn_cnt = ARR_LEN(bpf_filter),
        .license = (uintptr_t) "Proprietary",
        .log_buf = (uintptr_t) sniff->emsg,
        .log_size = sizeof(sniff->emsg),
        .log_level = 1
    };
    sniff->bpf_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (sniff->bpf_fd == -1) {
        log_errno("BPF_PROG_LOAD failed");
        log_error("Verifier Log: %s", sniff->emsg);
        return -1;
    }

    // attach bpf prog to device
    rc = bpf_attach_dev(sniff->bpf_fd, sniff->dev_index);
    if (rc < 0) return log_errno_rf("attach eBPF to %s failed", sniff->dev_name);

    // bind xsd to device
    struct sockaddr_xdp sxdp = {
        .sxdp_family   = AF_XDP,
        .sxdp_ifindex  = sniff->dev_index,
        .sxdp_queue_id = 0,
        .sxdp_flags    = XDP_COPY
    };
    rc = bind(sniff->sock_fd, (struct sockaddr *) &sxdp, sizeof(sxdp));
    if (rc) return log_errno_rf("bind to %s failed", sniff->dev_name);

    rc = xsk_map_update(sniff->map_fd, 0, sniff->sock_fd);
    if (rc) return log_errno_rf("map-update %d %d failed", 0, sniff->sock_fd);

    log_info("dns-sniff", "DNS active on %s", sniff->dev_name);

    // all done
    return 0;
}

// run capture cmd
static int run_capture(struct dns_sniff *sniff)
{
    int rc;

    switch(sniff->type) {
    case TYPE_RAW:  rc = sniff_raw(sniff); break;
    case TYPE_MMAP: rc = sniff_mmap(sniff); break;
    case TYPE_XDP:  rc = sniff_xdp(sniff); break;
    default: rc = -1;
    }

    return rc;
}

// run tracepcap cmd
static int run_tracepcap(struct dns_sniff *sniff)
{
    size_t pkt_len;

    // select a buffer
    uint8_t *buf = sniff->bufs[0];
    uint32_t buf_len = sizeof(sniff->bufs[0]);

    while ((pkt_len = pcap_read(sniff->pcap, buf, buf_len)) > 0) {
        // do nothing
    }

    return 0;
}

// run readpcap cmd
static int run_readpcap(struct dns_sniff *sniff)
{
    size_t pkt_len;

    // select a buffer
    uint8_t *buf = sniff->bufs[0];
    uint32_t buf_len = sizeof(sniff->bufs[0]);

    while ((pkt_len = pcap_read(sniff->pcap, buf, buf_len)) > 0) {
        int rc = sniff_process_pkt(sniff, buf, pkt_len);
        if (rc) return rc;
    }

    return 0;
}

/*
 * cmd-line options
 *
 */
enum { opt_ifname, opt_type, opt_fname, opt_pcapng, opt_loglevel };

static struct cmd_opt capt_opts[] = {
    { "--interface", "Name of interface to sniff DNS msgs", 0, 1, opt_ifname },
    { "--type",      "capture type raw|mmap|xdp", "raw", 1, opt_type },
    { "--file",      "Packet capture file", 0, 1, opt_fname },
    { "--pcapng",    "Use pcapng file fmt", 0, 0, opt_pcapng },
    { "--log-level", "logging level", STR(LOG_LEVEL), 1, opt_loglevel  },
    { NULL } 
};

static struct cmd_opt pcap_opts[] = {
    { "--file", "Name of packet capture file", 0, 1, opt_fname },
    { NULL } 
};

static const char *examples[] = {
    "capture --interface eth0",
    "capture --interface eth0 --file dns.pcap",
    "capture --interface eth0 --file dns.pcapng --pcapng",
    "readpcap --file dns.pcap",
    "tracepcap --file dns.pcap",
    NULL
};

static int set_interface(struct dns_sniff *sniff, struct cmd_argv *parse)
{
    const char *dev_name = parse->value;
    size_t len = strlen(dev_name);

    if (len >= sizeof(sniff->dev_name)) {
       return log_error_rf("%s bigger than max %zu", parse->name, sizeof(sniff->dev_name) - 1);
    }

    memcpy(sniff->dev_name, dev_name, len);
    sniff->dev_name[len] = '\0';

    sniff->dev_index = if_nametoindex(sniff->dev_name);
    if (sniff->dev_index == 0) {
        return log_errno_rf("if_nametoindex for %s failed", sniff->dev_name);
    }

    return 0;
}

static int set_type(struct dns_sniff *sniff, struct cmd_argv *parse)
{
    sniff->type = str_totype(parse->value);
    if (!sniff->type) {
        return log_cmd_err(sniff->cmd->name, parse->name, "Unknown type");
    }

    return 0;
}

struct cmd_mode cmds[] = {
    { MODE_RUN(run_capture),   MODE_CAPTURE,   capt_opts, "capture",  "capture DNS msgs from an interface" },
    { MODE_RUN(run_readpcap),  MODE_READPCAP,  pcap_opts, "readpcap", "Read DNS msgs from packet capture file" },
    { MODE_RUN(run_tracepcap), MODE_TRACEPCAP, pcap_opts, "tracepcap","trace a packet capture file"  },
   { NULL }
};


static int sniff_parse_argv(struct dns_sniff *sniff, int argc, char *argv[])
{
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        mode_usage(argv[0], cmds, examples);
        exit(0);
    }

    // get cmd
    char *mode = argv[1];
    sniff->cmd = cmd_mode_find(mode, cmds);
    if (!sniff->cmd) return log_error_rf("Unsupported mode %s", mode);

    // process cmd-line options
    int rc;
    struct cmd_argv parser = { argc, argv, sniff->cmd->opts, 2 } ;
    while ( (rc = cmd_argv_next(&parser)) >= 0) {
        switch(rc) {
        case opt_ifname:   rc = set_interface(sniff, &parser); break;
        case opt_type:     rc = set_type(sniff, &parser); break;
        case opt_fname:    rc = opt_setstr(&sniff->filename, &parser); break;
        case opt_loglevel: rc = opt_setint(&log_level, &parser); break;
        case opt_pcapng:   sniff->use_pcapng = 1; break;
        }
        if (rc < 0) break;
    }
    if (rc != OPT_EOF) return rc;

    // final checks
    switch(sniff->cmd->mode) {
    case MODE_CAPTURE:
        if (!*sniff->dev_name) return log_cmd_err(mode, capt_opts[0].name, "is required");
        break;
    case MODE_READPCAP:
    case MODE_TRACEPCAP:
        if (!sniff->filename) return log_cmd_err(mode, pcap_opts[0].name, "is required");
        break;
    }

    // all done
    return 0;
}

static int open_pcap(struct dns_sniff *sniff)
{
    uint32_t flags = 0;

    switch(sniff->cmd->mode) {
    case MODE_CAPTURE: flags |= PCAP_WRITE; break;
    case MODE_READPCAP: flags |= PCAP_READ; break;
    case MODE_TRACEPCAP: flags |= PCAP_READ | PCAP_TRACE; break;
    }
    if (sniff->use_pcapng) flags |= PCAP_FMTNG;

    sniff->pcap = pcap_open(sniff->filename, flags);
    if (!sniff->pcap) return -1;

    return 0;
}

static int sniff_init(struct dns_sniff *sniff)
{
    int rc;

    if (sniff->filename) {
        rc = open_pcap(sniff);
        if (rc) return rc;
    }

    switch(sniff->type) {
    case TYPE_RAW:  rc = setup_raw(sniff); break;
    case TYPE_MMAP: rc = setup_mmap(sniff); break;
    case TYPE_XDP:  rc = setup_xdp(sniff); break;
    default: rc = -1;
    }

    return rc;
}

// free state
static void sniff_free(struct dns_sniff *sniff)
{
    if (sniff->bpf_fd != -1) {
        bpf_attach_dev(-1, sniff->dev_index);
        close(sniff->bpf_fd);
    }
    if (sniff->map_fd != -1) close(sniff->map_fd);
    membuf_deinit(&sniff->umem);
    ring_deinit(&sniff->rx_ring);
    ring_deinit(&sniff->fill_ring);
    if (sniff->sock_fd != -1) close(sniff->sock_fd);
    if (sniff->pcap) pcap_close(sniff->pcap);
    if (sniff->filename) free(sniff->filename);

    free(sniff);
}

// create state
static struct dns_sniff *sniff_create(void)
{
    struct dns_sniff *sniff;

    sniff = malloc(sizeof(*sniff));
    if (!sniff) return log_errno_rn("malloc failed for state");

    memset(sniff, 0, sizeof(*sniff));
    sniff->sock_fd = -1;
    sniff->bpf_fd = -1;
    sniff->map_fd = -1;
    sniff->type = TYPE_RAW;

    return sniff;
}

int main(int argc, char *argv[])
{
    struct dns_sniff *sniff = NULL;
    int ec = 0;

    log_init(NULL, SNIFF_LOGLEVEL);
    if (!(sniff = sniff_create())) { ec = 1; goto done; }
    if (sniff_parse_argv(sniff, argc, argv)) { ec = 3;  goto done; }
    if (setup_signals(&sniff->sig)) { ec = 4; goto done; }
    if (sniff_init(sniff))   { ec = 5; goto done; }
    if (sniff->cmd->run(sniff)) { ec = 6; goto done; }

done:
    if (sniff) sniff_free(sniff);

    return ec;
}
