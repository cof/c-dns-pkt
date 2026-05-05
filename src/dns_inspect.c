/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * dns-inspect : DNS packet inspector
 * Usage:      : ./dns-inspect --help
 * Example     : ./dns-inspect capture --interface eth0
 *
 * Overview
 * --------
 * Implements a DNS message packet inspector.
 * Can inspect packets read directly from a network interface or pcap file.
 *
 * Supports the following interface capture types:
 *
 * raw  : AF_PACKET, SOCK_RAW, cBPF and recvmmsg()
 * mmap : AF_PACKET, SOCK_RAW, cBPF and PACKET_RX_RING (TPACKET_V3)
 * xdp  : veth-tap, AF_XDP, eBPF, UMEM (fill/rx rings) and BPF map patching
 *
 * Notes
 * -----
 * - cBPF is a classic BPF
 * - eBPF is extended BFP
 * - Uses DNS-PROTO api to decode/validate/print DNS messages
 * - Uses PCAP api to read/write/trace pcap files
 * - make gen-bpf created eBPF filter
 * - make install uses setcap cap_net_raw,cap_net_admin,cap_bpf=eip
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

#define INSP_TAP "insp_tap"
#define INSP_PEER "insp_peer"

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

// app state
struct dns_insp {
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
    int tap_index;
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
    unsigned int use_tap    : 1; // use tap device
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

// eBPF : make gen-bpf - build/bpf_filter.h
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
    0x0000000800030516ULL, // [09]jeq32 %r5,8,3
    0x0000dd86001c0516ULL, // [10]jeq32 %r5,0xdd86,28
    0x00000001000000b7ULL, // [11]mov %r0,1
    0x0000000000000095ULL, // [12]exit
    0x00000000000005bfULL, // [13]mov %r5,%r0
    0x0000002200000507ULL, // [14]add %r5,0x22
    0x00000000fffb53adULL, // [15]jlt %r3,%r5,-5
    0x0000000000170471ULL, // [16]ldxb %r4,[%r0+0x17]
    0x00000011fff90455ULL, // [17]jne %r4,0x11,-7
    0x00000000000e0461ULL, // [18]ldxw %r4,[%r0+0xe]
    0x0000000f00000457ULL, // [19]and %r4,0xf
    0x0000000200000467ULL, // [20]lsh %r4,2
    0x0000000e00000407ULL, // [21]add %r4,0xe
    0x000000000000400fULL, // [22]add %r0,%r4
    0x00000000000002bfULL, // [23]mov %r2,%r0
    0x00000000000020bfULL, // [24]mov %r0,%r2
    0x0000000800000007ULL, // [25]add %r0,8
    0x00000000fff003adULL, // [26]jlt %r3,%r0,-16
    0x0000000000022369ULL, // [27]ldxh %r3,[%r2+2]
    0x0000350000020315ULL, // [28]jeq %r3,0x3500,2
    0x0000000000002269ULL, // [29]ldxh %r2,[%r2+0]
    0x00003500ffec0255ULL, // [30]jne %r2,0x3500,-20
    0x00000000000003b7ULL, // [31]mov %r3,0
    0x0000000000101261ULL, // [32]ldxw %r2,[%r1+0x10]
    0x0000000000000118ULL, // [33] <--- MAP_RELOC lddw %r1,0
    0x0000000000000000ULL, // [34]
    0x0000003300000085ULL, // [35]call 51
    0x0000002000000067ULL, // [36]lsh %r0,0x20
    0x00000020000000c7ULL, // [37]arsh %r0,0x20
    0x0000000000000095ULL, // [38]exit
    0x00000000000002bfULL, // [39]mov %r2,%r0
    0x0000003600000207ULL, // [40]add %r2,0x36
    0x00000000ffe1322dULL, // [41]jgt %r2,%r3,-31
    0x0000000000140071ULL, // [42]ldxb %r0,[%r0+0x14]
    0x00000011ffdf0055ULL, // [43]jne %r0,0x11,-33
    0x00000000ffeb0005ULL, // [44]ja -21
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

static int insp_process_pkt(struct dns_insp *insp, void *pkt, size_t plen)
{
    uint8_t *ptr = pkt;
    uint8_t *end = ptr + plen;

    insp->rcv_pkts++;

    // Ethernet layer
    if (ptr + 14 > end) return 0;
    uint16_t type = u16_dec(ptr + 12);
    ptr += 14;
    while (is_vlan(type)) {
        if (ptr + 4 > end) return 0;
        type = u16_dec(ptr + 2);
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

    // pass pkt to DNS api
    insp->dns_pkts++;
    int rc = dns_validate(ptr, end - ptr, insp->emsg, sizeof(insp->emsg));
    int is_error = (rc < 0);
    insp->dns_okay += !is_error;
    insp->dns_fail += is_error;

    fputs(insp->emsg, stderr);

    // all done
    return rc;
}

static int insp_process_msg(struct dns_insp *insp, struct mmsghdr *msg)
{
    uint8_t *pkt_data = msg->msg_hdr.msg_iov->iov_base;
    uint32_t pkt_len = msg->msg_len;

    if (insp->pcap) {
        pcap_write(insp->pcap, pkt_data, pkt_len);
    }

    insp_process_pkt(insp, pkt_data, pkt_len);

    return 0;
}

/* RAW capture code */

static int capture_raw(struct dns_insp *insp)
{
    log_debug("Starting capture %s", insp->dev_name);

    while (insp->sig.run) {
        // read a block
        int nr = recvmmsg(insp->sock_fd, insp->msgs, PKT_MAXRECV, MSG_WAITFORONE, NULL);
        if (nr < 0) {
            if (errno == EINTR) continue;
            return log_errno_rf("recvmmsg fd %d on dev %s failed", insp->sock_fd, insp->dev_name);
        }
        for (int i = 0; i < nr; i++) {
            int rc = insp_process_msg(insp, &insp->msgs[i]);
            if (rc) return rc;
        }
    }

    if (insp->sig.signo) {
        log_msg("\n");
        log_info("+",
            "PID:%d shutting down: got signal %d (%s) from UID:%d PID:%d ",
            insp->pid,
            insp->sig.signo, strsignal(insp->sig.signo),
            insp->sig.uid, insp->sig.pid);
    }

    return 0;
}

int setup_raw(struct dns_insp *insp)
{
    log_debug("Setting up %s", insp->dev_name);

    // setup buffers
    for (int i = 0; i < PKT_MAXRECV; i++) {
        insp->vecs[i].iov_base = insp->bufs[i];
        insp->vecs[i].iov_len  = sizeof(insp->bufs[i]);
        insp->msgs[i].msg_hdr.msg_iov  = &insp->vecs[i];
        insp->msgs[i].msg_hdr.msg_iovlen  = 1;
    }

    // socket
    insp->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (insp->sock_fd == -1) return log_errno_rf("open AF_PACKET");

    // bind to interface - kernel will start sending us pkts
    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = insp->dev_index,
        .sll_protocol = htons(ETH_P_ALL)
    };
    int rc = bind(insp->sock_fd, (struct sockaddr *) &sll, sizeof(sll));
    if (rc) return log_errno_rf("bind to %s failed", insp->dev_name);

    // attach DNS filter
    struct sock_fprog bpf = {
        .len =   sizeof(dns_filter) / sizeof(struct sock_filter),
        .filter = dns_filter
    };
    rc = setsockopt(insp->sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (rc) return log_errno_rf("Attach DNS filter to %s failed", insp->dev_name);

    // set receive buffer size
    int size = RCVBUF_SIZE;
    rc = setsockopt(insp->sock_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if (rc) log_errno_rf("Set RCVBUF size %d failed", size);

    // promisc mode
    struct packet_mreq mreq = {
        .mr_ifindex = insp->dev_index,
        .mr_type    = PACKET_MR_PROMISC
    };
    rc = setsockopt(insp->sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    if (rc < 0) return log_errno_rf("setsockopt PACKET_MR_PROMISC");

    log_info("+", "DNS active on %s", insp->dev_name);

    // all done
    return 0;
}

/* MMAP capture code */

static int capture_mmap(struct dns_insp *insp)
{
    log_debug("Starting capture %s", insp->dev_name);

    insp->bd_ptr = insp->umem.mem;
    insp->bd_end = insp->bd_ptr + insp->umem.len;

    struct pollfd pfd = { .fd = insp->sock_fd, .events = POLLIN };

    while (insp->sig.run) {

        struct tpacket_block_desc *bd = mkptr(insp->bd_ptr, 0);
        if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) {
            // wait for kernel to fill block
            int rc = poll(&pfd, 1, -1);
            if (rc <= 0) {
                if (rc == 0 || errno == EINTR) continue;
                log_errno("poll %d failed", insp->sock_fd);
                break;
            }
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                int ec = 0;
                socklen_t eclen = sizeof(ec);
                rc = getsockopt(insp->sock_fd, SOL_SOCKET, SO_ERROR, &ec, &eclen);
                if (rc) ec = errno;
                log_ec(ec, "fd %d socket error", insp->sock_fd);
                break;
            }
            // must be POLLIN
            continue;
        }

        // jump to first pkt in block
        struct tpacket3_hdr *hdr = mkptr(bd, bd->hdr.bh1.offset_to_first_pkt);
        for (size_t i = 0; i <  bd->hdr.bh1.num_pkts; i++) {
            uint8_t *pkt = mkptr(hdr, hdr->tp_mac);
            insp_process_pkt(insp, pkt, hdr->tp_len);
            hdr = mkptr(hdr, hdr->tp_next_offset);
        }

        // release block back to kernel
        bd->hdr.bh1.block_status = TP_STATUS_KERNEL;

        // next block
        insp->bd_ptr += insp->req.tp_block_size;
        if (insp->bd_ptr >= insp->bd_end) {
            insp->bd_ptr = insp->umem.mem;
        }
    }

    return 0;
}

static int setup_mmap(struct dns_insp *insp)
{
    log_debug("Setting up %s", insp->dev_name);

    // create raw socket
    insp->sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (insp->sock_fd == -1) return log_errno_rf("open AF_PACKET");

    // bind to interface
    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = insp->dev_index,
        .sll_protocol = htons(ETH_P_ALL)
    };
    int rc = bind(insp->sock_fd, (struct sockaddr *) &sll, sizeof(sll));
    if (rc) return log_errno_rf("bind to %s failed", insp->dev_name);

    // attach DNS filter
    struct sock_fprog bpf = {
        .len =   sizeof(dns_filter) / sizeof(struct sock_filter),
        .filter = dns_filter
    };
    rc = setsockopt(insp->sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (rc) return log_errno_rf("Attach DNS filter to %s failed", insp->dev_name);

    // init tpacket request
    struct tpacket_req3 *req = &insp->req;
    req->tp_block_size = 4096 * 128; // Must be power of 2 and page-aligned (e.g., 512KB)
    req->tp_block_nr = 100;          // number of blocks in ring
    req->tp_frame_size = PKT_MAXSIZE;
    req->tp_frame_nr = (req->tp_block_size * req->tp_block_nr) / req->tp_frame_size;
    req->tp_retire_blk_tov = 60;  // 60ms timeout to prevent "stuck" packets

    // setup TPACKET_V3
    int ver = TPACKET_V3;
    rc = setsockopt(insp->sock_fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
    if (rc) return log_errno_rf("set PACKET_VERSION failed");

    // ask kernel to allocate ring buffer
    rc = setsockopt(insp->sock_fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));
    if (rc) return log_errno_rf("set PACKET_RX_RING failed");

    // map ring buffer to userspace
    size_t ring_len = req->tp_block_size * req->tp_block_nr;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED;
    void *ring_mem = mmap(NULL, ring_len, prot, flags, insp->sock_fd, 0);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap ring failed");
    membuf_init(&insp->umem, ring_mem, ring_len);

    log_info("+", "DNS active on %s", insp->dev_name);

    return 0;
}

/* XDP capture code */

static int xdp_init_tap(struct dns_insp *insp)
{
    char tmp[512];
    struct sbuf sbuf;
    struct sbuf *buf = sbuf_init(&sbuf, tmp, sizeof(tmp));

    const char *real = insp->dev_name;
    const char *tap = INSP_TAP;
    const char *peer = INSP_PEER;

    int flags = RUN_CAPS | RUN_NULL;

    // create veth tap device
    int rc = run_cmd(buf, flags, "ip link add %s type veth peer name %s", tap, peer);
    if (rc && rc != 2) return rc;
    insp->use_tap = 1;

    insp->tap_index = if_nametoindex(tap);
    if (insp->tap_index == 0) return log_errno_rf("name_toindex %s failed", tap);

    if (run_cmd(buf, flags, "ip link set %s up", tap)) return -1;
    if (run_cmd(buf, flags, "ip link set %s up", peer)) return -1;

    // clear old tc rules
    run_cmd(buf, flags, "tc qdisc del dev %s ingress", real);
    run_cmd(buf, flags, "tc qdisc del dev %s root", real);

    // add ingress mirror
    if (run_cmd(buf, flags, "tc qdisc add dev %s handle ffff: ingress", real)) return -1;
    if (run_cmd(buf, flags, "tc filter add dev %s parent ffff: matchall action mirred egress mirror dev %s", real, peer)) return -1;

    // add egress mirror
    if (run_cmd(buf, flags, "tc qdisc add dev %s root handle 1: prio", real)) return -1;
    if (run_cmd(buf, flags, "tc filter add dev %s parent 1: matchall action mirred egress mirror dev %s", real, peer)) return -1;

    return 0;
}

static void xdp_deinit_tap(struct dns_insp *insp)
{
    char tmp[256];
    struct sbuf sbuf;
    struct sbuf *buf = sbuf_init(&sbuf, tmp, sizeof(tmp));

    const char *real = insp->dev_name;
    const char *tap = INSP_TAP;

    run_cmd(buf, 1, "ip link del %s", tap);
    run_cmd(buf, 1, "tc qdisc del dev %s ingress", real);
    run_cmd(buf, 1, "tc qdisc del dev %s root", real);
}

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

// patch bpf code with map fd
static bool bpf_patch_map(int map_fd, size_t len, uint64_t bpf[static len])
{
    bool patched = false;

    for (size_t i = 0; i < len; i++) {
        // look for lddw (opcode 0x18)
        uint64_t insn = bpf[i];
        if ((insn & 0xFF) != 0x18) continue;
        insn |= (1ULL << 12);
        insn &= 0x00000000FFFFFFFFULL;
        insn |= ((uint64_t) map_fd << 32);
        bpf[i] = insn;
        patched = true;
        // skip 2nd haft of lddw
        i++;
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
        char buf[64];
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

    // sub-attribute: set Generic XDP (SKB_MODE) for max compatibility
    struct rtattr *flg = mkptr(sub, sub->rta_len);
    flg->rta_type = IFLA_XDP_FLAGS;
    flg->rta_len = NLA_HDRLEN + sizeof(uint32_t);
    uint32_t flags = XDP_FLAGS_SKB_MODE;
    memcpy(RTA_DATA(flg), &flags, sizeof(flags));

    // fix up lengths for nested structure
    rta->rta_len    =  (char *) mkptr(flg, flg->rta_len) - (char *) rta;
    req.n.nlmsg_len =  (char *) mkptr(rta, rta->rta_len) - (char *) &req;

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

static int capture_xdp(struct dns_insp *insp)
{
    log_debug("Starting capture %s", insp->dev_name);

    struct membuf *umem = &insp->umem;
    struct xsk_ring *fill = &insp->fill_ring;
    struct xsk_ring *rx   = &insp->rx_ring;
    xsk_ring_fill(fill);

    struct pollfd pfd = { .fd = insp->sock_fd, .events = POLLIN };

    while (insp->sig.run) {
        // wait for pkt
        int rc = poll(&pfd, 1, -1);
        if (rc <= 0) {
            if (rc == 0 || errno == EINTR) continue;
            log_errno("poll %d failed", insp->sock_fd);
            break;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            int ec = 0;
            socklen_t eclen = sizeof(ec);
            rc = getsockopt(insp->sock_fd, SOL_SOCKET, SO_ERROR, &ec, &eclen);
            if (rc) ec = errno;
            log_ec(ec, "fd %d socket error", insp->sock_fd);
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
            insp_process_pkt(insp, pkt, desc->len);
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

/*
 * 13 steps
 * --------
 * 1  - create veth-tap interface
 * 2  - alloc UMEM buffer
 * 3  - create xsd socket (AF_XDP)
 * 4  - register UMEM
 * 5  - create control rings (fill/rx/completion)
 * 6  - get control ring info
 * 7  - mem map control rings to userspace (fill/rx)
 * 8  - create xsk map
 * 9  - patch eBPF code with map fd
 * 10 - load eBPF program into kernel
 * 11 - attach eBPF to device
 * 12 - bind xsd to tap device
 * 13 - update xsk map with xsd fd
 */
static int setup_xdp(struct dns_insp *insp)
{
    log_debug("Setting up %s", insp->dev_name);

    int rc = xdp_init_tap(insp);
    if (rc) return log_error_rf("init tap %s failed", INSP_TAP);

    // allocate UMEM buffer to store packets
    size_t ring_len = PKT_NUMSLOT * PKT_MAXSIZE;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    off_t offset = 0;
    void *ring_mem = mmap(NULL, ring_len, prot, flags, -1, offset);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap UMEM failed");
    membuf_init(&insp->umem, ring_mem, ring_len);

    // create XDP socket
    insp->sock_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (insp->sock_fd == -1) return log_errno_rf("open AF_XDP");

    // register UMEM with kernel
    struct xdp_umem_reg *reg = &insp->reg;
    reg->addr = (uintptr_t) insp->umem.mem;
    reg->len = insp->umem.len;
    reg->chunk_size = PKT_MAXSIZE;
    rc = setsockopt(insp->sock_fd, SOL_XDP, XDP_UMEM_REG, reg, sizeof(*reg));
    if (rc) return log_errno_rf("set XDP_UMEM_REG failed");

    // create kernel space control rings
    uint32_t nslot = PKT_NUMSLOT;
    rc = setsockopt(insp->sock_fd, SOL_XDP, XDP_UMEM_FILL_RING, &nslot, sizeof(nslot));
    if (rc) return log_errno_rf("set XDP_UMEM_FILL_RING failed");
    nslot = PKT_NUMSLOT;
    rc = setsockopt(insp->sock_fd, SOL_XDP, XDP_RX_RING, &nslot, sizeof(nslot));
    if (rc) return log_errno_rf("set XDP_RX_RING failed");
    nslot = PKT_NUMSLOT;
    rc = setsockopt(insp->sock_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &nslot, sizeof(nslot));
    if (rc) return log_errno_rf("set XDP_UMEM_COMPLETION_RING failed");

    // get control ring offsets
    struct xdp_mmap_offsets xdp_off;
    socklen_t optlen = sizeof(xdp_off);
    rc = getsockopt(insp->sock_fd, SOL_XDP, XDP_MMAP_OFFSETS, &xdp_off, &optlen);
    if (rc) return log_errno_rf("get XDP_MMAP_OFFSETS failed");

    // map fill-ring into userspace
    ring_len = xdp_off.fr.desc + PKT_NUMSLOT * sizeof(uint64_t);
    prot = PROT_READ | PROT_WRITE;
    flags = MAP_SHARED;
    offset = XDP_UMEM_PGOFF_FILL_RING;
    ring_mem = mmap(NULL, ring_len, prot, flags, insp->sock_fd, offset);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap fill-ring failed");
    ring_init(&insp->fill_ring, ring_mem, ring_len, PKT_NUMSLOT, PKT_MAXSIZE, &xdp_off.fr);

    // map rx-ring into userspace
    ring_len = xdp_off.rx.desc + PKT_NUMSLOT * sizeof(struct xdp_desc);
    prot = PROT_READ | PROT_WRITE;
    flags = MAP_SHARED;
    offset = XDP_PGOFF_RX_RING;
    ring_mem = mmap(NULL, ring_len, prot, flags, insp->sock_fd, offset);
    if (ring_mem == MAP_FAILED) return log_errno_rf("mmap rx-ring failed");
    ring_init(&insp->rx_ring, ring_mem, ring_len, PKT_NUMSLOT, PKT_MAXSIZE, &xdp_off.rx);

    // create map
    insp->map_fd = xsk_map_create(1);
    if (insp->map_fd == -1) return log_errno_rf("map_create failed");
    if (!bpf_patch_map(insp->map_fd, ARR_LEN(bpf_filter), bpf_filter)) {
        return log_error_rf("patch_map %d failed", insp->map_fd);
    }

    // load eBPF program
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .insns = (uintptr_t) bpf_filter,
        .insn_cnt = ARR_LEN(bpf_filter),
        .license = (uintptr_t) "GPL",
        .log_buf = (uintptr_t) insp->emsg,
        .log_size = sizeof(insp->emsg),
        .log_level = 1
    };
    insp->bpf_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (insp->bpf_fd == -1) {
        log_errno("BPF_PROG_LOAD failed");
        log_error("Verifier Log: %s", insp->emsg);
        return -1;
    }

    // attach bpf prog to device
    rc = bpf_attach_dev(insp->bpf_fd, insp->tap_index);
    if (rc < 0) return log_errno_rf("attach eBPF to %s failed", INSP_TAP);

    // bind xsd to device
    struct sockaddr_xdp sxdp = {
        .sxdp_family   = AF_XDP,
        .sxdp_ifindex  = insp->tap_index,
        .sxdp_queue_id = 0,
        .sxdp_flags    = XDP_COPY
    };
    rc = bind(insp->sock_fd, (struct sockaddr *) &sxdp, sizeof(sxdp));
    if (rc) return log_errno_rf("bind to %s failed", insp->dev_name);

    rc = xsk_map_update(insp->map_fd, 0, insp->sock_fd);
    if (rc) return log_errno_rf("map-update %d %d failed", 0, insp->sock_fd);

    log_info("+", "DNS active on %s", insp->dev_name);

    // all done
    return 0;
}

// run capture on network interface
static int run_capture(struct dns_insp *insp)
{
    int rc;

    switch(insp->type) {
    case TYPE_RAW:  rc = capture_raw(insp); break;
    case TYPE_MMAP: rc = capture_mmap(insp); break;
    case TYPE_XDP:  rc = capture_xdp(insp); break;
    default: rc = -1;
    }

    return rc;
}

// run tracepcap on pcap file
static int run_tracepcap(struct dns_insp *insp)
{
    size_t pkt_len;

    // select a buffer
    uint8_t *buf = insp->bufs[0];
    uint32_t buf_len = sizeof(insp->bufs[0]);

    while ((pkt_len = pcap_read(insp->pcap, buf, buf_len)) > 0) {
        // do nothing
    }

    return 0;
}

// run readpcap on pcap file
static int run_readpcap(struct dns_insp *insp)
{
    size_t pkt_len;

    // select a buffer
    uint8_t *buf = insp->bufs[0];
    uint32_t buf_len = sizeof(insp->bufs[0]);

    while ((pkt_len = pcap_read(insp->pcap, buf, buf_len)) > 0) {
        int rc = insp_process_pkt(insp, buf, pkt_len);
        if (rc) return rc;
    }

    return 0;
}

/*
 * cmd-line options
 *
 */
enum { opt_ifname, opt_type, opt_fname, opt_loglevel, opt_pcapng };

static struct cmd_opt capt_opts[] = {
    { "--interface", "<name> network interface to listen on", 0, 1, opt_ifname },
    { "--type",      "<raw|mmap|xdp> capture method", "raw", 1, opt_type },
    { "--file",      "<path> path to save captured packets", 0, 1, opt_fname },
    { "--log-level", "<level> logging level", STR(LOG_INFO), 1, opt_loglevel  },
    { "--pcapng",    "use pcapng file fmt", 0, 0, opt_pcapng },
    { NULL }
};

static struct cmd_opt pcap_opts[] = {
    { "--file", "<path> path to capture file to read", 0, 1, opt_fname },
    { NULL }
};

static const char *examples[] = {
    "capture --interface eth0",
    "capture --interface eth0 --type mmap",
    "capture --interface eth0 --file dns.pcap",
    "capture --interface eth0 --file dns.pcapng --pcapng",
    "readpcap --file dns.pcap",
    "tracepcap --file dns.pcap",
    NULL
};

static int set_interface(struct dns_insp *insp, struct cmd_argv *parse)
{
    const char *dev_name = parse->value;
    size_t len = strlen(dev_name);

    if (len >= sizeof(insp->dev_name)) {
       return log_error_rf("%s bigger than max %zu", parse->name, sizeof(insp->dev_name) - 1);
    }

    memcpy(insp->dev_name, dev_name, len);
    insp->dev_name[len] = '\0';

    insp->dev_index = if_nametoindex(insp->dev_name);
    if (insp->dev_index == 0) {
        return log_errno_rf("if_nametoindex for %s failed", insp->dev_name);
    }

    return 0;
}

static int set_type(struct dns_insp *insp, struct cmd_argv *parse)
{
    insp->type = str_totype(parse->value);
    if (!insp->type) {
        return log_cmd_err(insp->cmd->name, parse->name, "Unknown type");
    }

    return 0;
}

struct cmd_mode cmds[] = {
    { MODE_RUN(run_capture),   MODE_CAPTURE,   capt_opts, "capture",  "Capture DNS messages from a network interface" },
    { MODE_RUN(run_readpcap),  MODE_READPCAP,  pcap_opts, "readpcap", "Read DNS messages from a pcap file" },
    { MODE_RUN(run_tracepcap), MODE_TRACEPCAP, pcap_opts, "tracepcap","Read record/block info from a pcap file" },
   { NULL }
};

// parse cmd-line args
static int insp_parse_argv(struct dns_insp *insp, int argc, char *argv[])
{
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        mode_usage(argv[0], cmds, examples);
        exit(0);
    }

    // get cmd
    char *mode = argv[1];
    insp->cmd = cmd_mode_find(mode, cmds);
    if (!insp->cmd) return log_error_rf("Unsupported mode %s", mode);

    // process cmd-line options
    int rc;
    struct cmd_argv parser = { argc, argv, insp->cmd->opts, 2 } ;
    while ( (rc = cmd_argv_next(&parser)) >= 0) {
        switch(rc) {
        case opt_ifname:   rc = set_interface(insp, &parser); break;
        case opt_type:     rc = set_type(insp, &parser); break;
        case opt_fname:    rc = opt_setstr(&insp->filename, &parser); break;
        case opt_loglevel: rc = opt_setint(&log_level, &parser); break;
        case opt_pcapng:   insp->use_pcapng = 1; break;
        }
        if (rc < 0) break;
    }
    if (rc != OPT_EOF) return rc;

    // final checks
    switch(insp->cmd->mode) {
    case MODE_CAPTURE:
        if (!*insp->dev_name) return log_cmd_err(mode, capt_opts[0].name, "is required");
        break;
    case MODE_READPCAP:
    case MODE_TRACEPCAP:
        if (!insp->filename) return log_cmd_err(mode, pcap_opts[0].name, "is required");
        break;
    }

    // all done
    return 0;
}

static int open_pcap(struct dns_insp *insp)
{
    uint32_t flags = 0;

    switch(insp->cmd->mode) {
    case MODE_CAPTURE: flags |= PCAP_WRITE; break;
    case MODE_READPCAP: flags |= PCAP_READ; break;
    case MODE_TRACEPCAP: flags |= PCAP_READ | PCAP_TRACE; break;
    }
    if (insp->use_pcapng) flags |= PCAP_FMTNG;

    insp->pcap = pcap_open(insp->filename, flags);
    if (!insp->pcap) return -1;

    return 0;
}

// setup state after parsing argv
static int insp_init(struct dns_insp *insp)
{
    int rc;

    if (insp->filename) {
        rc = open_pcap(insp);
        if (rc) return rc;
    }

    if (insp->cmd->mode != MODE_CAPTURE) return rc;

    switch(insp->type) {
    case TYPE_RAW:  rc = setup_raw(insp); break;
    case TYPE_MMAP: rc = setup_mmap(insp); break;
    case TYPE_XDP:  rc = setup_xdp(insp); break;
    default: rc = -1;
    }

    return rc;
}

// free state
static void insp_free(struct dns_insp *insp)
{
    if (insp->bpf_fd != -1) {
        bpf_attach_dev(-1, insp->tap_index);
        close(insp->bpf_fd);
    }
    if (insp->map_fd != -1) close(insp->map_fd);
    membuf_deinit(&insp->umem);
    ring_deinit(&insp->rx_ring);
    ring_deinit(&insp->fill_ring);

    if (insp->sock_fd != -1) close(insp->sock_fd);
    if (insp->use_tap) xdp_deinit_tap(insp);

    if (insp->pcap) pcap_close(insp->pcap);
    if (insp->filename) free(insp->filename);

    free(insp);
}

// create state
static struct dns_insp *insp_create(void)
{
    struct dns_insp *insp;

    insp = malloc(sizeof(*insp));
    if (!insp) return log_errno_rn("malloc failed for state");

    memset(insp, 0, sizeof(*insp));
    insp->sock_fd = -1;
    insp->bpf_fd = -1;
    insp->map_fd = -1;
    insp->type = TYPE_RAW;

    return insp;
}

int main(int argc, char *argv[])
{
    struct dns_insp *insp = NULL;
    int ec = 0;

    log_init(NULL, LOG_INFO);

    if (!(insp = insp_create())) { ec = 1; goto done; }
    if (insp_parse_argv(insp, argc, argv)) { ec = 2;  goto done; }
    if (setup_signals(&insp->sig)) { ec = 3; goto done; }
    if (insp_init(insp))     { ec = 4; goto done; }
    if (insp->cmd->run(insp)) { ec = 5; goto done; }

done:
    if (insp) insp_free(insp);

    return ec;
}
