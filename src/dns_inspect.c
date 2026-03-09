/*
 * dns-inpect - a simple DNS packet sniffer
 *
 * Usage: dns-inspect
 *
 * Notes:
 *
 */
#include <stdio.h>
#include <stdlib.h> 
#include <stdarg.h>
#include <stddef.h>
#include <string.h> 
#include <signal.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/ipv6.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h> 
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "pcap.h"
#include "dns_proto.h"

// supported cmds
#define MODE_CAPTURE   1
#define MODE_READPCAP  2
#define MODE_TRACEPCAP 3

#define PKT_BUFSIZE 2048
#define PKT_MAXRECV 10
#define PKT_MIN_LEN (14 + 20 + 8 + 12)

#define make_ptr(ptr, offset) ((void *) (ptr + offset))
#define RCVBUF_SIZE (2 * 1024 * 1024)
#define MAX_EVENTS 10

struct dns_sniff {
    // config
    pid_t pid;
    char *host;
    char *port;
    //  state
    int mode;
    char *pcap_filename;
    struct pcap_file *pcap;
    char dev_name[IFNAMSIZ]; 
    int dev_index;
    int sock_raw;
    // packet counters
    uint64_t num_recv_pkts;
    uint64_t num_dns_pkts;
    uint64_t num_dns_okay;
    uint64_t num_dns_fail;
    // read buffer
    struct mmsghdr msgs[PKT_MAXRECV];
    struct iovec   vecs[PKT_MAXRECV];
    uint8_t        bufs[PKT_MAXRECV][PKT_BUFSIZE];
};

static char dns_errbuf[DNS_ERRBUF_SIZE];

static int sniff_process_pkt(struct dns_sniff *sniff, uint8_t *pkt_data, uint32_t pkt_len)
{
    sniff->num_recv_pkts++;

    if (pkt_len < PKT_MIN_LEN) {
        // too small (eth+IP+UDP)
        return 0;
    }

    int offset = 0;

    // Etherner layer
    struct ethhdr *eth = make_ptr(pkt_data, offset);
    uint16_t type = ntohs(eth->h_proto);
    offset += sizeof(*eth);

    // VLAN tag ?
    if (type ==  0x8100) {
        // skip vlan tags
        uint16_t *iptr = make_ptr(pkt_data, 2);
        type = ntohs(*iptr);
        offset += 4;
    }   

    // IP layer
    int hdr_len = 0;
    int proto = 0;
    if (type ==  ETH_P_IP) {
        struct iphdr *ip = make_ptr(pkt_data,offset);
        if (ip->version != 4) return 0;
        hdr_len = ip->ihl * 4;
        proto = ip->protocol;
    }
    else if (type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = make_ptr(pkt_data, offset);
        if (ip6->version != 6) return 0;
        proto = ip6->nexthdr;
        hdr_len = 40;
    }
    else {
        // unknown type
        return 0;
    }
    offset += hdr_len;  
    if (proto != IPPROTO_UDP) return 0;

    // UDP layer
    struct udphdr *udp = make_ptr(pkt_data, offset);
    uint16_t src_port = ntohs(udp->source);
    uint16_t dst_port = ntohs(udp->dest);
    if (src_port != 53 && dst_port != 53) {
        // not a DNS port ?
        return 0;
    }
    offset += sizeof(*udp);

    // call into api
    sniff->num_dns_pkts++;
    if (validate_dns_packet(pkt_data + offset, pkt_len - offset, dns_errbuf) == 0) {
        sniff->num_dns_okay++;
    }
    else {
        sniff->num_dns_fail++;
    }
    log_msg(dns_errbuf);

    // all done
    return 0;
}

static int sniff_process_msg(struct dns_sniff *sniff, struct mmsghdr *msg)
{
    uint8_t *pkt_data = msg->msg_hdr.msg_iov->iov_base;
    uint32_t pkt_len = msg->msg_len;

    return sniff_process_pkt(sniff, pkt_data, pkt_len);
}


// signal handling
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t caught_signo = 0; 
static volatile sig_atomic_t sender_pid = 0; 
static volatile sig_atomic_t sender_uid = 0; 

static void catch_signal(int signo, siginfo_t *info, void *ucontext)
{
    caught_signo = signo;

    sender_pid = 0;
    sender_uid = 0;

    if (info->si_code <= 0) {
        sender_pid = info->si_pid;
        sender_uid = info->si_uid;
    }

    keep_running = 0;
}

int sniff_signals(struct dns_sniff *sniff)
{
    struct sigaction sa = { 0 };

    sa.sa_sigaction = catch_signal;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return log_errno_rf("setup sigint");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return log_errno_rf("setup sigterm");
    }

    // XXX prevent write(fd) trigger a signal
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        return log_errno_rf("setup SIGPIPE");
    }

    return 0;
}

int sniff_capture(struct dns_sniff *sniff)
{
    while (keep_running) {
        // read a block
        int nr = recvmmsg(sniff->sock_raw, sniff->msgs, PKT_MAXRECV, MSG_WAITFORONE, NULL);
        if (nr < 0) {
            if (errno == EINTR) continue;
             return log_errno_rf("recvmmsg fd %d on dev %s failed", sniff->sock_raw, sniff->dev_name);
        }
        for (int i = 0; i < nr; i++) {
            int rc = sniff_process_msg(sniff, &sniff->msgs[i]);
            if (rc) return rc;
        }
    }

    if (caught_signo) {
        log_info("dns-sniff", 
            "PID:%d shutting down: got signal %d (%s) from UID:%d PID:%d ",
            sniff->pid,
            caught_signo, strsignal(caught_signo), 
            sender_uid, sender_pid);
    }

    return 0;
}

// tcpdump -i any udp port 53 -dd
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

// attach dns pkt filter to device
int sniff_attach(struct dns_sniff *sniff)
{
    // socket
    sniff->sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sniff->sock_raw == -1) {
        return log_errno_rf("open AF_PACKET");
    }

    // bind to interface - kernel will start sending us pkts
    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = sniff->dev_index,
        .sll_protocol = htons(ETH_P_ALL)
    };
    if (bind(sniff->sock_raw, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
        return log_errno_rf("bind to %s failed", sniff->dev_name);
    }

    // attach DNS filter
    struct sock_fprog bpf = {
        .len =   sizeof(dns_filter) / sizeof(struct sock_filter),
        .filter = dns_filter
    };
    if (setsockopt(sniff->sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        return log_errno_rf("Attach DNS filter to %s failed", sniff->dev_name);
    }

    // set receive buffer size
    int size = RCVBUF_SIZE;
    if (setsockopt(sniff->sock_raw, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0) {
        log_errno_rf("Set RCVBUF size %d failed", size);
    }

    /* timestamping
    int flags= 
    if (setsockopt(sniff->sock_raw, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        return log_errno_rf("enable timestamping on %d failed", sniff->sock_raw);
    }
    */

    // promisc mode
    struct packet_mreq mreq = {
        .mr_ifindex = sniff->dev_index,
        .mr_type    = PACKET_MR_PROMISC
    };
    if (setsockopt(sniff->sock_raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        return log_errno_rf("setsockopt PACKET_MR_PROMISC");
    }

    log_info("dns-sniff", "DNS active on %s", sniff->dev_name);

    // all done
    return 0;
}

static int sniff_do_capture(struct dns_sniff *sniff)
{
    if (sniff_signals(sniff) != 0) return 4;
    if (sniff_attach(sniff) != 0)  return 4;
    if (sniff_capture(sniff) != 0) return 4;

    return 0;
}


static int sniff_do_readpcap(struct dns_sniff *sniff)
{
    size_t pkt_len;

    sniff->pcap = pcap_open(sniff->pcap_filename, PCAP_READ);
    if (!sniff->pcap) {
        return -1;
    }

    // select a buffer
    uint8_t *buf = sniff->bufs[0];
    uint32_t buf_len = sizeof(sniff->bufs[0]);

    while ( (pkt_len = pcap_read(sniff->pcap, buf, buf_len)) > 0) {
        int rc = sniff_process_pkt(sniff, buf, pkt_len);
        if (rc) return rc;
    }

     pcap_close(sniff->pcap);
     sniff->pcap = NULL;

     return 0;
}

static int sniff_do_tracepcap(struct dns_sniff *sniff)
{
    size_t pkt_len;

    sniff->pcap = pcap_open(sniff->pcap_filename, PCAP_READ | PCAP_TRACE);
    if (!sniff->pcap) {
        return -1;
    }

    // select a buffer
    uint8_t *buf = sniff->bufs[0];
    uint32_t buf_len = sizeof(sniff->bufs[0]);

    while ( (pkt_len = pcap_read(sniff->pcap, buf, buf_len)) > 0) {
        // do nothing
    }

     pcap_close(sniff->pcap);
     sniff->pcap = NULL;

     return 0;
}


static int sniff_setup_capture(void *state, int narg, struct str_slice args[narg])
{
    struct dns_sniff *sniff = state;

    sniff->mode = MODE_CAPTURE;
    if (narg != 2) {
       return log_error_rf("capture require an --interface name");
    }

    // --interface option
    struct str_slice opt = args[0];
    if (!slice_cmp_cstr(opt, STR_LIT("--interface"))) {
       return log_error_rf("capture unknown option %.*s", (int) opt.len, opt.ptr);
    }

    // device name
    struct str_slice name = args[1];
    if (name.len >= sizeof(sniff->dev_name)) {
       return log_error_rf("device name cant be bigger than %zu", sizeof(sniff->dev_name) - 1);
    }
    memcpy(sniff->dev_name, name.ptr, name.len);
    sniff->dev_name[name.len] = '\0';

    sniff->dev_index = if_nametoindex(sniff->dev_name);
    if (sniff->dev_index == 0) {
       return log_errno_rf("if_nametoindex for %s failed", sniff->dev_name);
    }

    // all done
    return 0;
}

static int sniff_setup_readpcap(void *state, int narg, struct str_slice args[narg])
{
    struct dns_sniff *sniff = state;

    sniff->mode = MODE_READPCAP;

    if (narg < 1) {
       return log_error_rf("readpcap: Missing --file option");
    }

    // --file
    struct str_slice opt = args[0];
    if (!slice_cmp_cstr(opt, STR_LIT("--file"))) {
       return log_error_rf("readpcap: unknown option %.*s", (int) opt.len, opt.ptr);
    }

    // name
    if (narg < 2) {
       return log_error_rf("readpcap: mising name");
    }
    sniff->pcap_filename = slice_strdup(args[1]);
    if (!sniff->pcap_filename) {
        return log_errno_rf("strdup failed for len %zu", args[1].len);
    }

    return 0;
}

static int sniff_setup_tracepcap(void *state, int narg, struct str_slice args[])
{
    struct dns_sniff *sniff = state;

    sniff->mode = MODE_TRACEPCAP;
    if (narg != 2) {
       return log_error_rf("tracepcap: missing --file");
    }

    // --file
    struct str_slice opt = args[0];
    if (!slice_cmp_cstr(opt, STR_LIT("--file"))) {
       return log_error_rf("tracepcap: unknown option %.*s", (int) opt.len, opt.ptr);
    }

    // name
    sniff->pcap_filename = slice_strdup(args[1]);
    if (!sniff->pcap_filename) {
        return log_errno_rf("strdup failed for len %zu", args[1].len);
    }

    return 0;
}

static int sniff_usage(void *state, struct str_slice name)
{
    FILE *out = stderr;
    int w= 10;

    fprintf(out,"Usage: %.*s [MODE] [OPTIONS]\n\n", SLICE(name));

    fprintf(out, "MODE:\n");
    fprintf(out, "  %-*s %s\n", w, "capture", "--interface name");
    fprintf(out, "  %-*s %s\n", w, "readpcap", "--file name");
    fprintf(out, "  %-*s %s\n", w, "tracepcap", "--file name");

    fprintf(out, "\nExample:\n");
    fprintf(out, "  %.*s capture --interface eth0\n", SLICE(name));
    fprintf(out, "  %.*s readpcap --file dns.pcap\n", SLICE(name));
    fprintf(out, "  %.*s tracecap --file dns.pcap\n", SLICE(name));

    return -1;
}

static struct util_cmd cmds[] =  {
    { STR_LIT("capture"),  sniff_setup_capture },
    { STR_LIT("readpcap"), sniff_setup_readpcap  },
    { STR_LIT("tracepcap"), sniff_setup_tracepcap }
};

static int sniff_parse_argv(struct dns_sniff *sniff, int argc, char *argv[])
{
    return util_parse_argv(sniff, argc, argv, ARRAY(cmds), sniff_usage);
}

void sniff_free(struct dns_sniff *sniff)
{
    if (sniff->sock_raw != -1) {
        close(sniff->sock_raw);
    }

    if (sniff->pcap) {
        pcap_close(sniff->pcap);
    }

    if (sniff->pcap_filename) {
        free(sniff->pcap_filename);
    }

    free(sniff);
}


static int sniff_init(struct dns_sniff *sniff)
{

    memset(sniff, 0, sizeof(*sniff));

    sniff->sock_raw = -1;

    for (int i = 0; i < PKT_MAXRECV; i++) {
        sniff->vecs[i].iov_base = sniff->bufs[i];
        sniff->vecs[i].iov_len  = sizeof(sniff->bufs[i]);
        sniff->msgs[i].msg_hdr.msg_iov  = &sniff->vecs[i];
        sniff->msgs[i].msg_hdr.msg_iovlen  = 1;
    }

    return 0;
}

struct dns_sniff *sniff_create(void)
{
    struct dns_sniff *sniff;

    sniff = malloc(sizeof(*sniff));

    if (!sniff) {
        return log_errno_rn("Malloc failed for sniff state");
    }

    return sniff;
}

int main(int argc, char *argv[])
{
    struct dns_sniff *sniff = NULL;
    int ec = EXIT_FAILURE;

    if (!(sniff = sniff_create())) { ec = 1; goto done; }
    if (sniff_init(sniff) != 0)  { ec = 2; goto done; }
    if (sniff_parse_argv(sniff, argc, argv) != 0) { ec = 3;  goto done; }

    switch(sniff->mode) {
    case MODE_CAPTURE:   ec = sniff_do_capture(sniff); break;
    case MODE_READPCAP:  ec = sniff_do_readpcap(sniff); break;
    case MODE_TRACEPCAP: ec = sniff_do_tracepcap(sniff); break;
    default: 
        log_error("Unsupported mode %d", sniff->mode);
        ec = 4;
    }

done:
    if (sniff) sniff_free(sniff);

    return ec;
}
