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

#include <sys/epoll.h>
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
#include <sys/epoll.h>
#include <errno.h>

#include "util.h"
#include "pcap.h"
#include "dns_proto.h"

#define MODE_CAPTURE   1
#define MODE_READPCAP  2
#define MODE_TRACEPCAP 3

#define MAX_EVENTS 10
#define PKTBUF_SIZE 2048
#define PKT_MIN_LEN (14 + 20 + 8 + 12)
#define make_ptr(ptr, offset) ((void *) (ptr + offset))

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
    int epoll_fd;
    // packet counters
    uint64_t num_recv_pkts;
    uint64_t num_dns_pkts;
    uint64_t num_dns_okay;
    uint64_t num_dns_fail;
    // read buffer
    int buf_len;
    char pkt_buf[];
};

static char dns_errbuf[DNS_ERRBUF_SIZE];

static int sniff_pkt_process(struct dns_sniff *sniff, int pkt_len)
{
    sniff->num_recv_pkts++;

    if (pkt_len < PKT_MIN_LEN) {
        // TOO small (eth+IP+UDP)
        return 0;
    }

    unsigned char *ptr = make_ptr(sniff->pkt_buf, 0);
    int offset = 0;

    // Etherner layer
    struct ethhdr *eth = make_ptr(ptr, offset);
    uint16_t type = ntohs(eth->h_proto);
    offset += sizeof(*eth);

    // VLAN tag ?
    if (type ==  0x8100) {
        // skip vlan tags
        uint16_t *iptr = make_ptr(ptr, 2);
        type = ntohs(*iptr);
        offset += 4;
    }   

    // IP layer
    int hdr_len = 0;
    int proto = 0;
    if (type ==  ETH_P_IP) {
        struct iphdr *ip = make_ptr(ptr,offset);
        if (ip->version != 4) return 0;
        hdr_len = ip->ihl * 4;
        proto = ip->protocol;
    }
    else if (type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = make_ptr(ptr, offset);
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
    struct udphdr *udp = make_ptr(ptr, offset);
    uint16_t src_port = ntohs(udp->source);
    uint16_t dst_port = ntohs(udp->dest);
    if (src_port != 53 && dst_port != 53) {
        // not a DNS port ?
        return 0;
    }
    offset += sizeof(*udp);

    // call into api
    sniff->num_dns_pkts++;
    if (validate_dns_packet(ptr + offset, pkt_len - offset, dns_errbuf) == 0) {
        sniff->num_dns_okay++;
    }
    else {
        sniff->num_dns_fail++;
    }
    log_msg(dns_errbuf);

    // all done
    return 0;
}


static int sniff_do_read(struct dns_sniff *sniff)
{
    ssize_t nr;

    // loopp until all packer read or error 
    // TODO use recvmmsg
    while (1) {
         nr = recvfrom(sniff->sock_raw, sniff->pkt_buf, sniff->buf_len, 0, NULL, NULL);
         if (nr  == -1) {
             if (errno == EINTR) break;
             if (errno == EAGAIN || EWOULDBLOCK) break;
             return log_errno("read fd %d on dev %s failed", sniff->sock_raw, sniff->dev_name);
         }
         if (sniff_pkt_process(sniff, nr) != 0) {
             return -1;
         }
    }

    // all done
    return 0;
}

int sniff_handle_event(struct dns_sniff *sniff, uint32_t events)
{
    int shutdown = 0;

    if (events & EPOLLIN) {
        // got a read event
        if (sniff_do_read(sniff) != 0) {
           shutdown = 1;
        }
    }

    if (events & (EPOLLERR | EPOLLHUP)) {
        // error event
        int error = 0;
        uint32_t epoll = events & (EPOLLERR | EPOLLHUP);
        socklen_t errlen = sizeof(error);
        if (getsockopt(sniff->sock_raw, SOL_SOCKET, SO_ERROR, &error, &errlen) == -1) {
            log_errno("socket %d epoll 0x%08x", sniff->sock_raw, epoll);
        }
        else if (error != 0) {
            log_error("socket %d epoll 0x%08x error %d (%s)", sniff->sock_raw, epoll, error, strerror(error));
        }
        else {
            log_error("socket %d epoll 0x%08x", sniff->sock_raw,  epoll);
        }
        shutdown = 1;
    }

    if (shutdown) {
        close(sniff->sock_raw);
        sniff->sock_raw = -1;
        return -1;
    }

    // all done
    return 0;
}

// signal handling
volatile sig_atomic_t keep_running = 1;
volatile sig_atomic_t caught_signo = 0; 
volatile sig_atomic_t sender_pid = 0; 
volatile sig_atomic_t sender_uid = 0; 

void sniff_handle_signal(int signo, siginfo_t *info, void *ucontext)
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

    sa.sa_sigaction = sniff_handle_signal;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return log_errno("setup sigint");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return log_errno("setup sigterm");
    }

    // XXX prevent write(fd) trigger a signal
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        return log_errno("setup SIGPIPE");
    }

    return 0;
}

// event handling
int sniff_poll(struct dns_sniff *sniff)
{
    struct epoll_event events[MAX_EVENTS];

    int nfd = epoll_wait(sniff->epoll_fd, events, MAX_EVENTS, -1);

    if (nfd < 0) {
        if (errno == EINTR) return 0;
        return log_errno("dns-sniff PID:%d epoll_wait failed", sniff->pid);
    }

    for (int i = 0; i < nfd; i++) {
        sniff_handle_event(sniff, events[i].events);
    }

    // all done
    return 0;
}

int sniff_capture(struct dns_sniff *sniff)
{
    while (keep_running) {
        if (sniff_poll(sniff) != 0) return -1;
    }

    if (caught_signo) {
        log_info("dns-sniff", "PID:%d shutting down: got signal %d (%s) from UID:%d PID:%d ", 
            sniff->pid, 
            caught_signo, strsignal(caught_signo), 
            sender_uid,
            sender_pid);
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
    sniff->sock_raw = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (sniff->sock_raw == -1) {
        return log_errno("open AF_PACKET");
    }

    // bind to interface - kernel will start sending us pkts
    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = sniff->dev_index,
        .sll_protocol = htons(ETH_P_ALL)
    };
    if (bind(sniff->sock_raw, (struct sockaddr *) &sll, sizeof(sll)) < 0) {
        return log_errno("bind to %s failed", sniff->dev_name);
    }

    // attach DNS filter
    struct sock_fprog bpf = {
        .len =   sizeof(dns_filter) / sizeof(struct sock_filter),
        .filter = dns_filter
    };
    if (setsockopt(sniff->sock_raw, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        return log_errno("Attach DNS filter to %s failed", sniff->dev_name);
    }

    // promisc mode
    struct packet_mreq mreq = {
        .mr_ifindex = sniff->dev_index,
        .mr_type    = PACKET_MR_PROMISC
    };
    if (setsockopt(sniff->sock_raw, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        return log_errno("setsockopt PACKET_MR_PROMISC");
    }

    // create epoll fd
    sniff->epoll_fd = epoll_create1(0);
    if (sniff->epoll_fd == -1) {
        return log_errno("epoll_create1 failed");
    }

    // add socket to epoll
    int rc;
    struct epoll_event ev = { 0 };
    ev.events = EPOLLIN;
    ev.data.ptr = sniff;
    do {
        rc = epoll_ctl(sniff->epoll_fd, EPOLL_CTL_ADD, sniff->sock_raw, &ev);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1) {
        return log_errno("epoll_ctl add filed for %d", sniff->sock_raw);
    }

    log_info("dns-sniff", "DNS active on %s", sniff->dev_name);

    // all done
    return 0;
}

static int sniff_readpcap(struct dns_sniff *sniff)
{
    size_t pkt_len;

    sniff->pcap = pcap_open(sniff->pcap_filename, PCAP_READ);
    if (!sniff->pcap) {
        return -1;
    }

    while ( (pkt_len = pcap_read(sniff->pcap, sniff->pkt_buf, sniff->buf_len)) > 0) {
        if (sniff_pkt_process(sniff, pkt_len) != 0) {
            return -1;
        }
    }

     pcap_close(sniff->pcap);
     sniff->pcap = NULL;

     return 0;
}

static int sniff_tracepcap(struct dns_sniff *sniff)
{
    size_t pkt_len;

    sniff->pcap = pcap_open(sniff->pcap_filename, PCAP_READ | PCAP_TRACE);
    if (!sniff->pcap) {
        return -1;
    }

    while ( (pkt_len = pcap_read(sniff->pcap, sniff->pkt_buf, sniff->buf_len)) > 0) {
        // do nothing
    }

     pcap_close(sniff->pcap);
     sniff->pcap = NULL;

     return 0;
}


static int sniff_usage(struct dns_sniff *sniff, const char *cmd)
{
    const char *base = strrchr(cmd, '/');
    const char *prog_name = (base) ? base + 1 : cmd;
    FILE *out = stderr;
    int w= 10;

    fprintf(out,"Usage: %s [MODE] [OPTIONS]\n\n", prog_name);

    fprintf(out, "MODE:\n");
    fprintf(out, "  %-*s %s\n", w, "--help", "Show this help");
    fprintf(out, "  %-*s %s\n", w, "capture", "--interface name");
    fprintf(out, "  %-*s %s\n", w, "readpcap", "--file name");
    fprintf(out, "  %-*s %s\n", w, "tracepcap", "--file name");

    fprintf(out, "\nExample:\n");
    fprintf(out, "  %s capture --interface eth0\n", prog_name);
    fprintf(out, "  %s readpcap --file dns.pcap\n", prog_name);
    fprintf(out, "  %s tracecap --file dns.pcap\n", prog_name);

    return -1;
}

// dns-inspect capture --interface eth0
int sniff_parse_argv(struct dns_sniff *sniff, int argc, char *argv[])
{
    if (argc < 2) {
        return sniff_usage(sniff, argv[0]);
    }

    // mode
    struct str_slice mode = slice_make_cstr(argv[1]);
    if (slice_cmp_cstr(mode, STR_LIT("capture"))) {
        sniff->mode = MODE_CAPTURE;
        int nargs = argc - 2;
        if (nargs != 2) {
           return log_error("capture require an --interface name");
        }
        // --interface option
        struct str_slice opt = slice_make_cstr(argv[2]);
        struct str_slice val = slice_make_cstr(argv[3]);
        if (!slice_cmp_cstr(opt, STR_LIT("--interface"))) {
           return log_error("capture unknown option %s", opt.ptr);
        }
        // device name
        if (opt.len >= sizeof(sniff->dev_name)) {
           return log_error("name cant be bigger than %zu", sizeof(sniff->dev_name) - 1);
        }
        memcpy(sniff->dev_name, val.ptr, val.len);
        sniff->dev_name[val.len] = '\0';
        sniff->dev_index = if_nametoindex(sniff->dev_name);
        if (sniff->dev_index == 0) {
           return log_errno("if_nametoindex for %s failed", sniff->dev_name);
        }
    }
    else if (slice_cmp_cstr(mode, STR_LIT("readpcap"))) {
        sniff->mode = MODE_READPCAP;
        int nargs = argc - 2;
        if (nargs != 2) {
           return log_error("readpcap requires a filename");
        }
        // --file
        struct str_slice opt = slice_make_cstr(argv[2]);
        struct str_slice val = slice_make_cstr(argv[3]);
        if (!slice_cmp_cstr(opt, STR_LIT("--file"))) {
           return log_error("readpcap unknown option %s", opt.ptr);
        }
        // filename
        sniff->pcap_filename = strdup(val.ptr);
        if (!sniff->pcap_filename) {
            return log_errno("strdup failed for %.*s", (int) max(strlen(opt.ptr), 400), val.ptr);
        }
    }
    else if (slice_cmp_cstr(mode, STR_LIT("tracepcap"))) {
        sniff->mode = MODE_TRACEPCAP;
        int nargs = argc - 2;
        if (nargs != 2) {
           return log_error("tracepcap requires a filename");
        }
        // --file
        struct str_slice opt = slice_make_cstr(argv[2]);
        struct str_slice val = slice_make_cstr(argv[3]);
        if (!slice_cmp_cstr(opt, STR_LIT("--file"))) {
           return log_error("tracepcap unknown option %s", opt.ptr);
        }
        // filename
        sniff->pcap_filename = strdup(val.ptr);
        if (!sniff->pcap_filename) {
            return log_errno("strdup failed for %.*s", (int) max(strlen(opt.ptr), 400), val.ptr);
        }
    }
    else {
        log_error("Unsupported mode %s", mode.ptr);
        return sniff_usage(sniff, argv[0]);
    }

    return 0;
}

void sniff_free(struct dns_sniff *sniff)
{
    if (sniff->sock_raw != -1) {
        close(sniff->sock_raw);
    }

    if (sniff->epoll_fd != -1) {
        close(sniff->epoll_fd);
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
    memset(sniff, 0, sizeof(*sniff) + PKTBUF_SIZE);

    sniff->buf_len = PKTBUF_SIZE;
    sniff->sock_raw = -1;
    sniff->epoll_fd = -1;

    return 0;
}

struct dns_sniff *sniff_create(void)
{
    struct dns_sniff *sniff;

    sniff = malloc(sizeof(*sniff) + PKTBUF_SIZE);
    if (!sniff) {
        return log_errnon("Malloc failed for sniff state");
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
    case MODE_CAPTURE:
        if (sniff_signals(sniff) != 0)  { ec = 4 ;goto done; }
        if (sniff_attach(sniff) != 0) { ec = 5; goto done; }
        if (sniff_capture(sniff) != 0) { ec = 6; goto done; }
        break;

    case MODE_READPCAP:
        if (sniff_readpcap(sniff) != 0) { ec = 7; goto done; }
        break;

    case MODE_TRACEPCAP:
        if (sniff_tracepcap(sniff) != 0) { ec = 8; goto done; }
        break;
    }

    // all done
    ec = 0;

done:
    if (sniff) sniff_free(sniff);

    return ec;
}
