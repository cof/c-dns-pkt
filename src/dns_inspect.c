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
 * Notes
 * -----
 * - Uses AF_PACKET, SOCK_RAW socket to monitor interface
 * - Uses EBF sock_filter for UDP DNS port 53
 * - Uses PROMISC mode
 * - Uses DNS api to decode,validate and print DNS messages
 * - Uses PCAP api to read|trace pcap files
 */
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
#include "log.h"
#include "pcap.h"
#include "dns_proto.h"

// supported cmds
#define MODE_NONE      0
#define MODE_CAPTURE   1
#define MODE_READPCAP  2
#define MODE_TRACEPCAP 3

// Packet size limits
#define PKT_BUFSIZE 2048
#define PKT_MAXRECV 10
#define PKT_MIN_LEN (14 + 20 + 8)

#define RCVBUF_SIZE (2 * 1024 * 1024)
#define MAX_EVENTS 10

// inspect state
struct dns_sniff {
    // config
    struct simple_sig sig;
    pid_t pid;
    // state
    struct cmd_mode *cmd;
    char *filename;
    struct pcap_file *pcap;
    char dev_name[IFNAMSIZ]; 
    int dev_index;
    int sock_raw;
    unsigned int use_pcapng : 1; // use pcapng output fmt
    // packet counters
    uint64_t num_recv_pkts;
    uint64_t num_dns_pkts;
    uint64_t num_dns_okay;
    uint64_t num_dns_fail;
    // validate emsg
    char dns_emsg[DNS_EMSG_MAXLEN];
    // packet read buffers
    struct mmsghdr msgs[PKT_MAXRECV];
    struct iovec   vecs[PKT_MAXRECV];
    uint8_t        bufs[PKT_MAXRECV][PKT_BUFSIZE];
};

static int sniff_process_pkt(struct dns_sniff *sniff, uint8_t *pkt_data, uint32_t pkt_len)
{
    sniff->num_recv_pkts++;

    // too small (eth+IP+UDP)
    if (pkt_len < PKT_MIN_LEN) return 0;
    int offset = 0;

    // Etherner layer
    struct ethhdr *eth = mkptr(pkt_data, offset);
    uint16_t type = ntohs(eth->h_proto);
    offset += sizeof(*eth);

    // VLAN tag ?
    if (type ==  0x8100) {
        // skip vlan tags
        uint16_t *iptr = mkptr(pkt_data, 2);
        type = ntohs(*iptr);
        offset += 4;
    }   

    // IP layer
    int hdr_len = 0;
    int proto = 0;
    if (type ==  ETH_P_IP) {
        struct iphdr *ip = mkptr(pkt_data, offset);
        if (ip->version != 4) return 0;
        hdr_len = ip->ihl * 4;
        proto = ip->protocol;
    }
    else if (type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = mkptr(pkt_data, offset);
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
    struct udphdr *udp = mkptr(pkt_data, offset);
    uint16_t src_port = ntohs(udp->source);
    uint16_t dst_port = ntohs(udp->dest);
    if (src_port != 53 && dst_port != 53) {
        // not a DNS port ?
        return 0;
    }
    offset += sizeof(*udp);

    // call into api
    sniff->num_dns_pkts++;
    int rc = dns_validate(pkt_data + offset, pkt_len - offset, sniff->dns_emsg, sizeof(sniff->dns_emsg));
    if (rc == 0) {
        sniff->num_dns_okay++;
    }
    else {
        sniff->num_dns_fail++;
    }
    fputs(sniff->dns_emsg, stderr);

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

static int sniff_capture(struct dns_sniff *sniff)
{
    while (sniff->sig.run) {
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

// run capture cmd
static int run_capture(struct dns_sniff *sniff)
{
    int rc;

    if ((rc = setup_signals(&sniff->sig))) return rc;
    if ((rc = sniff_attach(sniff)))  return rc;
    if ((rc = sniff_capture(sniff))) return rc;

    return 0;
}

/*
 * cmd-line options
 *
 */
enum { opt_ifname, opt_fname, opt_pcapng };

static struct cmd_opt capt_opts[] = {
    { "--interface" ,"Name of interface to sniff DNS msgs", 0, 1, opt_ifname },
    { "--file"      ,"Name of packet capture file", 0, 1, opt_fname },
    { "--pcapng"    , "Use pcapng file fmt", 0, 0, opt_pcapng },
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

struct cmd_mode cmds[] = {
    { MODE_RUN(run_capture),   MODE_CAPTURE,   capt_opts, "capture",  "capture DNS msgs from an interface" },
    { MODE_RUN(run_readpcap),  MODE_READPCAP,  pcap_opts, "readpcap", "Read DNS msgs from packet capture file" },
    { MODE_RUN(run_tracepcap), MODE_TRACEPCAP, pcap_opts, "tracepcap","trace a packet capture file"  },
   { NULL }
};

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
        case opt_ifname: rc = set_interface(sniff, &parser); break;
        case opt_fname:  rc = opt_setstr(&sniff->filename, &parser); break;
        case opt_pcapng: sniff->use_pcapng = 1; break;
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

    if (sniff->filename) {
        rc = open_pcap(sniff);
        if (rc) return rc;
    }

    // all done
    return 0;
}

// set defaults
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

// free state
static void sniff_free(struct dns_sniff *sniff)
{
    if (sniff->sock_raw != -1) close(sniff->sock_raw);
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

    return sniff;
}

int main(int argc, char *argv[])
{
    struct dns_sniff *sniff = NULL;
    int ec = 0;

    log_init(NULL, LOG_INFO);
    if (!(sniff = sniff_create())) { ec = 1; goto done; }
    if (sniff_init(sniff)) { ec = 2; goto done; }
    if (sniff_parse_argv(sniff, argc, argv)) { ec = 3;  goto done; }
    if (sniff->cmd->run(sniff)) { ec = 4; goto done; }

done:
    if (sniff) sniff_free(sniff);

    return ec;
}
