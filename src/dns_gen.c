/*
 * dns-gen - a simple DNS packet generator
 *
 *  dns-gen [mode] [option]
 *
 * See usage for more details.
 *
 */
#include <stdio.h>
#include <stdlib.h> 
#include <stdarg.h>
#include <stddef.h>
#include <string.h> 
#include <signal.h>
#include <time.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <unistd.h>
#include <errno.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "util.h"
#include "pcap.h"
#include "dns_proto.h"

#define MSG_TIMEOUT 5

// gen erro codes
#define SOCK_NONE     0
#define SOCK_DATA     1
#define SOCK_CLOSED  -1
#define SOCK_ERROR   -2
#define SOCK_TIMEOUT -3
#define SOCK_ENCODE  -4

// supported cmds
#define MODE_QUERY 1
#define MODE_RESP  2
#define MODE_FUZZ  3

#define FUZZ_HDR    1
#define FUZZ_COMP   2
#define FUZZ_TRUNC  3
#define FUZZ_LABELS 4
#define FUZZ_OPCODE 5
#define FUZZ_RCODE  6

#define ETHIPUDP_LEN (14 + 20 + 8)

struct dns_gen {
    // config
    pid_t pid;
    //  state
    int mode;
    // cmd options
    char dns_name[256];
    uint16_t dns_type;
    uint16_t dns_class;
    uint16_t dns_flags;
    char *serv_addr;
    uint16_t id;
    uint32_t ttl;
    char *output;
    struct pcap_file *pcap;
    struct dns_msg send_msg; // messge template
    uint32_t timeout; // send / recv message timeout 
    int fuzz_type;
    uint8_t pkt_buf[DNS_MAX_PDUSIZE];
    char emsg[DNS_EMSG_MAXLEN];
    // last tid sent
    uint16_t tid_sent;
    size_t pkt_len;
    // connetion
    size_t sent_len;
    size_t recv_len;
    struct timespec ts_sent;
    struct timespec ts_recv;
    struct sockaddr_storage sock_addr;
    socklen_t sock_addr_len;
    int sock_fd;
    // flags
    unsigned int is_tcp    : 1;
    unsigned int sock_err   : 1;
    unsigned int recv_close : 1;
    unsigned int log_msg    : 1;
};


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

int gen_signals(struct dns_gen *gen)
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

// util funcs
static double time_diff_ms(struct timespec *begin, struct timespec *end)
{
    double diff_sec = end->tv_sec  - begin->tv_sec;
    double diff_nsec = end->tv_nsec - begin->tv_nsec;
    return (diff_sec * 1000.0) + (diff_nsec / 1000000.0);
}

/* rfc1071 - Internet checksum implementation
   Compute Internet Checksum for "count" bytes
   beginning at location "addr".
*/
static uint16_t ip_checksum(const void *vaddr, size_t count) 
{
    const uint8_t *addr = vaddr;
    uint32_t sum = 0;

    while (count > 1)  {
        // This is the inner loop
        uint16_t tmp = (addr[0] << 8) | addr[1];
        sum += tmp;
        addr += 2;
        count -= 2;
    }

    //  Add left-over byte, if any
    if (count > 0) {
        sum += *((const uint8_t *) addr);;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t) ~sum;
}

static int get_dns_type(struct str_slice str)
{
    if (slice_cmp_cstr(str, STR_LIT("A")))  return DNS_TYPE_A;
    if (slice_cmp_cstr(str, STR_LIT("NS")))  return DNS_TYPE_NS;
    if (slice_cmp_cstr(str, STR_LIT("CNAME")))  return DNS_TYPE_CNAME;
    if (slice_cmp_cstr(str, STR_LIT("SOA")))  return DNS_TYPE_SOA;
    if (slice_cmp_cstr(str, STR_LIT("PTR")))  return DNS_TYPE_PTR;
    if (slice_cmp_cstr(str, STR_LIT("HINFO")))  return DNS_TYPE_HINFO;
    if (slice_cmp_cstr(str, STR_LIT("MX")))  return DNS_TYPE_MX;
    if (slice_cmp_cstr(str, STR_LIT("TXT")))  return DNS_TYPE_TXT;
    if (slice_cmp_cstr(str, STR_LIT("AAAA")))  return DNS_TYPE_AAAA;
    if (slice_cmp_cstr(str, STR_LIT("SRV")))  return DNS_TYPE_SRV;

    return 0;
}

static int get_dns_class(struct str_slice str)
{
    if (slice_cmp_cstr(str, STR_LIT("IN")))  return DNS_CLASS_IN;
    if (slice_cmp_cstr(str, STR_LIT("CS")))  return DNS_CLASS_CS;
    if (slice_cmp_cstr(str, STR_LIT("CH")))  return DNS_CLASS_CH;
    if (slice_cmp_cstr(str, STR_LIT("HS")))  return DNS_CLASS_HS;
    if (slice_cmp_cstr(str, STR_LIT("ANY")))  return DNS_CLASS_ANY;

    return 0;
}

static int get_dns_flag(struct str_slice str)
{
    if (slice_cmp_cstr(str, STR_LIT("CD")))  return DNS_FLAGS_CD;
    if (slice_cmp_cstr(str, STR_LIT("RD")))  return DNS_FLAGS_RD;
    if (slice_cmp_cstr(str, STR_LIT("AD")))  return DNS_FLAGS_AD;

    return 0;
}

static int get_fuzz_type(struct str_slice str)
{
    if (slice_cmp_cstr(str, STR_LIT("trunc-hdr")))  return FUZZ_HDR;
    if (slice_cmp_cstr(str, STR_LIT("comp-loop"))) return FUZZ_COMP;
    if (slice_cmp_cstr(str, STR_LIT("trunc")))  return FUZZ_TRUNC;
    if (slice_cmp_cstr(str, STR_LIT("labels"))) return FUZZ_LABELS;
    if (slice_cmp_cstr(str, STR_LIT("opcode"))) return FUZZ_OPCODE;
    if (slice_cmp_cstr(str, STR_LIT("rcode")))  return FUZZ_RCODE;

    return 0;
}

int ipaddrstr_toraw(void *addr, size_t len, struct str_slice str)
{
    char addrstr[INET6_ADDRSTRLEN];

    memcpy(addrstr, str.ptr, str.len);
    addrstr[str.len] = '\0';

    if (inet_pton(AF_INET, addrstr, addr) == 1) return 4;
    if (inet_pton(AF_INET6, addrstr, addr) == 1) return 6;

    return -1;
}

static uint16_t get_dns_flags(uint16_t flags, struct str_slice flags_str)
{
    while (flags_str.len) {
        struct str_slice flag = slice_split(&flags_str, '|');
        slice_trim(&flag);
        struct str_slice on_off = slice_rsplit(&flag, ':');
        slice_trim(&on_off);
        uint16_t mask = get_dns_flag(flag);
        if (mask && on_off.len) {
            if (*on_off.ptr == '0') {
                flags &= ~mask;
            }
            else if (*on_off.ptr == '1') {
                flags |= mask;
            }
        }
    }

    return flags;
}


/*
 * Figure out the record
 * =====================
 *  addr =  ip4addr|ip6addr|regname [<ttl>] [class=IN|CS|CH|HS]
 */
static int gen_load_rec(struct dns_gen *gen, struct dns_rec *rec, struct str_slice str)
{
    // get addr
    struct str_slice addr = slice_split(&str, ' ');
    slice_trim(&addr);
    if (addr.len > DNS_NAME_MAXSTR) {
        return log_error_rf("<addr> string len %zu bigger than max %d", addr.len, DNS_NAME_MAXSTR);
    }

    // need a copy for inet_pton call
    char addr_str[DNS_NAME_MAXLEN];
    memcpy(addr_str, addr.ptr, addr.len);
    addr_str[addr.len] = '\0';

    // start answer
    uint8_t addr_raw[DNS_NAME_MAXLEN];

    // set defaults
    rec->name = gen->dns_name;
    rec->class = gen->dns_class;
    rec->ttl = gen->ttl;

    // parse addr_str (ip4|ip6|name)
    if (inet_pton(AF_INET, addr_str, addr_raw) == 1) {
        // IPv4
        rec->type = DNS_TYPE_A;
        memcpy(rec->data.a, addr_raw, 4);
    }
    else if (inet_pton(AF_INET6, addr_str, addr_raw) == 1) {
        // IPv6
        rec->type = DNS_TYPE_AAAA;
        memcpy(rec->data.aaaa, addr_raw, 16);
    }
    else {
        // regname
        rec->type = DNS_TYPE_CNAME;
        rec->data.cname = addr_str;
    }
    
    // look for remaining attrs (e.g 3600 CH)
    while (str.len) {
        struct str_slice attr = slice_split(&str, ' ');
        slice_trim(&attr);
        int dns_class = get_dns_class(attr);
        if (dns_class != 0) {
            rec->class = dns_class;
        }
        else if (slice_isnumeric(attr)) {
            rec->ttl = atol(attr.ptr);
        }
    }

    // all done
    return 0;
}

static int gen_add_an(struct dns_gen *gen, struct str_slice str)
{
    struct dns_rec ans_rec = { 0 };

    int rc = gen_load_rec(gen, &ans_rec, str);
    if (rc) return rc;

    return dns_msg_add_an(&gen->send_msg, &ans_rec);
}

static int gen_add_ns(struct dns_gen *gen, struct str_slice str)
{
    struct dns_rec auth_rec = { 0 };

    int rc = gen_load_rec(gen, &auth_rec, str);
    if (rc) return rc;

    return dns_msg_add_ns(&gen->send_msg, &auth_rec);
}

static int gen_add_ar(struct dns_gen *gen, struct str_slice str)
{
    struct dns_rec ar_rec = { 0 };

    int rc = gen_load_rec(gen, &ar_rec, str);
    if (rc) return rc;

    return dns_msg_add_ar(&gen->send_msg, &ar_rec);
}

static void gen_print_rec(struct dns_gen *gen, struct dns_rec *rec)
{
    int nw = dns_rec_tostr(rec, gen->emsg, sizeof(gen->emsg));
    if (nw) printf("%s\n", gen->emsg);
}

static void gen_print_sect(struct dns_gen *gen, struct dns_sect *sect)
{
    for (int i = 0; i < sect->num_rec; i++) {
        gen_print_rec(gen, &sect->rec[i]);
    }
}

static void gen_print_msg(struct dns_gen *gen, struct dns_msg *msg)
{
    struct dns_rec *rec = dns_msg_get_rec(msg);

    if (rec) {
        gen_print_rec(gen, rec);
    }
    else if (dns_msg_cnt_rec(msg) == 0) {
        printf("<None>\n");
    }
    else {
        printf("\n");
        gen_print_sect(gen, &msg->an_recs);
        gen_print_sect(gen, &msg->ns_recs);
        gen_print_sect(gen, &msg->ar_recs);
    }
}

static int sock_read(struct dns_gen *gen, void *buf, size_t buf_len)
{
    // joker check
    if (gen->sock_err) return SOCK_ERROR;
    if (gen->recv_close) return SOCK_CLOSED;

    uint8_t *buf_ptr = buf;
    size_t tread = 0;

    while (tread < buf_len) {

        ssize_t nread = recv(gen->sock_fd, buf_ptr, buf_len, 0);
        if (nread < 0) {
            // read failed
            int ec = SOCK_ERROR;
            gen->sock_err = 1;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // recive timeout
                ec = SOCK_TIMEOUT;
            }
            else if (errno != EINTR) {
                // general error
                log_errno("recvfrom fd=%d failed", gen->sock_fd);
            }
            // stop read
            return ec;
        }

        if (nread == 0) {
            // peer closed
            gen->recv_close = 1;
            return SOCK_CLOSED;
        }

        // update read buffer
        gen->recv_len += nread;
        buf_ptr += nread;
        buf_len -= nread;
        tread += nread;

        // UDP is one shot
        if (!gen->is_tcp) break;
    }

    // have data
    return SOCK_DATA;
}

static int sock_write(struct dns_gen *gen, void *buf, size_t buf_len)
{
    struct sockaddr *sock_addr = (struct sockaddr *) &gen->sock_addr;
    socklen_t addr_len = gen->sock_addr_len;

    ssize_t nsent = sendto(gen->sock_fd, buf, buf_len, 0, sock_addr, addr_len);
    if (nsent < 0) {
        // write failed
        int ec = SOCK_ERROR;
        gen->sock_err = 1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // write timeout
            ec = SOCK_TIMEOUT;
        }
        else if (errno != EINTR) {
            // general error
            log_errno("recvfrom fd=%d failed", gen->sock_fd);
        }
        return ec;
    }

    // update write buffer
    gen->sent_len += nsent; 

    // data writen
    return SOCK_DATA;
}

static int send_dns_pdu(struct dns_gen *gen)
{ 
    uint8_t *pkt = gen->pkt_buf;
    size_t pkt_len = gen->pkt_len;

    gen->sent_len = 0;

    if (gen->is_tcp) {
        // send the 2 byte dns prefix
        uint16_t dns_len = ntohs(pkt_len);
        int rc = sock_write(gen, &dns_len, sizeof(dns_len));
        if (rc != SOCK_DATA) return rc;
        if (gen->sent_len != sizeof(dns_len)) {
            // should not happen ?
            return SOCK_ERROR;
        }
    }

    // send pdu
    int rc = sock_write(gen, pkt, pkt_len);
    if (rc != SOCK_DATA) return rc;

    return 0;
}

static int recv_dns_pdu(struct dns_gen *gen)
{
    size_t read_len = sizeof(gen->pkt_buf);

    gen->recv_len = 0;

    if (gen->is_tcp) {
        // read 2-byte prefix
        uint16_t dns_len;
        int rc = sock_read(gen, &dns_len, sizeof(dns_len));
        if (rc != SOCK_DATA) return rc;
        if (gen->recv_len != sizeof(dns_len)) {
            // should not happen ?
            return SOCK_ERROR;
        }
        read_len = ntohs(dns_len);
        gen->recv_len = 0;
    }

    // read the PDU
    int rc = sock_read(gen, gen->pkt_buf, read_len);
    if (rc != SOCK_DATA) return rc;

    // read a message
    if (clock_gettime(CLOCK_MONOTONIC, &gen->ts_recv) != 0) {
        log_errno("clock_gettime ts_recv failed");
        // keep going ?
    }

    return 0;
}

static int gen_connect(struct dns_gen *gen)
{
    // resolve hostname+ port string to list of (ip+port)
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = gen->is_tcp ? SOCK_STREAM : SOCK_DGRAM;
    const char *port = "53";

    int rc = getaddrinfo(gen->serv_addr, port, &hints, &res);
    if (rc != 0) {
        return log_error_rf("getaddrinfo(%s,%s) : %s\n", gen->serv_addr, port, gai_strerror(rc));
    }

    // get a UDP or TCP connection
    int sock_fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock_fd == -1) continue;
        if (!gen->is_tcp) break;
        rc = connect(sock_fd, ai->ai_addr, ai->ai_addrlen);
        if (rc != -1) break;
        log_errno("connect(%s:%s) failed", gen->serv_addr, port);
        close(sock_fd);
        sock_fd = -1;
    }

    // connect failed
    if (sock_fd == -1) {
        freeaddrinfo(res);
        return log_error_rf("Connect to %s:%s failed", gen->serv_addr, port);
    }

    // connected
    memcpy(&gen->sock_addr, res->ai_addr, res->ai_addrlen);
    gen->sock_addr_len = res->ai_addrlen;
    gen->sock_fd = sock_fd;
    freeaddrinfo(res);

    // set send and receive timeout
    struct timeval tv = {
        .tv_sec = gen->timeout
    };
    if (setsockopt(gen->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
        return log_errno_rf("setsockopt SO_SNDTIMEO on %d failed", gen->sock_fd);
    }
    if (setsockopt(gen->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        return log_errno_rf("setsockopt SO_RCVTIMEO on %d failed", gen->sock_fd);
    }

    printf("Connected to %s\n", gen->serv_addr);

    // all done
    return 0;
}

// encode send msg into pkt buffer
static int gen_msg_encode(struct dns_gen *gen)
{
    uint8_t *wptr = gen->pkt_buf + gen->pkt_len;
    size_t  wlen = sizeof(gen->pkt_buf) - gen->pkt_len;
    ssize_t pkt_len = dns_msg_encode(&gen->send_msg, wptr, wlen);

    if (pkt_len <= 0) {
        // encoder failed ?
        return SOCK_ENCODE;
    }

    gen->pkt_len += pkt_len;

    return 0;
}

static int gen_pcap_rec(struct dns_gen *gen)
{
    gen->pcap = pcap_open(gen->output, PCAP_WRITE);
    if (!gen->pcap) return -1;

    int rc = pcap_write(gen->pcap, gen->pkt_buf, gen->pkt_len);
    if (rc) return rc;

    rc = pcap_close(gen->pcap);
    gen->pcap = NULL;
    if (rc) return rc;

    return 0;
}

// make space for ETH+IP+UDP headers
static void pcap_start_pkt(struct dns_gen *gen)
{
    gen->pkt_len = ETHIPUDP_LEN;
}

// encode ETH+IP+UDP headers
static void pcap_end_pkt(struct dns_gen *gen)
{
    size_t start = ETHIPUDP_LEN;
    uint8_t *wptr = gen->pkt_buf + start;
    uint16_t msg_len = gen->pkt_len - start;

    // rewind to UDP header
    struct udphdr udp = {
        .source = htons(53),
        .dest = htons(53),
        .len = htons(8 + msg_len)
    };
    wptr -= sizeof(udp);
    memcpy(wptr, &udp, sizeof(udp));
   
    // rewind to IPv4 header
    struct iphdr ip = { 
        .version = 4, 
        .ihl = 5, 
        .ttl = 255,
        .tot_len = htons(msg_len + 8 + 20),
        .protocol = IPPROTO_UDP
    };

    ip.check = ip_checksum(&ip, sizeof(ip));
    ip.check = htons(ip.check);

    wptr -= sizeof(ip);
    memcpy(wptr, &ip, sizeof(ip));

    // rewind to Ethernet header
    struct ethhdr eth = { 
         .h_dest   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }, 
         .h_source = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 
        .h_proto = htons(ETH_P_IP) 
    };
    wptr -= sizeof(eth);
    memcpy(wptr, &eth, sizeof(eth));
}


static int gen_msg_chk(struct dns_gen *gen)
{
    if (!gen->log_msg) return 0;

    int rc = validate_dns_packet(gen->pkt_buf, gen->pkt_len, gen->emsg);
    log_msg(gen->emsg);

    return rc;
}

static int gen_send_query(struct dns_gen *gen)
{
    // next tid
    gen->send_msg.hdr.id = rand() % 65536;

    int rc = gen_msg_encode(gen);
    if (rc) return rc;

    // log/check DNS msg
    rc = gen_msg_chk(gen);
    if (rc) return rc;

    // tell user
    printf("Send query (%s) ID:0x%04x for %s %s %s\n", 
        gen->is_tcp ? "TCP" : "UDP",
        gen->send_msg.hdr.id, str_def(gen->dns_name, "<null>"),
        dns_class_tostr(gen->dns_class),
        dns_type_tostr(gen->dns_type));

    // send DNS msg
    rc = send_dns_pdu(gen);
    if (rc) return rc;

    // sent
    if (clock_gettime(CLOCK_MONOTONIC, &gen->ts_sent) != 0) {
        log_errno("clock_gettime ts_sent failed");
        // keep going ?
    }

    return 0;
}


static int gen_recv_resp(struct dns_gen *gen)
{
    int rc = recv_dns_pdu(gen);
    if (rc) {
        // recv failed ?
        const char *etype = "ERROR";
        const char *emsg = "rejected/ignored";
        switch(rc) {
        case SOCK_CLOSED: emsg = "closed"; break;
        case SOCK_ERROR:  emsg = "rejected/ignored"; break;
        case SOCK_TIMEOUT: etype = "TIMEOUT";  break;
        default: etype = NULL; // ignore
        }
        if (etype) {
            printf("[%s] server %s\n", etype, emsg);
        }
        // stop reading
        return rc;
    }

    struct dns_msg msg = { 0 };
    rc = dns_msg_decode(&msg, gen->pkt_buf, gen->recv_len);
    if (rc) return rc;

    // check msg is response
    struct dns_header *hdr = &msg.hdr;
    if ((hdr->flags & DNS_FLAGS_QR) == 0) {
        return log_info_rz("dns-gen", 
            "Unexpected DNS message ID: 0x%04x Flags: 0x%04x Len %zu",
            hdr->id, hdr->flags, gen->recv_len);
    }

    // check Transaction ID
    if (hdr->id != gen->tid_sent) {
        return log_info_rz("dng-gen",
            "Response ID 0x%04x does not match Request ID 0x%04x", 
            hdr->id, gen->tid_sent);
    }

    // check Result Code
    int rcode = hdr->flags & DNS_FLAGS_RCODE;
    if (rcode != DNS_RCODE_NOERROR) {
        return log_info_rz("dng-gen", 
            "Response ID 0x%04x failed with error %s", 
            hdr->id, rcode_tostr(rcode));
    }

    double delta_ms = time_diff_ms(&gen->ts_sent, &gen->ts_recv);

    printf("Received response in %ums: ", (uint32_t) delta_ms);

    gen_print_msg(gen, &msg);

    return 0;
}


static int gen_recv_badmsg(struct dns_gen *gen)
{
    return -1;
}

static int gen_send_badmsg(struct dns_gen *gen)
{
    return -1;
}

static int gen_do_query(struct dns_gen *gen)
{
    int rc = gen_connect(gen);
    if (rc) return rc;

    rc = gen_send_query(gen);
    if (rc) return rc;

    rc = gen_recv_resp(gen);
    if (rc) return rc;

    return 0;
}

static int gen_mkbadmsg(struct dns_gen *gen)
{
    uint8_t *start = gen->pkt_buf + gen->pkt_len;
    uint8_t *wptr = start;
    struct dns_header hdr = { 0 };

    switch(gen->fuzz_type) {
    case FUZZ_HDR:
        wptr += 10;
        break;
    case FUZZ_COMP:
        break;
    case FUZZ_TRUNC:
        break;
    case FUZZ_LABELS:
        break;
    case FUZZ_OPCODE:
        hdr.flags = 6  << 11;
        hdr.flags = ntohs(hdr.flags);
        memcpy(wptr, &hdr, sizeof(hdr));
        wptr += DNS_HDR_LEN;
        break;
    case FUZZ_RCODE:
        hdr.flags = DNS_FLAGS_QR;
        hdr.flags |= 11;
        hdr.flags = ntohs(hdr.flags);
        memcpy(wptr, &hdr, sizeof(hdr));
        wptr += DNS_HDR_LEN;
        break;
    }

    // add msg length to pkt len
    gen->pkt_len += wptr - start;

    return 0;
}

static int gen_do_fuzz(struct dns_gen *gen)
{
    int rc;

    if (gen->output) {
        pcap_start_pkt(gen);
        rc = gen_mkbadmsg(gen);
        if (rc) return rc;
        pcap_end_pkt(gen);
        rc = gen_pcap_rec(gen);
        printf("Wrote %zu bytes to %s\n", gen->pkt_len - ETHIPUDP_LEN, gen->output);
    }
    else {
        rc = gen_mkbadmsg(gen);
        rc = gen_connect(gen);
        if (rc) return rc;
        rc = gen_send_badmsg(gen);
        if (rc) return rc;
        rc = gen_recv_badmsg(gen);
    }

    return rc;
}

static int gen_setup_fuzz(void *state, int narg, struct str_slice args[])
{
    struct dns_gen *gen = state;
    const char *cmd = "fuzz";

    gen->mode = MODE_FUZZ;

    for (int i = 0; i < narg; i++) {
        struct str_slice opt = args[i];
        if (slice_cmp_cstr(opt,  STR_LIT("--type"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--type <Type>", "requires an argument");
            }
            struct str_slice val = args[++i];
            gen->fuzz_type = get_fuzz_type(val);
            if (!gen->fuzz_type) {
                return log_cmd_err(cmd, "--type", "Must be one of trunc-hdr|comp-loop|opcode|rcode");
            }
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--server"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--server <ip-addr>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--server <ip-addr>", "cannot be blank");
            if (gen->serv_addr) free(gen->serv_addr);
            gen->serv_addr = slice_strdup(val); 
            if (!gen->serv_addr) return log_errno_rf("copy ip_add failed");
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--output"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--output <FileName>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--output <FileName>", "cannot be blank");
            if (gen->output) free(gen->output);
            gen->output = slice_strdup(val);
            if (!gen->output) {
                return log_errno_rf("strdup failed for --output");
            }
        }
        else {
            return log_cmd_err(cmd, "unknown option", "%.*s", SLICE(opt));
        }
    }

    if (!gen->fuzz_type) {
        return log_cmd_err(cmd, "--type <Type>", "is required");
    }
    if (!gen->serv_addr && !gen->output) {
        return log_cmd_err(cmd, "--server or --output", "is required");
    }

    // all done
    return 0;
}

static int gen_do_resp(struct dns_gen *gen)
{
    pcap_start_pkt(gen);
    int rc = gen_msg_encode(gen);
    if (rc) return rc;
    pcap_end_pkt(gen);

    rc = gen_pcap_rec(gen);
    if (rc) return rc;

    printf("Wrote %zu bytes to %s\n", gen->pkt_len - ETHIPUDP_LEN, gen->output);

    return 0;
}

static int gen_setup_resp(void *state, int narg, struct str_slice args[])
{
    struct dns_gen *gen = state;
    const char *cmd = "query";

    gen->mode = MODE_RESP;

    for (int i = 0; i < narg; i++) {
        struct str_slice opt = args[i];
        if (slice_cmp_cstr(opt,  STR_LIT("--id"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--id <id>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--id <id>", "cannot be blank");
            gen->id = (uint16_t) strtol(val.ptr, NULL, 0);
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--name"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--name <DNS-name>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--name <dns-name>", "cannot be blank");
            if (val.len > DNS_NAME_MAXSTR) return log_cmd_err(cmd, "--name <dns-name>", "name too big");
            memcpy(gen->dns_name, val.ptr, val.len);
            gen->dns_name[val.len] = '\0';
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--answer"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--answer <Answer>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--answer <Answer>", "cannot be blank");
            if (gen_add_an(gen, val) != 0) {
                return log_cmd_err(cmd, "--answer <answer>", "Bad format");
            }
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--authority"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--authority <Authority>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--answer <Authority>", "cannot be blank");
            if (gen_add_ns(gen, val) != 0) {
                return log_cmd_err(cmd, "--answer <answer>", "Bad format");
            }
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--additional"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--additional <Additional>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--Additional <Additional>", "cannot be blank");
            if (gen_add_ar(gen, val) != 0) {
                return log_cmd_err(cmd, "--additional <Additional>", "Bad format");
            }
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--ttl"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--ttl <ttl>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--ttl <id>", "cannot be blank");
            gen->ttl = (uint32_t) strtol(val.ptr, NULL, 16);
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--flags"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--class <dns-class>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--flags <dns-flags>", "Must look like AD:0|CD:0|RD:0");
            gen->dns_flags = get_dns_flags(gen->dns_flags, slice_toupper(val));
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--output"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--output <FileName>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--output <FileName>", "cannot be blank");
            if (gen->output) free(gen->output);
            gen->output = slice_strdup(val);
            if (!gen->output) {
                return log_errno_rf("strdup failed for --output");
            }
        }
        else {
            return log_cmd_err(cmd, "unknown option", "%.*s", SLICE(opt));
        }
    }

    // check required args
    if (!*gen->dns_name)  {
        return log_cmd_err(cmd, "--name <dns-name>", "is required");
    }
    if (!dns_msg_cnt_rec(&gen->send_msg)) {
        return log_cmd_err(cmd, "--answer | --authority | --additional", "is required");
    }
    if (!gen->output) {
        return log_cmd_err(cmd, "--output <file>", "is required");
    }

    // setup msg now
    dns_msg_set_id_flags(&gen->send_msg, gen->id, gen->dns_flags);

    // all done
    return 0;
}


static int gen_setup_query(void *state, int narg, struct str_slice args[])
{
    struct dns_gen *gen = state;
    const char *cmd = "query";

    gen->mode = MODE_QUERY;
    gen->dns_flags = DNS_FLAGS_RD;
    gen->dns_class = DNS_CLASS_IN;

    for (int i = 0; i < narg; i++) {
        struct str_slice opt = args[i];
        if (slice_cmp_cstr(opt,  STR_LIT("--name"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--name <dns-name>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--name <dns-name>", "cannot be blank");
            if (val.len > DNS_NAME_MAXSTR) return log_cmd_err(cmd, "--name <dns-name>", "name too big");
            memcpy(gen->dns_name, val.ptr, val.len);
            gen->dns_name[val.len] = '\0';
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--type"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--type <dns-type>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--type <dns-type>", "cannot be blank");
            gen->dns_type = get_dns_type(slice_toupper(val));
            if (!gen->dns_type) return log_cmd_err(cmd, "--type <dns-type>", "Value Must be one of A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV");
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--class"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--class <dns-class>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--type <dns-type>", "cannot be blank");
            gen->dns_class = get_dns_class(slice_toupper(val));
            if (!gen->dns_class) return log_cmd_err(cmd, "--type <dns-type>", "Value Must be one of IN|CS|CH|HS|ANY");
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--flags"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--flags <Flags>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--flags <Flags>", "Must look like AD:0|CD:0|RD:0");
            gen->dns_flags = get_dns_flags(gen->dns_flags, slice_toupper(val));
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--server"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--server <ip-addr>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--server <ip-addr>", "cannot be blank");
            if (gen->serv_addr) free(gen->serv_addr);
            gen->serv_addr = slice_strdup(val); 
            if (!gen->serv_addr) return log_errno_rf("copy ip_add failed");
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--timeout"))) {
            if (i == narg - 1) return log_cmd_err(cmd, "--timeout <TimeOut>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--timeout <TimeOuts>", "Cannot be blank");
            gen->timeout = (uint16_t) strtol(val.ptr, NULL, 0);
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--tcp"))) {
            gen->is_tcp = 1;
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--log"))) {
            gen->log_msg = 1;
        }
        else {
            return log_cmd_err(cmd, "unknown option", "%.*s", SLICE(opt));
        }
    }

    // min args check
    if (!*gen->dns_name) return log_cmd_err(cmd, "--name <dns-name>", "is required");
    if (!gen->serv_addr) return log_cmd_err(cmd, "--server <ip-addr>", "is required");

    // set up 
    dns_msg_set_id_flags(&gen->send_msg, 0, gen->dns_flags);
    int rc = dns_msg_add_qd(&gen->send_msg, gen->dns_name, gen->dns_class, gen->dns_type);
    if (rc) return rc;

    return 0;
}

static int gen_usage(void *state, struct str_slice prog_name)
{
    FILE *out = stderr;
    int w= 10;

    fprintf(out,"Usage: %.*s [MODE] [OPTIONS]\n\n", SLICE(prog_name));

    fprintf(out, "MODE:\n");
    fprintf(out, "  %-*s %s\n", w, "query", "--name <dns-name> --type <rec-type> --server <ip-addr> --flags <Flags> --timeout <TimeOut> --tcp");
    fprintf(out, "  %-*s %s\n", w, "fuzz", "--type <rec-type> --server <ip-addr>");
    fprintf(out, "  %-*s %s\n", w, "response", "--id <trans-id> --name <dns-name> --answer <Ans> --output <pcap-file> --authority <Auth>");

    fprintf(out, "\nExample:\n");
    fprintf(out, "  %.*s query --name example.com --type A --server 8.8.8.8\n", SLICE(prog_name));
    fprintf(out, "  %.*s query --name example.com --type A --server 8.8.8.8 --flags 'AD:1|CD:1|RD:0'\n", SLICE(prog_name));
    fprintf(out, "  %.*s fuzz --type compression-loop --server 127.0.0.1\n", SLICE(prog_name));
    fprintf(out, "  %.*s response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin\n", SLICE(prog_name));

    return -1;
}

static struct util_cmd cmds[] =  {
    { STR_LIT("query"), gen_setup_query },
    { STR_LIT("fuzz"),  gen_setup_fuzz },
    { STR_LIT("response"),  gen_setup_resp },
};

static int gen_parse_argv(struct dns_gen *gen, int argc, char *argv[])
{
    return util_parse_argv(gen, argc, argv, ARRAY(cmds), gen_usage);
}

void gen_free(struct dns_gen *gen)
{
    if (gen->sock_fd != -1) {
        close(gen->sock_fd);
    }

    if (gen->output) free(gen->output);
    if (gen->pcap) pcap_close(gen->pcap);

    free(gen);
}

static int gen_init(struct dns_gen *gen)
{
    memset(gen, 0, sizeof(*gen));
    gen->sock_fd = -1;

    // needed for tids
    srand(time(NULL));

    return 0;
}

struct dns_gen *gen_create(void)
{
    struct dns_gen *gen;

    gen = malloc(sizeof(*gen));
    if (!gen) {
        return log_errno_rn("Malloc failed for gen state");
    }

    return gen;
}

int main(int argc, char *argv[])
{
    struct dns_gen *gen = NULL;
    int ec = 0;

    if (!(gen = gen_create())) { ec = 1; goto done; }
    if (gen_init(gen)) { ec = 2; goto done; }
    if (gen_parse_argv(gen, argc, argv)) { ec = 3;  goto done; }
    if (gen_signals(gen))  { ec = 4 ; goto done; }

    switch(gen->mode) {
    case MODE_QUERY: if (gen_do_query(gen)) ec = 5; break;
    case MODE_RESP:  if (gen_do_resp(gen))  ec = 6; break;
    case MODE_FUZZ:  if (gen_do_fuzz(gen))  ec = 7;  break;
    default:
        log_error("Unsupported mode %d", gen->mode);
        ec = 8;
    }

done:
    if (gen) gen_free(gen);

    return ec;
}
