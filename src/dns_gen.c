/*
 * dns-gen  :  DNS packet generator
 * Usage:   : ./dns-gen --help
 * Example  : ./dns-gen query --name example.com --type A --server 8.8.8.8
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
#include "log.h"
#include "pcap.h"
#include "dns_proto.h"

#define GEN_FAIL -1
#define MSG_TIMEOUT 5

// socker errors
#define SOCK_NONE     0
#define SOCK_DATA     1
#define SOCK_CLOSED  -1
#define SOCK_ERROR   -2
#define SOCK_TIMEOUT -3
#define SOCK_ENCODE  -4

// supported cmds
#define MODE_NONE  0
#define MODE_QUERY 1
#define MODE_RESP  2
#define MODE_FUZZ  3

#define FUZZ_HDR_TRUNC   1
#define FUZZ_HDR_OPCODE  2
#define FUZZ_HDR_RCODE   3
#define FUZZ_HDR_QDCNT   4
#define FUZZ_QD_CMPLOOP  5
#define FUZZ_QD_BADJMP   6

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
    struct dns_msg send; 
    struct dns_msg recv;
    uint32_t timeout; // send / recv message timeout 
    int fuzz_type;
    uint8_t pkt_buf[DNS_MAX_PDUSIZE];
    char emsg[DNS_EMSG_MAXLEN];
    // last tid sent
    uint16_t tid_sent;
    size_t pkt_len;
    // connection
    size_t sent_len;
    size_t recv_len;
    struct timespec ts_sent;
    struct timespec ts_recv;
    struct sockaddr_storage sock_addr;
    socklen_t sock_addr_len;
    int sock_fd;
    // flags
    unsigned int is_tcp     : 1;
    unsigned int sock_err   : 1;
    unsigned int recv_close : 1;
    unsigned int log_msg    : 1;
    unsigned int use_pcapng : 1;
};


// signal handling
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t caught_signo = 0; 
static volatile sig_atomic_t sender_pid = 0; 
static volatile sig_atomic_t sender_uid = 0; 

static void catch_signal(int signo, siginfo_t *info, void *ucontext)
{
    (void) ucontext;
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
    (void) (gen);
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

static int get_fuzz_type(const char *str)
{
    if (!strncasecmp(str, STR_LIT("hdr-trunc")))  return FUZZ_HDR_TRUNC;
    if (!strncasecmp(str, STR_LIT("hdr-opcode"))) return FUZZ_HDR_OPCODE;
    if (!strncasecmp(str, STR_LIT("hdr-rcode")))  return FUZZ_HDR_RCODE;
    if (!strncasecmp(str, STR_LIT("hdr-qdcnt")))  return FUZZ_HDR_QDCNT;
    if (!strncasecmp(str, STR_LIT("qd-cmploop"))) return FUZZ_QD_CMPLOOP;
    if (!strncasecmp(str, STR_LIT("qd-badjmp")))  return FUZZ_QD_BADJMP;

    return 0;
}

static inline uint8_t *enc_u16(uint8_t *wptr, uint16_t value)  
{
    *wptr++ = value >> 8;
    *wptr++ = value;
    return wptr;
}

static int get_dns_class(struct str_slice str)
{
    char tmp[10];
    size_t len = min(sizeof(tmp) - 1, str.len);
    memcpy(tmp, str.ptr, len);

    return dns_get_class(tmp);
}

static int get_dns_flag(struct str_slice str)
{
    char tmp[10];
    size_t len = min(sizeof(tmp) - 1, str.len);
    memcpy(tmp, str.ptr, len);
    return dns_get_flag(tmp);
}


/*
 * Figure out the record
 * =====================
 *  addr =  ip4addr|ip6addr|regname [<ttl>] [class=IN|CS|CH|HS]
 */
static int gen_load_rec(struct dns_gen *gen, struct dns_rec *rec, const char *astr)
{
    struct str_slice str = slice_make_cstr(RMCONST(char *, astr));

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


    // set defaults
    rec->name = gen->dns_name;
    rec->class = gen->dns_class;
    rec->ttl = gen->ttl;

    // parse addr_str (ip4|ip6|name)
    uint8_t addr_raw[DNS_NAME_MAXLEN];
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

static int gen_print_dnsrsp(struct dns_gen *gen)
{
    struct dns_msg *rsp = &gen->recv;
    struct dns_rec *rec = dns_msg_get_rec(rsp);

    char *desc = gen->emsg;
    *desc = '\0';
    if (rec) {
        int rc = dns_rec_tostr(rec, 0, desc, sizeof(gen->emsg));
        if (rc < 0) return rc;
    }
    else if (dns_msg_cnt_rec(rsp) == 0) {
        desc = "<None>";
    }
    else {
        printf("\n");
        int rc = dns_msg_sects_tostr(rsp, desc, sizeof(gen->emsg));
        if (rc) return rc;
    }

    int nw = printf("%s\n", desc);
    if (nw < 0) {
        log_errno("printf failed!");
        return GEN_FAIL;
    }

    return 0;
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

static int gen_send_dnspdu(struct dns_gen *gen)
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

static int gen_recv_err(struct dns_gen *gen, int err)
{
    (void) gen;
    const char *etype = "ERROR";
    const char *emsg = "rejected/ignored";

    switch(err) {
    case SOCK_CLOSED:  emsg  = "closed"; break;
    case SOCK_ERROR:   emsg  = "rejected/ignored"; break;
    case SOCK_TIMEOUT: etype = "TIMEOUT";  break;
    case SOCK_DATA:    emsg  = "read/write failed"; break;
    default:           etype = NULL; // ignore  ?
    }

    if (etype) {
        printf("[%s] server %s\n", etype, emsg);
    }

    return GEN_FAIL;
}

static int gen_recv_dnspdu(struct dns_gen *gen)
{
    size_t read_len = sizeof(gen->pkt_buf);
    gen->recv_len = 0;

    if (gen->is_tcp) {
        // read 2-byte prefix
        uint16_t dns_len;
        int rc = sock_read(gen, &dns_len, sizeof(dns_len));
        if (rc != SOCK_DATA) {
            return gen_recv_err(gen, rc);
        }
        if (gen->recv_len != sizeof(dns_len)) {
            // should not happen ?
            return gen_recv_err(gen, SOCK_DATA);
        }
        read_len = ntohs(dns_len);
        gen->recv_len = 0;
    }

    // read the PDU
    int rc = sock_read(gen, gen->pkt_buf, read_len);
    if (rc != SOCK_DATA) {
        return gen_recv_err(gen, rc);
    }

    // read a message
    rc = clock_gettime(CLOCK_MONOTONIC, &gen->ts_recv);
    if (rc != 0) {
        // keep going ?
        log_errno("clock_gettime ts_recv failed");
    }

    // all done
    return 0;
}

static int gen_serv_connect(struct dns_gen *gen)
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

    //printf("Connected to %s\n", gen->serv_addr);

    // all done
    return 0;
}

// encode send msg into packet buffer
static int gen_enc_dnsmsg(struct dns_gen *gen)
{
    uint8_t *wptr = gen->pkt_buf + gen->pkt_len;
    size_t  wlen = sizeof(gen->pkt_buf) - gen->pkt_len;

    ssize_t pkt_len = dns_msg_encode(&gen->send, wptr, wlen);

    if (pkt_len <= 0) {
        // encoder failed ?
        return SOCK_ENCODE;
    }

    gen->pkt_len += pkt_len;

    return 0;
}

// decode packet buffer into recv msg
static int gen_dec_dnsmsg(struct dns_gen *gen)
{
    int rc = dns_msg_decode(&gen->recv, gen->pkt_buf, gen->recv_len);
    if (rc) return rc;

    return 0;
}

static int gen_pcap_rec(struct dns_gen *gen)
{
    uint32_t flags = PCAP_WRITE;
    if (gen->use_pcapng) flags |= PCAP_FMTNG;

    gen->pcap = pcap_open(gen->output, flags);
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

static int gen_verify_encmsg(struct dns_gen *gen)
{
    if (!gen->log_msg) return 0;

    int rc = validate_dns_packet(gen->pkt_buf, gen->pkt_len, gen->emsg);
    log_msg(gen->emsg);

    return rc;
}

static int gen_send_query(struct dns_gen *gen)
{
    // next tid
    gen->send.hdr.id =  rand() % 65536;

    int rc = gen_enc_dnsmsg(gen);
    if (rc) return rc;

    rc = gen_verify_encmsg(gen);
    if (rc) return rc;

    // tell user
    printf("Send query (%s) ID:0x%04x for %s %s %s\n", 
        gen->is_tcp ? "TCP" : "UDP",
        gen->send.hdr.id, str_def(gen->dns_name, "<null>"),
        dns_class_tostr(gen->dns_class),
        dns_type_tostr(gen->dns_type));

    // send DNS msg
    rc = gen_send_dnspdu(gen);
    if (rc) return rc;

    // sent
    gen->tid_sent = gen->send.hdr.id;
    if (clock_gettime(CLOCK_MONOTONIC, &gen->ts_sent) != 0) {
        log_errno("clock_gettime ts_sent failed");
        // keep going ?
    }

    return 0;
}

static int gen_recv_resp(struct dns_gen *gen)
{
    int rc = gen_recv_dnspdu(gen);
    if (rc) return rc;

    rc = gen_dec_dnsmsg(gen);
    if (rc) return rc;

    // check msg is response
    struct dns_header *recv_hdr = &gen->recv.hdr;
    if ((recv_hdr->flags & DNS_FLAGS_QR) == 0) {
        return log_info_rz("dns-gen", 
            "Unexpected DNS message ID: 0x%04x Flags: 0x%04x Len %zu",
            recv_hdr->id, recv_hdr->flags, gen->recv_len);
    }

    // check Transaction ID
    if (recv_hdr->id != gen->tid_sent) {
        return log_info_rz("dng-gen",
            "Response ID 0x%04x does not match Request ID 0x%04x", 
            recv_hdr->id, gen->tid_sent);
    }

    // check Result Code
    int rcode = recv_hdr->flags & DNS_FLAGS_RCODE;
    if (rcode != DNS_RCODE_NOERROR) {
        return log_info_rz("dng-gen", 
            "Response ID 0x%04x failed with error %s", 
            recv_hdr->id, rcode_tostr(rcode));
    }

    double delta_ms = time_diff_ms(&gen->ts_sent, &gen->ts_recv);
    printf("Received response in %ums: ", (uint32_t) delta_ms);

    gen_print_dnsrsp(gen);

    return 0;
}

static int run_query(struct dns_gen *gen)
{
    int rc = gen_serv_connect(gen);
    if (rc) return rc;

    rc = gen_send_query(gen);
    if (rc) return rc;

    rc = gen_recv_resp(gen);
    if (rc) return rc;

    return 0;
}

static int run_resp(struct dns_gen *gen)
{
    pcap_start_pkt(gen);

    int rc = gen_enc_dnsmsg(gen);
    if (rc) return rc;

    pcap_end_pkt(gen);

    rc = gen_pcap_rec(gen);
    if (rc) return rc;

    printf("Wrote %zu bytes to %s\n", gen->pkt_len - ETHIPUDP_LEN, gen->output);

    return 0;
}

static uint8_t *gen_enc_badhdr(struct dns_gen *gen, uint8_t *wptr, struct dns_header *hdr)
{
    // sync for receive
    gen->tid_sent =  rand() % 65536;
    hdr->id = gen->tid_sent;

    // encode hdr
    hdr->id       = ntohs(hdr->id);
    hdr->flags    = ntohs(hdr->flags);
    hdr->qd_count = ntohs(hdr->qd_count);
    hdr->an_count = ntohs(hdr->an_count);
    hdr->ns_count = ntohs(hdr->ns_count);
    hdr->ar_count = ntohs(hdr->ar_count);

    wptr = mempcpy(wptr, hdr, sizeof(*hdr));
    return wptr;
}

static int gen_enc_badmsg(struct dns_gen *gen)
{
    struct dns_header hdr = { 0 };
    uint8_t *start = gen->pkt_buf + gen->pkt_len;
    uint8_t *wptr = start;

    switch(gen->fuzz_type) {
    case FUZZ_HDR_TRUNC:
        // create truncated header
        wptr += 10;
        break;
    case FUZZ_HDR_OPCODE:
        hdr.flags = 6  << 11;
        wptr = gen_enc_badhdr(gen, wptr, &hdr);
        break;
    case FUZZ_HDR_RCODE:
        hdr.flags = DNS_FLAGS_QR;
        hdr.flags |= 11;
        wptr = gen_enc_badhdr(gen, wptr, &hdr);
        break;
    case FUZZ_HDR_QDCNT:
        // set qd count to 0xffff
        hdr.qd_count = 0xffff;
        wptr = gen_enc_badhdr(gen, wptr, &hdr);
        break;
    case FUZZ_QD_CMPLOOP:
        // encode a Question with a compression ptr loop
        hdr.qd_count = 1;
        wptr = gen_enc_badhdr(gen, wptr, &hdr);
        *wptr++ = DNS_COMP_PTR; // comp ptr
        *wptr++ = 0x0C; // jmp back to offset 12
        wptr = enc_u16(wptr, DNS_TYPE_A);
        wptr = enc_u16(wptr, DNS_CLASS_IN);
        break;
    case FUZZ_QD_BADJMP:
        // encode a Question with a badjmp compression ptr
        hdr.qd_count = 1;
        wptr = gen_enc_badhdr(gen, wptr, &hdr);
        *wptr++ = DNS_COMP_PTR; // comp ptr
        *wptr++ = 0x00; // jmp back to offset 0
        wptr = enc_u16(wptr, DNS_TYPE_A);
        wptr = enc_u16(wptr, DNS_CLASS_IN);
        break;
    }

    // add msg length to pkt len
    gen->pkt_len += wptr - start;

    return 0;
}

static int run_fuzz(struct dns_gen *gen)
{
    int rc;

    if (gen->output) {
        pcap_start_pkt(gen);
        rc = gen_enc_badmsg(gen);
        if (rc) return rc;
        pcap_end_pkt(gen);
        rc = gen_pcap_rec(gen);
        printf("Wrote %zu bytes to %s\n", gen->pkt_len - ETHIPUDP_LEN, gen->output);
    }
    else {
        rc = gen_enc_badmsg(gen);
        if (rc) return rc;
        rc = gen_serv_connect(gen);
        if (rc) return rc;
        gen_verify_encmsg(gen);
        if (rc) return rc;
        rc = gen_send_dnspdu(gen);
        if (rc) return rc;
        rc = gen_recv_resp(gen);
    }

    return rc;
}

static int run_unsupp(struct dns_gen *gen)
{
    // should never happen
    return log_error_rf("Unsupported mode %d", gen->mode);
} 

/*
 * cmd-line options
 *
 */
enum {
    NO_OPT = 0,
    QUERY_NAME,
    QUERY_TYPE,
    QUERY_CLASS,
    QUERY_FLAGS,
    QUERY_SERVER,
    QUERY_TIMEOUT,
    QUERY_TCP,
    QUERY_LOG,
    RESP_ID,
    RESP_NAME,
    RESP_FLAGS,
    RESP_AN,
    RESP_NS,
    RESP_AR,
    RESP_TTL,
    RESP_OUTPUT,
    RESP_PCAPNG,
    FUZZ_TYPE,
    FUZZ_SERVER,
    FUZZ_OUTPUT,
    FUZZ_PCAPNG
};



struct get_opt query_opts[] = {
    { "name",   "<NAME> A DNS name", 1,  QUERY_NAME },
    { "type",  "<TYPE> A DNS type A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV", 1, QUERY_TYPE },
    { "class", "<CLASS> A DNS class IN|CS|CH|HS|ANY", 1, QUERY_CLASS },
    { "flags", "<FLAGS> Query flags AD:0|CD:0|RD:0", 1, QUERY_FLAGS },
    { "server", "<ADDR> Server IP address or name", 1, QUERY_SERVER },
    { "timeout", "<TimeOut> Response timeout", 1, QUERY_TIMEOUT },
    { "tcp",  "Use TCP to send msg (instead of UDP)", 0, QUERY_TCP },
    { "log",  "Log DNS message that are sent", 0, QUERY_LOG },
    { NULL }
};

struct get_opt resp_opts[] = {
    { "id"        , "<ID> A DNS header id",  1, RESP_ID  },
    { "name"      , "<NAME> A DNS name",     1, RESP_NAME },
    { "flags"     , "<FLAGS> Query flags name:value name=AD|CD|RD and val=0|1", RESP_FLAGS },
    { "answer"    , "<ANS>  answer record",  1, RESP_AN },
    { "authority" , "<AUTH> auth record",    1, RESP_NS },
    { "additional", "<ADD>  add record",     1, RESP_AR },
    { "output"    , "<FILE> pcap file name", 1, RESP_OUTPUT },
    { "pcapng"    , "Use pcapng file fmt",   0, RESP_PCAPNG  },
    { NULL }
};

struct get_opt fuzz_opts[] = {
    { "type",   "<FUZZ> type must be hdr-trunc|hdr-opcode|hdr-rcode|hdr-qdcnt|qd-cmploop|qd-badjmp", 1, FUZZ_TYPE },
    { "server", "<ADDR> Server address to send pdu to",  1, FUZZ_SERVER },
    { "output", "<FILE> pcap file name", 1, FUZZ_OUTPUT },
    { "pcapng" , "Use pcapng file fmt",  0, FUZZ_PCAPNG  },
    { NULL }
};

static const char *examples[] = {
    "query --name example.com --type A --server 8.8.8.8",
    "query --name example.com --type A --server 8.8.8.8 --flags 'AD:1|CD:1|RD:0'",
    "query --name example.com --type MX --server 8.8.8.8 --tcp",
    "fuzz --type qd-cmploop --server 127.0.0.1",
    "fuzz --type qd-badjmp --output f.pcapng --pcapng",
    "response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin"
};

struct {
    int mode;
    int (*run)(struct dns_gen *sniff);
    struct get_opt *opts;
    char *name;
    char *desc;
} cmds[] = {
   [MODE_NONE]  = { MODE_NONE , run_unsupp  },
   [MODE_QUERY] = { MODE_QUERY, run_query, query_opts, "query", "send DNS query message to a server" },
   [MODE_RESP]  = { MODE_RESP,  run_resp,  resp_opts, "response", "create a dns mesage with bad values" },
   [MODE_FUZZ]  = { MODE_FUZZ,  run_fuzz,  fuzz_opts, "fuzz",  "create a dns reponse message" },
};

static int gen_usage(char *path)
{
    struct str_slice prog_name = slice_rsplit1(slice_make_cstr(path), '/');
    FILE *out = stdout;
    int w= 10;

    fprintf(out,"Usage: %.*s [MODE] [OPTIONS]\n\n", SLICE(prog_name));

    // list modes
    fprintf(out, "MODE:\n");
    for (size_t i = 1; i < ARR_LEN(cmds); i++) {
        fprintf(out, "  %-*s %s\n", w, cmds[i].name, cmds[i].desc);
    }
    fprintf(out, "\n");

    // list options
    for (size_t i = 1; i < ARR_LEN(cmds); i++) {
        fprintf(out, "%s Options:\n", cmds[i].name);
        for (size_t j = 0; j < ARR_LEN(query_opts); j++) {
            struct get_opt *opt = &query_opts[j];
            if (!opt->name) break;
            fprintf(out, "  --%-*s %s\n", w, opt->name, opt->desc);
        }
        fprintf(out, "\n");
    }

    fprintf(out, "Examples:\n");
    for (size_t i = 0; i < ARR_LEN(examples); i++) {
        fprintf(out, "  %.*s %s\n", SLICE(prog_name), examples[i]);
    }

    return -1;
}

char *mode_tostr[] = {
    [MODE_NONE] = "<null>",
    [MODE_QUERY] = "query",
    [MODE_RESP] = "response",
    [MODE_FUZZ] = "fuzz"
};

static int get_mode(const char *str)
{
    if (!strcmp(str, "query")) return MODE_QUERY;
    if (!strcmp(str, "response")) return MODE_RESP;
    if (!strcmp(str, "fuzz")) return MODE_FUZZ;

    return 0;
}

static int set_dns_name(struct dns_gen *gen, struct get_opt *opt, const char *name)
{
    size_t len = strlen(name);

    if (len >= DNS_NAME_MAXSTR) {
       return log_cmd_err(mode_tostr[gen->mode], opt->name, "name too big");
    }

    memcpy(gen->dns_name, name, len);
    gen->dns_name[len] = '\0';

    return 0;
}

static int set_dns_type(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    gen->dns_type = dns_get_type(str);
    if (!gen->dns_type) {
        return log_cmd_err(mode_tostr[gen->mode], opt->name, "Unknown type");
    }
    return 0;
}

static int set_dns_class(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    gen->dns_class = dns_get_class(str);
    if (!gen->dns_type) {
        return log_cmd_err(mode_tostr[gen->mode], opt->name, "Unknown class");
    }
    return 0;
}

static int set_dns_flags(struct dns_gen *gen, struct get_opt *opt, char *str)
{
    struct str_slice flags_str = slice_make_cstr(str);
    uint16_t flags = 0;

    while (flags_str.len) {
        struct str_slice flag = slice_split(&flags_str, '|');
        slice_trim(&flag);
        struct str_slice on_off = slice_rsplit(&flag, ':');
        slice_trim(&on_off);
        uint16_t mask = get_dns_flag(flag);
        if (!mask) {
            return log_cmd_err(mode_tostr[gen->mode], opt->name, "Unknown flag %.*s", (int) flag.len, flag.ptr);
        }
        if (mask && on_off.len) {
            if (*on_off.ptr == '0') {
                flags &= ~mask;
            }
            else if (*on_off.ptr == '1') {
                flags |= mask;
            }
        }
    }

    gen->dns_flags = flags;

    return 0;
}

static int set_server(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    (void) opt;

    if (gen->serv_addr) {
        free(gen->serv_addr);
    }
    gen->serv_addr = strdup(str);
    if (!gen->serv_addr) {
        return log_errno_rf("strdup server failed");
    }

    return 0;
}

static int set_timeout(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    long val = strtol(str, NULL, 0);
    if (val < 0) {
        return log_cmd_err(mode_tostr[gen->mode], opt->name, "timeout cannot be < 0");
    }
    gen->timeout = val;

    return 0;
}

static int set_id(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    long val = strtol(str, NULL, 0);
    if (val < 0 || val > 0xffff) {
        return log_cmd_err(mode_tostr[gen->mode], opt->name, "id must be range [0x0, 0xffff]");
    }
    gen->id = val;

    return 0;
}

static int add_an(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    struct dns_rec rec = { 0 };

    int rc = gen_load_rec(gen, &rec, str);
    if (rc) return log_cmd_err(mode_tostr[gen->mode], opt->name, "Bad format");
    rc =  dns_msg_add_an(&gen->send, &rec);
    if (rc) return log_cmd_err(mode_tostr[gen->mode], opt->name, "Add failed");

    return 0;
}

static int add_ns(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    struct dns_rec rec = { 0 };

    int rc = gen_load_rec(gen, &rec, str);
    if (rc) return log_cmd_err(mode_tostr[gen->mode], opt->name, "Bad format");
    rc =  dns_msg_add_ns(&gen->send, &rec);
    if (rc) return log_cmd_err(mode_tostr[gen->mode], opt->name, "Add failed");

    return 0;
}

static int add_ar(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    struct dns_rec rec = { 0 };

    int rc = gen_load_rec(gen, &rec, str);
    if (rc) return log_cmd_err(mode_tostr[gen->mode], opt->name, "Bad format");
    rc =  dns_msg_add_ar(&gen->send, &rec);
    if (rc) return log_cmd_err(mode_tostr[gen->mode], opt->name, "Add failed");

    return 0;
}

static int set_output(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    (void) opt;
    if (gen->output) free(gen->output);
    gen->output = strdup(str);
    if (!gen->output) return log_errno_rf("strdup failed for output");

    return 0;
}

static int set_fuzz_type(struct dns_gen *gen, struct get_opt *opt, const char *str)
{
    gen->fuzz_type = get_fuzz_type(str);
    if (!gen->fuzz_type) {
        return log_cmd_err(mode_tostr[gen->mode], opt->name, "%s", opt->desc);
    }

    return 0;
}

static int gen_parse_argv(struct dns_gen *gen, int argc, char *argv[])
{
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        return gen_usage(argv[0]);
    }

    // get mode
    char *cmd = argv[1];
    gen->mode = get_mode(cmd);
    if (!gen->mode) {
        return log_error_rf("Unsupported mode %s", cmd);
    }

    // set mode defaults
    switch(gen->mode) {
    case MODE_QUERY:
        gen->dns_flags = DNS_FLAGS_RD;
        gen->dns_class = DNS_CLASS_IN;
        break;
    }

    // process cmd-line options
    struct getopt_parse parse;
    int rc = getopt_init(&parse, argc, argv, 0, cmds[gen->mode].opts);
    if (rc) fatal_error("cmd-line parser failed");
    while ((rc = getopt_next(&parse)) >= 0) {
        struct get_opt *opt = getopt_curopt(&parse);
        switch(rc) {
        // query
        case QUERY_NAME:    rc = set_dns_name(gen, opt, getopt_str(&parse)); break;
        case QUERY_TYPE:    rc = set_dns_type(gen, opt, getopt_str(&parse)); break;
        case QUERY_CLASS:   rc = set_dns_class(gen, opt, getopt_str(&parse)); break;
        case QUERY_FLAGS:   rc = set_dns_flags(gen, opt, getopt_str(&parse)); break;
        case QUERY_SERVER:  rc = set_server(gen, opt, getopt_str(&parse)); break;
        case QUERY_TIMEOUT: rc = set_timeout(gen, opt, getopt_str(&parse)); break;
        case QUERY_TCP: gen->is_tcp = 1; break;
        case QUERY_LOG: gen->log_msg = 1; break;
        // response
        case RESP_ID:   rc = set_id(gen, opt, getopt_str(&parse)); break;
        case RESP_NAME: rc = set_dns_name(gen, opt, getopt_str(&parse)); break;
        case RESP_FLAGS: rc = set_dns_flags(gen, opt, getopt_str(&parse)); break;
        case RESP_AN:  rc = add_an(gen, opt, getopt_str(&parse)); break;
        case RESP_NS:  rc = add_ns(gen, opt, getopt_str(&parse)); break;
        case RESP_AR:  rc = add_ar(gen, opt, getopt_str(&parse)); break;
        case RESP_TTL: rc = set_timeout(gen, opt, getopt_str(&parse)); break;
        case RESP_OUTPUT: rc = set_output(gen, opt, getopt_str(&parse)); break;
        case RESP_PCAPNG: gen->use_pcapng = 1; break;
        // fuzz
        case FUZZ_TYPE:   rc = set_fuzz_type(gen, opt, getopt_str(&parse)); break;
        case FUZZ_SERVER: rc = set_server(gen, opt, getopt_str(&parse)); break;
        case FUZZ_OUTPUT: rc = set_output(gen, opt, getopt_str(&parse)); break;
        case FUZZ_PCAPNG: gen->use_pcapng = 1; break;
        }
        if (rc < 0) break;
    }
    if (rc != GETOPT_EOF) return rc;

    // final check
    switch(gen->mode) {
    case MODE_QUERY:
        if (!*gen->dns_name) return log_cmd_err(cmd, "--name <dns-name>", "is required");
        if (!gen->serv_addr) return log_cmd_err(cmd, "--server <ip-addr>", "is required");
        dns_msg_set_id_flags(&gen->send, 0, gen->dns_flags);
        rc = dns_msg_add_qd(&gen->send, gen->dns_name, gen->dns_type, gen->dns_class);
        if (rc) return rc;
        break;
    case MODE_RESP:
        if (!*gen->dns_name) {
            return log_cmd_err(cmd, resp_opts[1].name, "is required");
        }
        if (!dns_msg_cnt_rec(&gen->send)) {
            return log_cmd_err(cmd, "answer|authority|additional", "is required");
        }
        if (!gen->output) {
            return log_cmd_err(cmd, resp_opts[6].name, "is required");
        }
        dns_msg_set_id_flags(&gen->send, gen->id, gen->dns_flags);
        break;
    case MODE_FUZZ:
        if (!gen->fuzz_type) {
            return log_cmd_err(cmd, fuzz_opts[0].name, "is required");
        }
        if (!gen->serv_addr && !gen->output) {
            return log_cmd_err(cmd, "--server or --output", "is required");
        }
        break;
    }

    // all done
    return 0;
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
    if (cmds[gen->mode].run(gen)) { ec = 5; goto done; }

done:
    if (gen) gen_free(gen);

    return ec;
}
