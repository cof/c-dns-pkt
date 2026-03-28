/*
 * dns-gen  :  DNS packet generator
 * Usage:   : ./dns-gen --help
 * Example  : ./dns-gen query --name example.com --type A --server 8.8.8.8
 *
 * Overview
 * --------
 * Basicaly a DNS packet generator for testing DNS servers or dns-inspect.
 *
 * Notes
 * -----
 * Uses SOCK api to create a UDP or TCP socket
 * Uses DNS api to encode DNS messages
 * Uses PCAP api to generate pcap files
 */
#include <time.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "util.h"
#include "log.h"
#include "pcap.h"
#include "dns_proto.h"
#include "sock.h"

// supported cmds
#define MODE_NONE  0
#define MODE_QUERY 1
#define MODE_RESP  2
#define MODE_FUZZ  3

// fuzz type codes
#define FUZZ_HDR_TRUNC   1
#define FUZZ_HDR_OPCODE  2
#define FUZZ_HDR_RCODE   3
#define FUZZ_HDR_QDCNT   4
#define FUZZ_QD_CMPLOOP  5
#define FUZZ_QD_BADJMP   6

#define ETHIPUDP_LEN (14 + 20 + 8)

// gen state
struct dns_gen {
    // config
    pid_t pid;
    struct simple_sig sig;
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
    struct dns_msg snd_msg; // msg to encode into pkt_buf
    struct dns_msg rcv_msg; // decoded msg read from pkt_buf
    uint32_t timeout;       // send / recv message timeout in ms
    uint16_t fuzz_type;
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
    struct simple_sock sock;
    // flags
    unsigned int use_tcp    : 1; // Guess ....
    unsigned int log_msg    : 1; // log all msg to stdout
    unsigned int use_pcapng : 1; // use pcapng for output fmt
};

// util funcs
static double time_diff_ms(struct timespec *begin, struct timespec *end)
{
    double diff_sec = end->tv_sec  - begin->tv_sec;
    double diff_nsec = end->tv_nsec - begin->tv_nsec;
    return (diff_sec * 1000.0) + (diff_nsec / 1000000.0);
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

static int get_dns_flag(struct str_slice str)
{
    char tmp[10];
    size_t len = min(sizeof(tmp) - 1, str.len);
    memcpy(tmp, str.ptr, len);
    return dns_get_flag(tmp);
}

static int get_flag_val(struct str_slice str)
{
    if (str.len != 1) return 0;
    if (*str.ptr == '0') return 1;
    if (*str.ptr == '1') return 2;
    return 0;
}

// print recv error
static int gen_recv_err(int err)
{
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

    return -1;
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

// make space for ETH+IP+UDP headers
static int pcap_start_pkt(struct dns_gen *gen)
{
    gen->pkt_len = ETHIPUDP_LEN;

    return 0;
}

// encode ETH+IP+UDP headers
static int pcap_end_pkt(struct dns_gen *gen)
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

    return 0;
}

// write DNS msg to pcap file
static int gen_pcap_file(struct dns_gen *gen)
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

static int gen_print_dnsrsp(struct dns_gen *gen)
{
    struct dns_msg *rsp = &gen->rcv_msg;
    struct dns_rec *rec;
    char *desc = NULL;
    int rc;

    // encode rsp sections to str
    if (dns_msg_cnt_rec(rsp) == 0) {
        // no sections
        desc = "<None>";
    }
    else if ((rec = dns_msg_get_rec(rsp)) != NULL)  {
        // one section
        desc = gen->emsg; *desc = '\0';
        rc = dns_rec_tostr(rec, 0, desc, sizeof(gen->emsg));
        if (rc < 0) return rc;
        while (*desc && *desc == ' ') desc++;
    }
    else {
        // multiple sections
        desc = gen->emsg; *desc = '\0';
        printf("\n");
        rc = dns_msg_sects_tostr(rsp, desc, sizeof(gen->emsg));
        if (rc < 0) return rc;
    }

    rc = printf("%s\n", desc);
    if (rc < 0) return log_error_rf("printf failed!");

    return 0;
}

// recv pdu from server
static int gen_recv_dnspdu(struct dns_gen *gen)
{
    size_t read_len = sizeof(gen->pkt_buf);
    ssize_t rc;

    if (gen->use_tcp) {
        // read 2-byte prefix
        uint16_t dns_len;
        rc = sock_recv_data(&gen->sock, &dns_len, sizeof(dns_len));
        if (rc != sizeof(dns_len)) return gen_recv_err(rc);
        read_len = ntohs(dns_len);
    }

    // read PDU
    rc = sock_recv_data(&gen->sock, gen->pkt_buf, read_len);
    if (rc <= 0) return gen_recv_err(rc);

    // record pkt len
    gen->recv_len = rc;

    // read a message
    rc = clock_gettime(CLOCK_MONOTONIC, &gen->ts_recv);
    if (rc != 0) log_errno("clock_gettime ts_recv failed");

    return 0;
}


// send pdu to server
static int gen_send_dnspdu(struct dns_gen *gen)
{ 
    uint16_t dns_len;
    struct iovec iovs[2];
    int num_iov = 0;

    if (gen->use_tcp) {
        // send the 2 byte dns length prefix
        dns_len = ntohs(gen->pkt_len);
        iov_load(iovs + 0, &dns_len, sizeof(dns_len));
        num_iov++;
    }

    iov_load(iovs + num_iov, gen->pkt_buf, gen->pkt_len);
    num_iov++;

    // send pdu
    ssize_t rc = sock_send_iovs(&gen->sock, num_iov, iovs);
    if (rc >= 0) rc = 0;

    return rc;
}

// decode DNS rsp from packet buffer
static int gen_dec_dnsmsg(struct dns_gen *gen)
{
    return dns_msg_decode(&gen->rcv_msg, gen->pkt_buf, gen->recv_len);
}

// encode DNS send msg into packet buffer
static int gen_enc_dnsmsg(struct dns_gen *gen)
{
    void *buf = gen->pkt_buf + gen->pkt_len;
    size_t space = sizeof(gen->pkt_buf) - gen->pkt_len;

    ssize_t pkt_len = dns_msg_encode(&gen->snd_msg, buf, space);
    if (pkt_len <= 0) return log_error_rf("encode DNS pdu failed");

    gen->pkt_len += pkt_len;

    return 0;
}

static int gen_verify_encmsg(struct dns_gen *gen)
{
    if (!gen->log_msg) return 0;

    int rc = validate_dns_packet(gen->pkt_buf, gen->pkt_len, gen->emsg);
    log_msg(gen->emsg);

    return rc;
}

// recv query rsp from server
static int gen_recv_resp(struct dns_gen *gen)
{
    int rc;

    if ((rc = gen_recv_dnspdu(gen))) return rc;
    if ((rc = gen_dec_dnsmsg(gen))) return rc;

    // check msg is response
    struct dns_header *rcv_hdr = &gen->rcv_msg.hdr;
    if ((rcv_hdr->flags & DNS_FLAGS_QR) == 0) {
        return log_info_rc("dns-gen", 1,
            "Unexpected DNS message ID: 0x%04x Flags: 0x%04x Len %zu",
            rcv_hdr->id, rcv_hdr->flags, gen->recv_len);
    }

    // check Transaction ID
    if (rcv_hdr->id != gen->tid_sent) {
        return log_info_rc("dng-gen", 2,
            "Response ID 0x%04x does not match Request ID 0x%04x", 
            rcv_hdr->id, gen->tid_sent);
    }

    // check Result Code
    int rcode = rcv_hdr->flags & DNS_FLAGS_RCODE;
    if (rcode != DNS_RCODE_NOERROR) {
        return log_info_rc("dng-gen", 3,
            "Response ID 0x%04x failed with error %s", 
            rcv_hdr->id, rcode_tostr(rcode));
    }

    double delta_ms = time_diff_ms(&gen->ts_sent, &gen->ts_recv);
    printf("Received response in %ums: ", (uint32_t) delta_ms);

    gen_print_dnsrsp(gen);

    // all done
    return 0;
}

// send query msg to server
static int gen_send_query(struct dns_gen *gen)
{
    // next tid
    gen->snd_msg.hdr.id =  rand() % 65536;
    gen->pkt_len = 0;

    int rc;
    if ((rc = gen_enc_dnsmsg(gen))) return rc;
    if ((rc = gen_verify_encmsg(gen))) return rc;

    // tell user
    printf("Send query (%s) ID:0x%04x for %s %s %s\n",
        gen->use_tcp ? "TCP" : "UDP",
        gen->snd_msg.hdr.id, str_def(gen->dns_name, "<null>"),
        dns_class_tostr(gen->dns_class),
        dns_type_tostr(gen->dns_type));

    // send DNS msg
    if ((rc = gen_send_dnspdu(gen))) return rc;

    // sent - as far as we know
    gen->tid_sent = gen->snd_msg.hdr.id;
    if (clock_gettime(CLOCK_MONOTONIC, &gen->ts_sent) != 0) {
        log_errno("clock_gettime ts_sent failed");
        // keep going ?
    }

    // all done
    return 0;
}

static int gen_serv_connect(struct dns_gen *gen)
{
    // select TCP or UDP connection
    uint32_t mode = gen->use_tcp ? SOCK_TCP : SOCK_UDP | SOCK_UDPCON;
    const char *port = "53";

    int rc;
    if ((rc = sock_client(&gen->sock, mode, gen->serv_addr, port))) return rc;
    if ((rc = sock_set_sndto(&gen->sock, gen->timeout))) return rc;
    if ((rc = sock_set_rcvto(&gen->sock, gen->timeout))) return rc;

    // all done
    return 0;
}

// run query cmd
static int run_query(struct dns_gen *gen)
{
    int rc;

    if ((rc = gen_serv_connect(gen))) return rc;
    if ((rc = gen_send_query(gen))) return rc;
    if ((rc = gen_recv_resp(gen))) return rc;

    return 0;
}

// run response cmd
static int run_response(struct dns_gen *gen)
{
    int rc; 

    if ((rc = pcap_start_pkt(gen))) return rc;
    if ((rc = gen_enc_dnsmsg(gen))) return rc;
    if ((rc = pcap_end_pkt(gen))) return rc;
    if ((rc = gen_pcap_file(gen))) return rc;

    printf("Wrote %zu bytes to %s\n", gen->pkt_len - ETHIPUDP_LEN, gen->output);

    return 0;
}

// encode a bad header
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

// encode a bad msg
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
 
// run fuzz cmd
static int run_fuzz(struct dns_gen *gen)
{
    int rc = 0;

    if (gen->output) {
        // encode bad msg
        if ((rc = pcap_start_pkt(gen))) return rc;
        if ((rc = gen_enc_badmsg(gen))) return rc;
        if ((rc = pcap_end_pkt(gen))) return rc;
        if ((rc = gen_pcap_rec(gen))) return rc;
        printf("Wrote %zu bytes to %s\n", gen->pkt_len - ETHIPUDP_LEN, gen->output);
    }
    else {
        // send bad msg
        if ((rc = gen_enc_badmsg(gen))) return rc;
        if ((rc = gen_serv_connect(gen))) return rc;
        if ((rc = gen_verify_encmsg(gen))) return rc;
        if ((rc = gen_send_dnspdu(gen))) return rc;
        if ((rc = gen_recv_resp(gen)))  return rc;
    }

    // all done
    return 0;
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

struct cmd_opt query_opts[] = {
    { "--name",   "<NAME> A DNS name", 0, 1,  QUERY_NAME },
    { "--type",  "<TYPE> A DNS type A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV", 0, 1, QUERY_TYPE },
    { "--class", "<CLASS> A DNS class IN|CS|CH|HS|ANY", 0, 1, QUERY_CLASS },
    { "--flags", "<FLAGS> Query flags AD:0|CD:0|RD:0", 0, 1, QUERY_FLAGS },
    { "--server", "<ADDR> Server IP address or name", 0, 1, QUERY_SERVER },
    { "--timeout", "<TimeOut> Response timeout in ms", 0, 1, QUERY_TIMEOUT },
    { "--tcp",  "Use TCP to send msg (instead of UDP)", 0, 0, QUERY_TCP },
    { "--log",  "Log DNS message that are sent", 0, 0, QUERY_LOG },
    { NULL }
};

struct cmd_opt resp_opts[] = {
    { "--id"        , "<ID> A DNS header id",  0, 1, RESP_ID  },
    { "--name"      , "<NAME> A DNS name",     0, 1, RESP_NAME },
    { "--flags"     , "<FLAGS> Query flags name:value name=AD|CD|RD and val=0|1", 0, 1, RESP_FLAGS },
    { "--answer"    , "<ANS>  answer record",  0, 1, RESP_AN },
    { "--authority" , "<AUTH> auth record",    0, 1, RESP_NS },
    { "--additional", "<ADD>  add record",     0, 1, RESP_AR },
    { "--output"    , "<FILE> pcap file name", 0, 1, RESP_OUTPUT },
    { "--pcapng"    , "Use pcapng file fmt",   0, 0, RESP_PCAPNG  },
    { NULL }
};

struct cmd_opt fuzz_opts[] = {
    { "--type",   "<FUZZ> type must be hdr-trunc|hdr-opcode|hdr-rcode|hdr-qdcnt|qd-cmploop|qd-badjmp", 0, 1, FUZZ_TYPE },
    { "--server", "<ADDR> Server address to send pdu to", 0, 1, FUZZ_SERVER },
    { "--output", "<FILE> pcap file name", 0, 1, FUZZ_OUTPUT },
    { "--pcapng" , "Use pcapng file fmt",  0, 0, FUZZ_PCAPNG  },
    { NULL }
};

static const char *examples[] = {
    "query --name example.com --type A --server 8.8.8.8",
    "query --name example.com --type A --server 8.8.8.8 --flags 'AD:1|CD:1|RD:0'",
    "query --name example.com --type MX --server 8.8.8.8 --tcp",
    "fuzz --type qd-cmploop --server 127.0.0.1",
    "fuzz --type qd-badjmp --output f.pcapng --pcapng",
    "response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin",
    NULL
};

struct {
    int mode;
    int (*run)(struct dns_gen *sniff);
    struct cmd_opt *opts;
    char *name;
    char *desc;
} cmds[] = {
   [MODE_NONE]  = { MODE_NONE , run_unsupp  },
   [MODE_QUERY] = { MODE_QUERY, run_query, query_opts, "query", "send DNS query message to a server" },
   [MODE_RESP]  = { MODE_RESP,  run_response,  resp_opts, "response", "create a dns mesage with bad values" },
   [MODE_FUZZ]  = { MODE_FUZZ,  run_fuzz,  fuzz_opts, "fuzz",  "create a dns reponse message" },
};

static void gen_usage(const char *cmd)
{
    const char *prog_name = get_basename(cmd);
    int w= 10;

    printf("Usage: %s [MODE] [OPTIONS]\n\n", prog_name);

    // list modes
    printf("MODE:\n");
    for (size_t i = 1; i < ARR_LEN(cmds); i++) {
        printf("  %-*s %s\n", w, cmds[i].name, cmds[i].desc);
    }
    printf("\n");

    // list options
    for (size_t i = 1; i < ARR_LEN(cmds); i++) {
        printf("%s Options:\n", cmds[i].name);
        struct cmd_opt *opts = cmds[i].opts;
        for (size_t j = 0; opts[j].name; j++) {
            struct cmd_opt *opt = &opts[j];
            printf("  %-*s %s\n", w, opt->name, opt->desc);
        }
        printf("\n");
    }

    printf("Examples:\n");
    for (int i = 0; examples[i]; i++)  {
        printf("  %s %s\n", prog_name, examples[i]);
    }
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

static int set_dns_name(struct dns_gen *gen, struct cmd_argv *parse)
{
    size_t len = strlen(parse->value);

    if (len >= DNS_NAME_MAXSTR) {
       return log_cmd_err(mode_tostr[gen->mode], parse->name, "name too big");
    }

    memcpy(gen->dns_name, parse->value, len);
    gen->dns_name[len] = '\0';

    return 0;
}

static int set_type_str(struct dns_gen *gen, 
    uint16_t *val, int(*lookup)(const char *str),
    struct cmd_argv *parse)
{
    int code = lookup(parse->value);
    if (!code) return log_cmd_err(mode_tostr[gen->mode], parse->name, "Unknown type");
    *val = code;
    return 0;
}

// parse flags string e.g 'AD:1|CD:1|RD:0' 
static int set_dns_flags(struct dns_gen *gen, struct cmd_argv *parse)
{
    struct str_slice flags_str = slice_make_cstr(parse->value);
    uint16_t flags = 0;
    const char *mode = mode_tostr[gen->mode];

    while (flags_str.len) {
        // get name
        struct str_slice flag = slice_split(&flags_str, '|');
        slice_trim(&flag);
        // get value
        struct str_slice onoff = slice_rsplit(&flag, ':');
        slice_trim(&onoff);
        // get flag mask
        uint16_t mask = get_dns_flag(flag);
        if (!mask) return log_cmd_err(mode, parse->name, "Unknown flag %.*s", SLICE(flag));
        int val = get_flag_val(onoff);
        if (!val) return log_cmd_err(mode, parse->name, "Unknown value %.*s", SLICE(onoff));
        // set field off or on
        flags = val == 1 ? flags & ~mask : flags | mask;
    }

    gen->dns_flags = flags;

    return 0;
}

static int set_id(struct dns_gen *gen, struct cmd_argv *parse)
{
    long val = strtol(parse->value, NULL, 0);
    if (val < 0 || val > 0xffff) {
        return log_cmd_err(mode_tostr[gen->mode], parse->name, "id must be range [0x0, 0xffff]");
    }
    gen->id = val;

    return 0;
}

static int add_sect(struct dns_gen *gen, int sc, struct cmd_argv *parse)
{
    struct dns_rec rec = { 0 };
    int rc;
    
    // load defaults
    if (!rec.name)  rec.name = gen->dns_name;
    if (!rec.class) rec.class = gen->dns_class;
    if (!rec.ttl)  rec.ttl = gen->ttl;

    if ((rc = dns_rec_load(&rec, sc, parse->value))) return rc;
    if ((rc = dns_msg_add_rec(&gen->snd_msg, sc,  &rec))) return rc;

    return 0;
}

// parse cmd-line args
static int gen_parse_argv(struct dns_gen *gen, int argc, char *argv[])
{
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        gen_usage(argv[0]);
        exit(0);
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
    struct cmd_argv parse = { argc, argv, cmds[gen->mode].opts, 2 } ;
    int rc;
    while ( (rc = cmd_argv_next(&parse)) >= 0) {
        switch(rc) {
        // query
        case QUERY_NAME:  rc = set_dns_name(gen, &parse); break;
        case QUERY_TYPE:  rc = set_type_str(gen, &gen->dns_type, dns_get_type, &parse); break;
        case QUERY_CLASS: rc = set_type_str(gen, &gen->dns_class, dns_get_class, &parse); break;
        case QUERY_FLAGS: rc = set_dns_flags(gen, &parse); break;
        case QUERY_SERVER:  rc = opt_setstr(&gen->serv_addr, &parse); break;
        case QUERY_TIMEOUT: rc = opt_setuint(&gen->timeout, &parse); break;
        case QUERY_TCP: gen->use_tcp = 1; break;
        case QUERY_LOG: gen->log_msg = 1; break;
        // response
        case RESP_ID:    rc = set_id(gen, &parse); break;
        case RESP_NAME:  rc = set_dns_name(gen, &parse); break;
        case RESP_FLAGS: rc = set_dns_flags(gen, &parse); break;
        case RESP_AN:    rc = add_sect(gen, DNS_MSG_AN, &parse); break;
        case RESP_NS:    rc = add_sect(gen, DNS_MSG_NS, &parse); break;
        case RESP_AR:    rc = add_sect(gen, DNS_MSG_AR, &parse); break;
        case RESP_TTL:   rc = opt_setuint(&gen->timeout, &parse); break;
        case RESP_OUTPUT: rc = opt_setstr(&gen->output, &parse); break;
        case RESP_PCAPNG: gen->use_pcapng = 1; break;
        // fuzz
        case FUZZ_TYPE:   rc = set_type_str(gen, &gen->fuzz_type, get_fuzz_type, &parse); break;
        case FUZZ_SERVER: rc = opt_setstr(&gen->serv_addr, &parse); break;
        case FUZZ_OUTPUT: rc = opt_setstr(&gen->output, &parse); break;
        case FUZZ_PCAPNG: gen->use_pcapng = 1; break;
        }
        if (rc < 0) break;
    }
    if (rc != OPT_EOF) return rc;

    // final check
    switch(gen->mode) {
    case MODE_QUERY:
        if (!*gen->dns_name) return log_cmd_err(cmd, "--name <dns-name>", "is required");
        if (!gen->serv_addr) return log_cmd_err(cmd, "--server <ip-addr>", "is required");
        dns_msg_set_id_flags(&gen->snd_msg, 0, gen->dns_flags);
        rc = dns_msg_add_qd(&gen->snd_msg, gen->dns_name, gen->dns_type, gen->dns_class);
        if (rc) return rc;
        break;
    case MODE_RESP:
        if (!*gen->dns_name) return log_cmd_err(cmd, resp_opts[1].name, "is required");
        if (!dns_msg_cnt_rec(&gen->snd_msg)) return log_cmd_err(cmd, "answer|authority|additional", "is required");
        if (!gen->output) return log_cmd_err(cmd, resp_opts[6].name, "is required");
        dns_msg_set_id_flags(&gen->snd_msg, gen->id, gen->dns_flags);
        break;
    case MODE_FUZZ:
        if (!gen->fuzz_type) return log_cmd_err(cmd, fuzz_opts[0].name, "is required");
        if (!gen->serv_addr && !gen->output) return log_cmd_err(cmd, "--server or --output", "is required");
        break;
    }

    // all done
    return 0;
}

static int gen_init(struct dns_gen *gen)
{
    memset(gen, 0, sizeof(*gen));

    // init all fds to -1
    gen->sock.fd = -1;

    // needed for tids
    srand(time(NULL));

    return 0;
}

static void gen_free(struct dns_gen *gen)
{
    sock_close(&gen->sock, 0);
    if (gen->output) free(gen->output);
    if (gen->pcap) pcap_close(gen->pcap);

    free(gen);
}

static struct dns_gen *gen_create(void)
{
    struct dns_gen *gen;

    gen = malloc(sizeof(*gen));
    if (!gen) return log_errno_rn("Malloc failed for gen state");

    return gen;
}

int main(int argc, char *argv[])
{
    struct dns_gen *gen = NULL;
    int ec = 0;

    if (!(gen = gen_create())) { ec = 1; goto done; }
    if (gen_init(gen)) { ec = 2; goto done; }
    if (gen_parse_argv(gen, argc, argv)) { ec = 3;  goto done; }
    if (setup_signals(&gen->sig))  { ec = 4 ; goto done; }
    if (cmds[gen->mode].run(gen)) { ec = 5; goto done; }

done:
    if (gen) gen_free(gen);

    return ec;
}
