/*
 * dns-gen - a simple DNS packet generator
 *
 * Usage: dns-gen
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
#include <time.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h> 
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>

#include "util.h"
#include "dns_proto.h"

#define RECV_TIMEOUT 5

// supported cmds
#define MODE_QUERY 1
#define MODE_RESP  2
#define MODE_FUZZ  3

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
    char *id;
    char *answer;
    char *output;
    uint32_t recv_timeout;
    uint8_t pkt_buf[DNS_MAX_PDUSIZE];
    char emsg[DNS_EMSG_MAXLEN];
    // last tid sent
    ssize_t recv_len;
    uint16_t tid_sent;
    struct timespec ts_sent;
    struct timespec ts_recv;
    // connetion
    struct sockaddr_storage dst_addr;
    socklen_t dst_len;
    int sock_fd;
    // flags
    unsigned int use_tcp : 1;
    unsigned int sys_err : 1;
    unsigned int log_msg : 1;
    unsigned int use_flags : 1;
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

static double time_diff_ms(struct timespec *begin, struct timespec *end)
{
    double diff_sec = end->tv_sec  - begin->tv_sec;
    double diff_nsec = end->tv_nsec - begin->tv_nsec;
    return (diff_sec * 1000.0) + (diff_nsec / 1000000.0);
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


static int gen_connect(struct dns_gen *gen)
{
    // resolve hostname+ port string to list of (ip+port)
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = gen->use_tcp ? SOCK_STREAM : SOCK_DGRAM;
    const char *port = "53";

    int rc = getaddrinfo(gen->serv_addr, port, &hints, &res);
    if (rc != 0) {
        return log_error_rf("getaddrinfo(%s,%s) : %s\n", gen->serv_addr, port, gai_strerror(rc));
    }

    // get udp or tcp socket
    int sock_fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock_fd == -1) continue;
        if (!gen->use_tcp) break;
        rc = connect(sock_fd, ai->ai_addr, ai->ai_addrlen);
        if (rc != -1) break;
        log_errno("connect(%s:%s) failed", gen->serv_addr, port);
        close(sock_fd);
        sock_fd = -1;
    }

    if (sock_fd == -1) {
        freeaddrinfo(res);
        return log_error_rf("Connect to %s:%s failed", gen->serv_addr, port);
    }

    memcpy(&gen->dst_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    gen->dst_len = res->ai_addrlen;
    gen->sock_fd = sock_fd;

    // set recv timeout
    struct timeval tv;
    tv.tv_sec = gen->recv_timeout;
    tv.tv_usec = 0;
    if (setsockopt(gen->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        return log_errno_rf("setsockopt SO_RCVTIMEO on %d failed", gen->sock_fd);
    }

    log_info("dns-gen", "Connected to %s", gen->serv_addr);

    // all done
    return 0;
}
    
static int send_dns_pdu(struct dns_gen *gen, uint8_t *pkt, size_t len)
{
    ssize_t nsent = sendto(gen->sock_fd, 
        pkt, len, 0,
        (struct sockaddr *) &gen->dst_addr, gen->dst_len
    );

    if (nsent == -1) {
        return log_errno_rf("sendto failed to send %zu bytes", len);
    }

    if (nsent != len) {
        return log_error_rf("sendto truncated: %zd/%zu bytes", nsent, len);
    }

    return 0;
}

static int recv_dns_pdu(struct dns_gen *gen)
{
    struct sockaddr_storage from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t nread = recvfrom(
        gen->sock_fd, 
        gen->pkt_buf, sizeof(gen->pkt_buf), 0, 
        (struct sockaddr *)&from_addr, &from_len
    );

    if (nread < 0) {
        if (errno == EINTR) return -2;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return -3;
        gen->sys_err = 1;
        return -1;
    }

    gen->recv_len = nread;
    if (clock_gettime(CLOCK_MONOTONIC, &gen->ts_recv) != 0) {
        log_errno("clock_gettime ts_recv failed");
        // keep going ?
    }

    return 0;
}

static int gen_send_query(struct dns_gen *gen, const char *name, uint16_t qclass, uint16_t qtype) 
{
    struct dns_enc enc = {
        .pkt_buf = gen->pkt_buf,
        .pkt_max = sizeof(gen->pkt_buf),
    };

    // next tid
    uint16_t tid = rand() % 65536;
    qtype = qtype  ?: DNS_TYPE_A;
    qclass = qclass ?: DNS_CLASS_IN;
    uint16_t flags = gen->dns_flags;

    // encode PDU
    int rc = dns_enc_start(&enc, tid, flags);
    dns_enc_add_quest(&enc, name, qtype, qclass);
    dns_enc_end(&enc);

    // check message is valid before we send
    if (gen->log_msg) {
        rc = validate_dns_packet(enc.pkt_buf, enc.pkt_len, gen->emsg);
        log_msg(gen->emsg);
        if (rc) return rc;
    }

    log_info("dns-gen", "Send query ID:0x%04x for %s %s %s", tid, name,
        dns_class_tostr(qclass, NULL), dns_type_tostr(qtype, NULL));

    // send it
    rc = send_dns_pdu(gen, enc.pkt_buf, enc.pkt_len);
    if (rc) return rc;

    // msg sent  as far as we know
    gen->tid_sent = tid;
    if (clock_gettime(CLOCK_MONOTONIC, &gen->ts_sent) != 0) {
        log_errno("clock_gettime ts_sent failed");
        // keep going ?
    }

    return 0;
}

static int gen_recv_resp(struct dns_gen *gen)
{
    int rc = recv_dns_pdu(gen);
    if (rc) return rc;

    struct dns_msg msg = { 0 };
    rc = dns_decode_msg(&msg, gen->pkt_buf, gen->recv_len);
    if (rc) return rc;

    // check response
    struct dns_header *hdr = &msg.hdr;
    if (!(hdr->flags & DNS_FLAGS_QR)) {
        return log_info_rz("dns-gen", 
            "Unexpected DNS message ID: 0x%04x Flags: 0x%04x Len %zu",
            hdr->id, hdr->flags, gen->recv_len);
    }

    // check Transaction ID
    if (hdr->id != gen->tid_sent) {
        return log_info_rz("dng-gen",
            "Response ID 0x%04x does not match Request ID 0x%04x", hdr->id, gen->tid_sent);
    }

    // check Result Code
    int rcode = hdr->flags & DNS_FLAGS_RCODE;
    if (rcode != DNS_RCODE_NOERROR) {
        char num[10];
        itoa(num, 10, rcode);
        return log_info_rz("dng-gen",
            "Response ID 0x%04x failed with error %s", hdr->id, rcode_tostr(rcode, num));
    }

    double delta_ms = time_diff_ms(&gen->ts_sent, &gen->ts_recv);

    char *desc = ""; 
    gen->emsg[0] = '\0';
    if (msg.ans.num_rec == 1) {
        dns_rec_tostr(gen->emsg, sizeof(gen->emsg), &msg.ans.rec[0]);
        desc = gen->emsg;
    }

    log_info("dns-gen", "Received response in %.3fms: %s", delta_ms,  desc);
    for (int i = 0; i < msg.ans.num_rec; i++) {
        int nw = dns_rec_tostr(gen->emsg, sizeof(gen->emsg), &msg.ans.rec[i]);
        if (nw) {
            log_msg(gen->emsg);
        }
    }

    return 0;
}

static int gen_do_query(struct dns_gen *gen)
{
    int rc = gen_connect(gen);
    if (rc) return rc;

    rc = gen_send_query(gen, gen->dns_name, gen->dns_class, gen->dns_type);
    if (rc) return rc;

    rc = gen_recv_resp(gen);
    if (rc) return rc;

    return 0;
}

static int gen_do_fuzz(struct dns_gen *gen)
{
    return -1;
}

static int gen_setup_fuzz(void *state, int narg, struct str_slice args[])
{
    return -1;
}

static int gen_do_resp(struct dns_gen *gen)
{
    return -1;
}

static int gen_add_answer(struct dns_gen *gen, struct str_slice ans_str)
{
    return -1;
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
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--name"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--name <dns-name>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--name <dns-name>", "cannot be blank");
            if (val.len > DNS_NAME_MAXSTR) return log_cmd_err(cmd, "--name <dns-name>", "name too big");
            memcpy(gen->dns_name, val.ptr, val.len);
            gen->dns_name[val.len] = '\0';
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--answer"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--answer <answer>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--answer <answer>", "cannot be blank");
            if (gen_add_answer(gen, val) != 0) return log_cmd_err(cmd, "--answer <answer>", "Bad format");
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--output"))) {
            if (i == narg - 1) {
                return log_cmd_err(cmd, "--name <dns-name>", "requires an argument");
            }
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--name <dns-name>", "cannot be blank");
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

    if (!*gen->dns_name)  return log_cmd_err(cmd, "--name <dns-name>", "is required");
    if (!gen->answer) return log_cmd_err(cmd, "--answer <answer>", "is required");
    if (!gen->output) return log_cmd_err(cmd, "--output <file>", "is required");

    return -1;
}


static int gen_setup_query(void *state, int narg, struct str_slice args[])
{
    struct dns_gen *gen = state;
    const char *cmd = "query";

    gen->mode = MODE_QUERY;
    gen->dns_flags = DNS_FLAGS_RD;

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
            if (i == narg - 1) return log_cmd_err(cmd, "--class <dns-class>", "requires an argument");
            struct str_slice val = args[++i];
            if (!val.len) return log_cmd_err(cmd, "--flags <dns-flags>", "Must look like AD:0|CD:0|RD:0");
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
        else if (slice_cmp_cstr(opt,  STR_LIT("--tcp"))) {
            gen->use_tcp = 1;
        }
        else if (slice_cmp_cstr(opt,  STR_LIT("--log"))) {
            gen->log_msg = 1;
        }
        else {
            return log_cmd_err(cmd, "unknown option", "%.*s", SLICE(opt));
        }
    }

    // min args check
    if (!*gen->dns_name)  return log_cmd_err(cmd, "--name <dns-name>", "is required");
    if (!gen->serv_addr) return log_cmd_err(cmd, "--server <ip-addr>", "is required");

    return 0;
}

static int gen_usage(void *state, struct str_slice prog_name)
{
    FILE *out = stderr;
    int w= 10;

    fprintf(out,"Usage: %.*s [MODE] [OPTIONS]\n\n", SLICE(prog_name));

    fprintf(out, "MODE:\n");
    fprintf(out, "  %-*s %s\n", w, "query", "--name <dns-name> --type <rec-type> --server <ip-addr> --flags <flags> --tcp");
    fprintf(out, "  %-*s %s\n", w, "fuzz", "--type <rec-type> --server <ip-addr>");
    fprintf(out, "  %-*s %s\n", w, "response", "--id <trans-id> --name <dns-name> --answer <ip-addr> --output <pcap-file>");

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
    int ec = EXIT_FAILURE;

    if (!(gen = gen_create())) { ec = 1; goto done; }
    if (gen_init(gen) != 0)    { ec = 2; goto done; }
    if (gen_parse_argv(gen, argc, argv) != 0) { ec = 3;  goto done; }
    if (gen_signals(gen) != 0)  { ec = 4 ;goto done; }

    switch(gen->mode) {
    case MODE_QUERY: ec = gen_do_query(gen); break;
    case MODE_RESP:  ec = gen_do_resp(gen); break;
    case MODE_FUZZ:  ec = gen_do_fuzz(gen); break;
    default: ec = 5; break;
    }

done:
    if (gen) gen_free(gen);

    return ec;
}
