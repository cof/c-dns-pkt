/*
 * A DNS message codec API
 * -----------------------
 * General idea is use a dns_msg struture to read/write DNS messages.
 *
 * API
 * ---
 * validate_dns_packet(pkt_buf, pkt_len, emsg) : check pkt valid and print desc to esmg
 * dns_msg_decode(msg, buf, len) : decode buffer into a DNS message
 * dns_msg_encode(msg, buf, len) : encode DNS message into buffer
 *
 * DNS msg
 * -------
 * msg is a stucture defined as follows:
 *
 *  DNS msg - struct dns_msg 
 *   - hdr (id, flags, qd_count, an_count, ns_count, ar_count)
 *   - qd_recs - question section 
 *   - an_recs - answer section 
 *   - ns_recs - authority section
 *   - ar_recs - additional section
 *
 * Queston Section:
 *    num_qd - number of dns_quest
 *    qd_recs - array of dns_quest
 *    dns_quest - struct dns_quest
 *    - qname 
 *    - qtype
 *    - qclas
 *
 * an|ns|ar Sections - struct dns_sect
 *  num_rec - number of dns_rec
 *  rec     - array of dns_rec
 *
 * Record - struct dns_rec
 *  name, type,class ttl, rdlen
 *  Uses a union type to store RDATA
 *
 * Helpers
 * --------
 * dns_msg_sects_tostr(msg,buf,len) : print sections to str buffer
 * dns_msg_get_rec(msg) : get first rec if available
 * dns_msg_add_qd(msg,name, qtype, qclass) : add qd section
 * dns_msg_add_rec(msg, sc, rec) : add record to an|ns|ar section
 *
 * dns_msg_cnt_rec(mg) - count total records in msg
 * dns_rec_load(rec, sc, str) - load str repr of rec into record
 *
 * References
 * ----------
 * rfc1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
 * rfc6891 - Extension Mechanisms for DNS (EDNS(0))
 *
 */
#ifndef _DNS_PROTO_H_
#define _DNS_PROTO_H_

// Protocol Size limits
#define DNS_NAME_MAXLEN  255  // names  255 octets or less
#define DNS_NAME_MAXSTR  253  // 255 - len(1) - nul(1) = 253
#define DNS_LABEL_MAXSTR 63   // 63 octets or less
#define DNS_HDR_LEN      12   // header size
#define DNS_MAX_UDP     512   // can be overriden by EDNS

// Our limits
#define DNS_MAX_PDUSIZE  2048
#define DNS_EMSG_MAXLEN  4096
#define DNS_MAX_REC       32  // max section records 
#define DNS_MAX_TXT       32  // max txt string
#define DNS_COMP_PTR    0xC0  // 1100000 upper 2 bits
#define DNS_MAX_JMP       16  // max number of compression pointer jmps
#define DNS_MAX_SUFFIX    32  // max number of compression names

#define DNS_FAIL -1

// DNS header flags
#define DNS_FLAGS_QR      0x8000 // query response
#define DNS_FLAGS_OPCODE  0x7800 // 4 bit Opcode (0 .. 5)
#define DNS_FLAGS_CD      0x0800 // Checking Disabled (DNSSEC)
#define DNS_FLAGS_AA      0x0400 // Authoritative Answer
#define DNS_FLAGS_TC      0x0200 // Truncated
#define DNS_FLAGS_AD      0x0020 // Authentic Data
#define DNS_FLAGS_RD      0x0100 // Recursion Desired
#define DNS_FLAGS_RA      0x0080 // Recursion Available
#define DNS_FLAGS_RCODE   0x000F // 4 bit Response Code

// DNS opcodes
#define DNS_OPCODE_QUERY  0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2
#define DNS_OPCODE_NOTIFY 4
#define DNS_OPCODE_UPDATE 5

// DNS rcodes
#define DNS_RCODE_NOERROR  0
#define DNS_RCODE_FORMERR  1
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3
#define DNS_RCODE_NOTIMP   4
#define DNS_RCODE_REFUSED  5

// DNS Record Types (QTYPE / TYPE)
#define DNS_TYPE_A      1    // IPv4 Address
#define DNS_TYPE_NS     2    // Authoritative Name Server
#define DNS_TYPE_CNAME  5    // Canonical Name (Alias)
#define DNS_TYPE_SOA    6    // Start of Authority
#define DNS_TYPE_PTR    12   // Domain Name Pointer (Reverse DNS)
#define DNS_TYPE_HINFO  13   // Host Information
#define DNS_TYPE_MX     15   // Mail Exchange
#define DNS_TYPE_TXT    16   // Text Strings
#define DNS_TYPE_AAAA   28   // IPv6 Address
#define DNS_TYPE_SRV    33   // Service Locator
#define DNS_TYPE_OPT    41   // EDNS0 Options (RFC 6891) 
#define DNS_TYPE_ANY    255  // Wildcard match (Query only)

// DNS Classes (QCLASS / CLASS)
#define DNS_CLASS_IN    1    // Internet
#define DNS_CLASS_CS    2    // CSNET (Obsolete)
#define DNS_CLASS_CH    3    // CHAOS
#define DNS_CLASS_HS    4    // Hesiod
#define DNS_CLASS_ANY   255  // Wildcard match (Query only)

// Required structures
struct dns_header {
    uint16_t id;       // Transaction ID
    uint16_t flags;    // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qd_count;  // Number of Questions
    uint16_t an_count;// Number of Answer RRs
    uint16_t ns_count;// Number of Authority RRs
    uint16_t ar_count;// Number of Additional RRs
};

struct dns_question {
    char qname[256];
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_record {
    char name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t rdata[512];
};

// Required functions
int parse_dns_header(const uint8_t *buf, size_t len, struct dns_header *hdr);
int parse_dns_name(
    const uint8_t *pkt, size_t pkt_len, 
    size_t offset, char *out, size_t out_len, 
    size_t *bytes_consumed);
int validate_dns_packet(const uint8_t *pkt, size_t len, char *error_msg);


/*  
  A simple DNS message api

 */
const char *rcode_tostr(int rcode);
const char *dns_class_tostr(int ec);
const char *dns_type_tostr(int ec);

struct dns_quest {
    const char *qname;
    uint16_t qtype;
    uint16_t qclass;
};

// A record wrapper using union wrappers around RDATA
struct dns_rec {
    const char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl; 
    uint16_t rdlen;     
    union {
        uint8_t a[4];   // 1
        char *ns_name; // 2
        char *cname;   // 5
        struct {
            char *mname;
            char *rname;
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t min;
        } soa; // 6
        char *ptr_name; 
        struct {
            char *cpu_str;
            char *os_str;
        } hinfo; // 13
        struct {
            uint16_t pref;    
            char *name;
        } mx; // 15
        struct {
            uint16_t num_str;
            char *str[DNS_MAX_TXT];
        } txt; // 16
        uint8_t aaaa[16];  //  28
        struct {
            uint16_t prior;
            uint16_t weight;
            uint16_t port;
            char *name;
        } srv; // 33
        struct {
            uint16_t udp_size;
            uint32_t ttl_val;
            uint8_t ext_rcode;
            uint8_t edns_ver;
            uint8_t do_bit;
        } opt; // 41
        const uint8_t *raw;
    } data;
};

// dns section
struct dns_sect {
    size_t num_rec;
    struct dns_rec rec[DNS_MAX_REC];
};

// convert dns msg section to readable string
int dns_quest_tostr(struct dns_quest *quest, char *buf, size_t buf_len);
int dns_sect_tostr(struct dns_sect *sect, int sc, char *buf, size_t buf_len);
int dns_rec_tostr(struct dns_rec *rec, int sc, char *buf, size_t buf_len);

// DNS message
struct dns_msg {
    struct dns_header hdr;
    char names[DNS_MAX_PDUSIZE];
    int names_len;
    size_t num_qd;
    struct dns_quest qd_recs[DNS_MAX_REC];
    struct dns_sect an_recs;
    struct dns_sect ns_recs;
    struct dns_sect ar_recs;
};

// decode/encode a DNS message
int dns_msg_decode(struct dns_msg *msg, uint8_t *buf, size_t len);
ssize_t dns_msg_encode(struct dns_msg *msg, uint8_t *buf, size_t len);

// helper functions
int dns_msg_sects_tostr(struct dns_msg *msg,  char *buf, size_t len);

static inline void dns_msg_set_id_flags(struct dns_msg *msg, uint16_t id, uint16_t flags)
{
    msg->hdr.id = id;
    msg->hdr.flags = flags;
}

// DNS messaage sections
#define DNS_MSG_QD 1
#define DNS_MSG_AN 2
#define DNS_MSG_NS 3
#define DNS_MSG_AR 4

int dns_msg_add_qd(struct dns_msg *msg, const char *name, uint16_t qtype,  uint16_t qclass);
int dns_msg_add_rec(struct dns_msg *msg, int sc, struct dns_rec *rec);

static inline int dns_msg_num_an(struct dns_msg *msg)
{
    return msg->an_recs.num_rec;
}

static inline int dns_msg_num_ns(struct dns_msg *msg)
{
    return msg->ns_recs.num_rec;
}

static inline int dns_msg_num_ar(struct dns_msg *msg)
{
    return msg->ar_recs.num_rec;
}

static inline int dns_msg_cnt_rec(struct dns_msg *msg)
{
    int nrec = 0;

    nrec += dns_msg_num_an(msg);
    nrec += dns_msg_num_ns(msg);
    nrec += dns_msg_num_ar(msg);

    return nrec;
}

struct dns_rec *dns_msg_get_rec(struct dns_msg *msg);

int dns_get_type(const char *str);
int dns_get_class(const char *str);
int dns_get_flag(const char *str);
int dns_rec_load(struct dns_rec *rec, int sc, const char *str);

#endif
