#ifndef __DNS_PROTO_H__
#define __DNS_PROTO_H__

#define DNS_EMSG_MAXLEN 4096
#define DNS_MAX_PDUSIZE 2048
#define DNS_NAME_MAXLEN 255
#define DNS_NAME_MAXSTR 253
#define DNS_MAX_REC     16
#define DNS_HDR_LEN     12

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

// helper api
const char *rcode_tostr(int rcode, const char *def_str);

// 4.1.2. Question section format
struct dns_quest {
    const char *qname;
    uint16_t qtype;
    uint16_t qclass;
};


// 4.1.3. Resource record format
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
            uint8_t cpu_len;
            uint8_t os_offset;
            uint8_t os_len;
        } hinfo; // 13
        struct {
            uint16_t pref;    
            char *name;
        } mx; // 15
        char *txt; // 16
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

struct dns_sect {
    int num_rec;
    struct dns_rec rec[DNS_MAX_REC];
};

struct dns_msg {
    struct dns_header hdr;
    char names[DNS_MAX_PDUSIZE];
    int names_len;
    int num_quest;
    struct dns_quest quest[DNS_MAX_REC];
    struct dns_sect ans;
    struct dns_sect auth;
    struct dns_sect add;
};

int dns_decode_msg(struct dns_msg *msg, uint8_t *buf, size_t len);

const char *dns_class_tostr(int ec, const char *def);
const char *dns_type_tostr(int ec, const char *def);
int dns_rec_tostr(char *buf, size_t buf_len, struct dns_rec *rec);

// A simple dns pkt encoder
struct dns_enc {
    struct dns_header hdr;
    uint8_t *pkt_buf;
    size_t pkt_max;
    size_t pkt_len;
};

int dns_enc_start(struct dns_enc *enc, uint16_t tid, uint16_t flags);
int dns_enc_end(struct dns_enc *enc);
int dns_enc_add_quest(struct dns_enc *enc, const char *name, uint16_t qtype,  uint16_t qclass);

#endif
