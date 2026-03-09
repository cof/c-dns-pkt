#ifndef __DNS_PROTO_H__
#define __DNS_PROTO_H__

#define DNS_ERRBUF_SIZE 4096
#define DNS_MAX_PDU 2048
#define DNS_MAX_NAME 253

// DNS header flags
#define DNS_FLAGS_QR      0x8000 // query response
#define DNS_FLAGS_OPCODE  0x7800 // 4 bit Opcode (0 .. 5)
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


const char *dns_class_tostr(int ec, const char *def);
const char *dns_type_tostr(int ec, const char *def);

// A simple dns pkt encoder
struct dns_enc {
    uint8_t *pkt_buf;
    size_t pkt_len;  
    size_t pkt_max;  
    size_t offset;
    struct dns_header hdr;
};

int dns_enc_start(struct dns_enc *enc, uint16_t tid, uint16_t flags);
int dns_enc_end(struct dns_enc *enc);
int dns_enc_query_start(struct dns_enc *enc, uint16_t tid, uint8_t recur_desired, uint8_t dns_sec);
int dns_enc_add_quest(struct dns_enc *enc, const char *name, uint16_t qtype,  uint16_t qclass);

#endif
