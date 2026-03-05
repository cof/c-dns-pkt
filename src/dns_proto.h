#ifndef __DNS_PROTO_H__
#define __DNS_PROTO_H__

#define DNS_ERRBUF_SIZE 4096

#define DNS_ERR_NONE    0
#define DNS_ERR_HDRLEN  1
#define DNS_ERR_BADJMP  2
#define DNS_ERR_NUMJMP  3
#define DNS_ERR_OUTLEN  4
#define DNS_ERR_NONULL  5
#define DNS_ERR_TRUNC   6
#define DNS_ERR_TYPE_A      7   // IP4 address 
#define DNS_ERR_TYPE_NS     8   // Authoritative Name Server
#define DNS_ERR_TYPE_CNAME  9   // Canonical Name (Alias)
#define DNS_ERR_TYPE_SOA    10  // Start of Authority
#define DNS_ERR_TYPE_PTR    11  // Domain Name Pointer (Reverse DNS)
#define DNS_ERR_TYPE_HINFO  12  // Host Information
#define DNS_ERR_TYPE_MX     13  // Mail Exchange
#define DNS_ERR_TYPE_TXT    14  // Text Strings
#define DNS_ERR_TYPE_AAAA   15  // IPv6 Address
#define DNS_ERR_TYPE_SRV    16  // Service Locator
#define DNS_ERR_TYPE_OPT    17  // EDNS0 Options (RFC 6891)
#define DNS_ERR_TYPE_ANY    18  // Wildcard match (Query only)

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

#endif
