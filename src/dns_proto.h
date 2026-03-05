#ifndef __DNS_PROTO_H__
#define __DNS_PROTO_H__

#define DNS_ERRBUF_SIZE 4096

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
