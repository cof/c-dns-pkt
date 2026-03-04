/*
 *
 */

#include <arpa/inet.h>   

#include "util.h"
#include "dns_proto.h"

static int dns_err(int ec, char *msg_buf, const char *fmt, ...)
{
    va_list args;  

    va_start(args, fmt);
    vsnprintf(msg_buf, DNS_ERRBUF_SIZE, fmt, args);
    va_end(args);

    return ec;
}

// Required functions
int parse_dns_header(const uint8_t *buf, size_t len, struct dns_header *hdr)
{
    if (len < sizeof(*hdr)) {
        // too small
        return -1;
    }

    // decode the header
    hdr->id       = decode_u32(buf + 0);
    hdr->flags    = decode_u32(buf + 2);
    hdr->qd_count = decode_u32(buf + 4);
    hdr->an_count = decode_u32(buf + 6);
    hdr->ns_count = decode_u32(buf + 8);
    hdr->ar_count = decode_u32(buf + 10);

    // return num bytes processed ?
    return sizeof(*hdr);
}


int parse_dns_name(
    const uint8_t *pkt, size_t pkt_len, 
    size_t offset, char *out, size_t out_len, 
    size_t *bytes_consumed)
{
    return 0;
}


// bad design error_msg should be char ** ???

int validate_dns_packet(const uint8_t *pkt, size_t len, char *emsg)
{
    struct dns_header hdr;

    int nread = parse_dns_header(pkt, len, &hdr);
    if (nread < 0) {
        return dns_err(-1, emsg, "DNS packet len %fd header too small for hdr", len);
    }

    len -= nread;
    pkt += nread;

    // all done
    return 0;
}
