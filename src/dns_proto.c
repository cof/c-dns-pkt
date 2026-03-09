/*
 * A DNS protocol decoder
 *
 * Refs
 * ====
 *  rfc1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
 *  rfc6891 - Extension Mechanisms for DNS (EDNS(0))
 */

#include <errno.h>
#include <arpa/inet.h>   

#include "util.h"
#include "dns_proto.h"

// flag decoder error
#define DEC_ERR -1

// log error return err
#define dec_error_re(fmt, ...) \
    (_log_error(__FILE__, __LINE__, __func__, 0,  fmt, ##__VA_ARGS__), DEC_ERR)


#define DNS_MAX_EMSG 10
#define DNS_NAME_SIZE 256
#define DNS_MSG_SIZE 256 + 256 + 100 // big enough for 2 names + some extra

#define DNS_MAX_JMP 10 // max number of compression ptr jmps
#define DNS_MAX_UDP 512 // rfc1035 - can be overriden by EDNS0

struct dns_err {
    int group;
    int field;
    int ec;
};

struct dns_dec {
    const uint8_t *pkt_buf;
    size_t pkt_len;
    size_t consumed;
    size_t offset;
    struct dns_header hdr;
    // a simple error stack
    struct dns_err errs[DNS_MAX_EMSG];
    int nerr;
    // flags
    unsigned int got_edns : 1;
    unsigned int dnssec_ok : 1;
    // EDNS0 Options (RFC 6891)  
    int udp_size;
    uint8_t ext_rcode;
    uint8_t edns_ver;
    // track what we write into emsg
    struct rwbuf emsg;
    char msg[DNS_MSG_SIZE]; // dns_err_tostr
};

static char *dns_wmsg(struct dns_dec *dec, const char *fmt, ...) \
    __attribute__((format(printf, 2, 3)));

// decoders
static inline uint32_t dec_u32(const unsigned char *buf)
{
    uint32_t value;

    value = buf[0] << 24;
    value |= buf[1] << 16;
    value |= buf[2] << 8;
    value |= buf[3];

    return value;
}

static inline uint16_t dec_u16(const unsigned char *buf)
{
    uint16_t value;

    value = buf[0] << 8;
    value |= buf[1];

    return value;
}

// XXX - use xmacros to ensure both code and string match
#define DNS_ERRORS(X) \
    X(DNS_ERR_OK, "Okay") \
    X(DNS_ERR_HDRLEN, "header len") \
    X(DNS_ERR_BADJMP, "Invalid compression pointer (outside range)") \
    X(DNS_ERR_MAXJMP, "Invalid compression pointer (loop detected)") \
    X(DNS_ERR_NAMELEN, "Name length bigger than pkt size") \
    X(DNS_ERR_OUTLEN, "Name bigger than buf size") \
    X(DNS_ERR_NONULL, "Name missing null char") \
    X(DNS_ERR_TRUNC,  "Field truncated") \
    X(DNS_ERR_MINLEN, "Field smaller than min len") \
    X(DNS_ERR_FLDLEN, "Field length bigger than pkt") \
    X(DNS_ERR_OPTSECT, "OPT field not allowed") \
    X(DNS_ERR_NOSPACE, "No space in buffer")

#define DNS_ERROR_ENUM(NAME, TEXT) NAME,
#define DNS_ERROR_TEXT(NAME, TEXT) [NAME] = TEXT,

enum dns_dec_error {
    DNS_ERRORS(DNS_ERROR_ENUM)
};

static const char *dns_ec_tostr[] = {
    DNS_ERRORS(DNS_ERROR_TEXT)
};


// decode error locations
// XXX - use xmacros to ensure both code and string match
#define DNS_DECODES(X) \
    X(DNS_DEC_NONE, "NONE") \
    X(DNS_DEC_PDU,  "PDU") \
    X(DNS_DEC_HDR, "HDR") \
    X(DNS_DEC_QUESTION,   "Question") \
    X(DNS_DEC_ANSWER,     "Answer") \
    X(DNS_DEC_AUTHORITY,  "Authority") \
    X(DNS_DEC_ADDITIONAL, "Additional") \
    X(DNS_DEC_RECORD,     "Record") \
    X(DNS_DEC_RDATA,      "RDATA") \
    X(DNS_DEC_NAME,       "Name") \
    X(DNS_DEC_TYPE_A,     "A") \
    X(DNS_DEC_TYPE_NS,    "NS") \
    X(DNS_DEC_TYPE_CNAME, "CNAME") \
    X(DNS_DEC_TYPE_SOA,   "SOA") \
    X(DNS_DEC_TYPE_PTR,   "PTR") \
    X(DNS_DEC_TYPE_HINFO, "HINFO")\
    X(DNS_DEC_TYPE_MX,    "MX") \
    X(DNS_DEC_TYPE_TXT,   "TXT") \
    X(DNS_DEC_TYPE_AAAA,  "AAAA") \
    X(DNS_DEC_TYPE_SRV,   "SRV") \
    X(DNS_DEC_TYPE_OPT,   "OPT") \
    X(DNS_DEC_TYPE_ANY,   "ANY") 

#define DNS_DECODE_ENUM(NAME, TEXT) NAME,
#define DNS_DECODE_TEXT(NAME, TEXT) [NAME] = TEXT,

enum dns_dec_code {
    DNS_DECODES(DNS_DECODE_ENUM)
};

static const char *dec_code_tostr[] = {
    DNS_DECODES(DNS_DECODE_TEXT)
};

const char *dns_class_tostr(int ec, const char *def)
{
    if (ec == 0) return "";
    if (ec == 1) return "IN";
    if (ec == 3) return "CH";
    if (ec == 4) return "HS";
    if (ec == 254) return "NONE";
    if (ec == 255) return "*";

    return def ?: "???";
};

const char *dns_type_tostr(int ec, const char *def)
{
    if (ec == 1) return "A";
    if (ec == 2)  return "NS";
    if (ec == 5)  return "CNAME";
    if (ec == 6)  return "SOA";
    if (ec == 12) return "PTR";
    if (ec == 15) return "MX";
    if (ec == 16) return "TXT";
    if (ec == 28) return "AAAA";
    if (ec == 33) return "SRV";
    if (ec == 41) return "OPT";
    if (ec == 252) return "AXFR";
    if (ec == 255)  return "ANY";

    return def ?: "???";
}

static const char *opcode_tostr[] = {
    [DNS_OPCODE_QUERY]  = "QUERY",
    [DNS_OPCODE_IQUERY] = "IQUERY",
    [DNS_OPCODE_STATUS] = "STATUS",
    [3] = "3",
    [DNS_OPCODE_NOTIFY] = "NOTIFY",
    [DNS_OPCODE_UPDATE ] = "UPDATE"
};

static const char *rcode_tostr[] = {
    [DNS_RCODE_NOERROR]  = "NoError",
    [DNS_RCODE_FORMERR]  = "FormErr",
    [DNS_RCODE_SERVFAIL] = "ServFail",
    [DNS_RCODE_NXDOMAIN] = "NXDomain",
    [DNS_RCODE_NOTIMP]   = "NotImp",
    [DNS_RCODE_REFUSED]  = "Refused",
    [6] = "YXDomain",
    [7] = "YXRRSet",
    [8] = "NXRRSet",
    [9] = "NotAuth",
    [10] = "NotZone",
    // 11 - 15 Available for assignment
    [16] = "BADVERSA",
    [16] = "BADSIG",
    [17] = "BADKEYA",
    [18] = "BADTIME",
    [19] = "BADMODE",
    [20] = "BADNAMEA",
    [21] = "BADALGA",
    [22] = "BADTRUC"
};


static char *dns_wmsg(struct dns_dec *dec, const char *fmt, ...) 
{
    va_list args;
    struct rwbuf *buf;
    int nw;

    buf = &dec->emsg;
    va_start(args, fmt);
    nw = vsnprintf(rwbuf_wpos(buf), rwbuf_wrem(buf), fmt, args);
    va_end(args);

    if (nw < 0 || nw >= rwbuf_wrem(buf)) {
        log_error("wbuffer full");
        return NULL;
    }

    // return ptr where we stored messge
    return rwbuf_wres(buf, nw);
}

int dns_dec_err(struct dns_dec *dec, int group, int field, int ec)
{
    if (dec->nerr >= ARR_LEN(dec->errs)) {
        return dec_error_re("No room for err  %d %d %d", group, field, ec);
    }

    dec->errs[dec->nerr].group = group;
    dec->errs[dec->nerr].field = field;
    dec->errs[dec->nerr].ec = ec;
    dec->nerr++;

    // all done
    return 0;
}

char *dns_err_tostr(struct dns_dec *dec, struct dns_err *err)
{
    const char *group = ec_tostr(ARRAY(dec_code_tostr), err->group, "???");
    const char *field = ec_tostr(ARRAY(dec_code_tostr), err->field, "???");
    const char *error = ec_tostr(ARRAY(dns_ec_tostr), err->ec, "???");

    int nw = snprintf(dec->msg, sizeof(dec->msg), "%s %s %s", group, field, error);
    if (nw < 0 || nw >= sizeof(dec->msg)) {
        return log_errorn("snprinf dns error failed nw=%d", nw);
    }

    // all done
    return dec->msg;
}

static int dns_dec_genmsg(struct dns_dec *dec)
{
    if (!dec->nerr) {
        if (!rwbuf_avail(&dec->emsg)) {
            // decoders desc failed ?
            dns_wmsg(dec, "[ERROR] Missing PDU desc");
        }
        // done
        return 0;
    }

    // desribe error
    dns_wmsg(dec, "[ERROR] ");
    if (dec->pkt_len > sizeof(dec->hdr)) {
        // have a hdr
        dns_wmsg(dec, "ID 0x%04x ",  dec->hdr.id);
    }

    // build the erro strng
    for (int i = dec->nerr - 1; i >=  0; i--) {
        char *estr = dns_err_tostr(dec, &dec->errs[i]);
        dns_wmsg(dec, " %s", estr);
    }

    dns_wmsg(dec, "\n");

    // ERROR
    return -1;
}

// Required functions
int parse_dns_header(const uint8_t *buf, size_t len, struct dns_header *hdr)
{
    if (len < sizeof(*hdr)) {
        // too small
        return DNS_ERR_HDRLEN;
    }

    // decode the header
    hdr->id       = dec_u16(buf + 0);
    hdr->flags    = dec_u16(buf + 2);
    hdr->qd_count = dec_u16(buf + 4);
    hdr->an_count = dec_u16(buf + 6);
    hdr->ns_count = dec_u16(buf + 8);
    hdr->ar_count = dec_u16(buf + 10);

    // all done
    return 0;
}

// Required functions
int parse_dns_name(
    const uint8_t *pkt, size_t pkt_len, size_t offset, 
    char *out, size_t out_len, 
    size_t *bytes_consumed)
{
    int ridx = offset;
    int njmp = 0;
    int len = 0;

    *bytes_consumed = 0;

    while (ridx < pkt_len) {
        int len = pkt[ridx++];
        if ((len & 0xc0) == 0xc0) {
            //  compression pointer - rfc1035 - 4.1.4. Message compression  
            if (ridx == pkt_len) return DNS_ERR_BADJMP; 
            if (njmp++ > DNS_MAX_JMP) return DNS_ERR_MAXJMP;
            if (njmp == 1) *bytes_consumed += 2;
            len = ((len & 0x3F) << 8) | pkt[ridx];
            if (len < 12) return DNS_ERR_BADJMP;
            if (len > pkt_len) return DNS_ERR_BADJMP;
            ridx = len;
            continue;
        }

        // label - len (0-63)
        int pkt_rem = pkt_len - ridx;
        if (len > pkt_rem) return DNS_ERR_NAMELEN;
        if (len > out_len) return DNS_ERR_OUTLEN; 
        if (!njmp) *bytes_consumed += 1 + len;

        // null check
        if (len == 0) break;
    
        // copy label
        if (out) {
            memcpy(out, pkt + ridx, len);
            out += len;
        }
        out_len -= len;
        ridx += len;

        // add a dot    
        if (!out_len) return DNS_ERR_OUTLEN;
        if (ridx < pkt_len && pkt[ridx] != 0) {
            // store the dot
            if (out) *out++ = '.';
            out_len--;
        }
    }

    // did we stop at 0
    if (len != 0) return DNS_ERR_NONULL;

    // null-terminate
    if (!out_len) return DNS_ERR_OUTLEN;
    if (out) *out = '\0';

    // all done    
    return 0;
}

static int dns_dec_record(struct dns_dec *dec, int section, struct dns_record *rec)
{
    size_t consumed;
    size_t offset;
    int ec; 
    char ip_addr[INET_ADDRSTRLEN];
    char *rdata_desc;
    char num[2][10];

    // label
    ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, rec->name, sizeof(rec->name), &consumed);
    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_NAME, ec);
    }
    dec->offset += consumed;

    // need 10 bytes for header
    if (dec->offset + 10 > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_HDR, DNS_ERR_TRUNC);
    }

    rec->type   = dec_u16(dec->pkt_buf + dec->offset + 0);
    rec->class  = dec_u16(dec->pkt_buf + dec->offset + 2);
    rec->ttl    = dec_u32(dec->pkt_buf + dec->offset + 4);
    rec->rdlength = dec_u16(dec->pkt_buf + dec->offset + 8);

    // rdata
    dec->offset += 10;
    if (dec->offset + rec->rdlength > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_RDATA, DNS_ERR_TRUNC);
    }

    rdata_desc = "";

    // decode rdata
    switch(rec->type) {
    case DNS_TYPE_A: // IP4 address
        // integer
        if (rec->rdlength != 4) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_A, DNS_ERR_MINLEN);
        }
        if (inet_ntop(AF_INET, dec->pkt_buf + dec->offset, dec->msg, sizeof(dec->msg)) == NULL) {
            log_errno("inet_ntop failed to decode IPv4 addr");
            strcpy(dec->msg, "???");
        }
        rdata_desc = dec->msg;
        break;
    case DNS_TYPE_NS: //  Authoritative Name Server
        if (rec->rdlength < 1) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_NS, DNS_ERR_MINLEN);
        }
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, dec->msg, sizeof(dec->msg), &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_NS, ec);
        }
        rdata_desc = dec->msg;
        break;
    case DNS_TYPE_CNAME: // Canonical Name (Alias)
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, dec->msg, sizeof(dec->msg), &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_CNAME, ec);
        }
        rdata_desc = dec->msg;
        break;
    case DNS_TYPE_SOA: { // Start of Authority
        // name + name + 5 integers
        // Primary Master Name Server - MNAME
        offset = dec->offset;
        char *wptr = dec->msg;
        char *wptr_end = wptr + sizeof(dec->msg);
        int nw = snprintf(wptr, wptr_end - wptr, "MNAME=");
        wptr += nw;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, offset, wptr, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, ec);
        }
        offset += consumed;
        wptr += consumed;
        *wptr++ = ' ';
        // Responsible Person's Email - RNAME
        nw += snprintf(wptr, wptr_end - wptr, "RNAME=");
        wptr += nw;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, offset, wptr, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, ec);
        }
        offset += consumed;
        wptr += consumed;
        *wptr++ = ' ';
        // serial + refresh + retry + expire + mininum (5 x 32 bit ints)
        if (offset + 20 > dec->offset + rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, DNS_ERR_TRUNC);
        }
        char *names[5] = { "serial","refresh", "retry", "expire", "mininum" };
        uint32_t vals[5];
        memcpy(vals, dec->pkt_buf + offset, 20);
        for (int i = 0; i < 5; i++) {
            vals[i] = ntohl(vals[i]);
            nw = snprintf(wptr, wptr_end - wptr, " %s=%u", names[i], vals[i]);
        }
        // "MNAME=%s RNAME=%s %u %u %u %u %u"
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_PTR:  // Domain Name Pointer (Reverse DNS)
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, dec->msg, sizeof(dec->msg), &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_CNAME, ec);
        }
        rdata_desc = dec->msg;
        break;
    case DNS_TYPE_HINFO: { // Host Information
        if (rec->rdlength < 2) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_MINLEN);
        }
        uint8_t cpu_len = dec->pkt_buf[dec->offset];
        if (cpu_len + 1 > rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        uint8_t os_offset = 1 + cpu_len;
        if (os_offset >= rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        uint8_t os_len = dec->pkt_buf[dec->offset + os_offset];
        if (os_len + 1 + os_len != rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        break;
    }
    case DNS_TYPE_MX: {  // Mail Exchange 
        if (rec->rdlength < 3)  {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_MX, DNS_ERR_MINLEN);
        }
        char *wptr = dec->msg;
        char *wptr_end = wptr + sizeof(dec->msg);
        // preference
        uint16_t preference = dec_u16(dec->pkt_buf + dec->offset);
        int nw = snprintf(wptr, wptr_end - wptr, "%d ", preference);
        wptr += nw;
        // Mail Server Name
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset + 2, wptr, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_MX, ec);
        }
        // parse_dns_name adds a nul
        wptr += consumed;
        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_TXT: { // Text Strings

        unsigned const char *rdata_ptr = dec->pkt_buf + dec->offset;
        char *wptr = dec->msg;
        char *wptr_end = wptr + sizeof(dec->msg);
        int ridx = 0;

        while (ridx < rec->rdlength) {
            // Length
            uint8_t txt_len = dec->pkt_buf[ridx++];
            if (ridx + txt_len > rec->rdlength) {
                return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_TXT, DNS_ERR_FLDLEN);
            }
            // Text
            if (wptr + txt_len > wptr_end) {
                log_error("DNS_TYPE_TXT string longer than desc buffer");
                break;
            }
            wptr = mempcpy(wptr, rdata_ptr + ridx , txt_len);
            *wptr++ = ' ';
            ridx += txt_len;
        }
        *wptr = '\0';
        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_AAAA:  // IPv6 Address
        if (rec->rdlength != 16) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_AAAA, DNS_ERR_MINLEN);
        }
        if (inet_ntop(AF_INET6, dec->pkt_buf + dec->offset, dec->msg, sizeof(dec->msg)) == NULL) {
            log_errno("inet_ntop failed to decode IPv6 addr");
            strcpy(ip_addr, "???");
        }
        rdata_desc = dec->msg;
        break;
    case DNS_TYPE_SRV: { // Service Locator
        // 2 + 2 + 2 + target
        if (rec->rdlength < 7) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SRV, DNS_ERR_MINLEN);
        }
        uint16_t prior = dec_u16(dec->pkt_buf + dec->offset + 0);
        uint16_t weight = dec_u16(dec->pkt_buf + dec->offset + 2);
        uint16_t port = dec_u16(dec->pkt_buf + dec->offset + 4);
        char *wptr = dec->msg;
        char *wptr_end = wptr + sizeof(dec->msg);
        int nw = snprintf(dec->msg, wptr_end - wptr, "Priority %d Weight %d port %d ", prior, weight, port);
        wptr += nw;
        // name
        int ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset + 6, wptr, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SRV, ec);
        }
        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_OPT: { // EDNS0 Options (RFC 6891)
        if (section != DNS_DEC_ADDITIONAL) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_OPT, DNS_ERR_OPTSECT);
        }
        size_t offset = dec->offset - 8;
        if (!*rec->name)  {
            strcpy(rec->name, "<Root>");
        }
        rec->class = 0;
        uint16_t udp_size = dec_u16(dec->pkt_buf + offset);
        uint32_t ttl_val  = dec_u32(dec->pkt_buf + offset + 2);
        uint8_t ext_rcode = (ttl_val >> 24) & 0xFF;
        uint8_t version   = (ttl_val >> 16) & 0xFF;
        uint8_t do_bit   = (ttl_val & 0x8000);
        snprintf(dec->msg, sizeof(dec->msg),
            "UDP-size:%d Ext-RCODE:%d EDNS0:%d DNSEC-OK:%d",
            udp_size, ext_rcode, version, !!do_bit);
        // store these values
        dec->got_edns = 1;
        dec->udp_size = udp_size;
        dec->ext_rcode = ext_rcode;
        dec->edns_ver = version;
        dec->dnssec_ok = !!do_bit;
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_ANY: // Wildcard match (Query only) 
        break;
    default:
        break;
    }

    // next row
    dec->offset += rec->rdlength;

    itoa(num[0], 10, rec->class); 
    itoa(num[1], 10, rec->type);

    // desc PDU as we decode
    dns_wmsg(dec, "  %s: %s %s %s %s\n",
        ec_tostr(ARRAY(dec_code_tostr), section, "???"),
        rec->name, dns_class_tostr(rec->class, num[0]), 
        dns_type_tostr(rec->type, num[1]),
        rdata_desc
    );

    // all done
    return 0;
}

static int dns_dec_section(struct dns_dec *dec, int section, int rows)
{
    struct dns_record rec;

    for (int i = 0; i < rows; i++) {
        if (dns_dec_record(dec, section, &rec) != 0) {
            return dns_dec_err(dec, DNS_DEC_PDU, section, i);
        }
    }

    return 0;
}

static int dns_dec_question(struct dns_dec *dec, struct dns_question *quest)
{
    size_t consumed;
    int ec; 
    char num[2][10];

    // label
    ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, quest->qname, sizeof(quest->qname), &consumed);
    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_QUESTION, DNS_DEC_NAME, ec);
    }

    dec->offset += consumed;
    if (dec->offset + 4 > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_QUESTION, DNS_DEC_HDR, DNS_ERR_TRUNC);
    }

    quest->qtype  = dec_u16(dec->pkt_buf + dec->offset);
    quest->qclass = dec_u16(dec->pkt_buf + dec->offset + 2);
    dec->offset += 4;

    itoa(num[0], 10, quest->qclass); 
    itoa(num[1], 10, quest->qtype);

    // desc PDU as we decode
    dns_wmsg(dec, "  %s: %s %s %s\n",
        "Question", quest->qname, 
        dns_class_tostr(quest->qclass, num[0]), 
        dns_type_tostr(quest->qtype,  num[1])
    );

    // all done
    return 0;
}

static int dns_dec_questions(struct dns_dec *dec)
{
    struct dns_question quest;

    for (int i = 0; i < dec->hdr.qd_count; i++) {
        if (dns_dec_question(dec, &quest) != 0) {
            return dns_dec_err(dec, DNS_DEC_PDU, DNS_DEC_QUESTION, i);
        }
    }

    return 0;
}

static int dns_dec_header(struct dns_dec *dec)
{
    int ec = parse_dns_header(dec->pkt_buf, dec->pkt_len, &dec->hdr);

    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_PDU, DNS_DEC_HDR, ec);
    }
    dec->offset += sizeof(struct dns_header);

    char num[2][10];
    struct dns_header *hdr = &dec->hdr;
    int qr = hdr->flags & DNS_FLAGS_QR ? 0 : 1;
    int opcode  = (hdr->flags & DNS_FLAGS_OPCODE) >> 11;
    const char *opcode_str = ec_tostr(ARRAY(opcode_tostr), opcode, itoa(num[0],10, opcode));
    const char *type_str = qr ? "RESPONSE" : "QUERY";

    char extra[100];
    struct rwbuf buf = RWBUF_INIT(extra, sizeof(extra));
    extra[0] = '\0';

    if (qr) {
        // query response
        int as = hdr->flags & DNS_FLAGS_AA ? 1 : 0;
        int tc = (hdr->flags & DNS_FLAGS_TC) ? 1 : 0;
        int rd = hdr->flags & DNS_FLAGS_RD ? 1 : 0;
        int ra = hdr->flags & DNS_FLAGS_RA ? 1 : 0;
        int rcode = hdr->flags & DNS_FLAGS_RCODE;

        // add flags
        if (as) rwbuf_strcat_sep(&buf, ' ', STR_LIT("AS:1"));
        if (tc) rwbuf_strcat_sep(&buf, ' ', STR_LIT("TC:1"));
        if (rd) rwbuf_strcat_sep(&buf, ' ', STR_LIT("RD:1"));
        if (ra) rwbuf_strcat_sep(&buf, ' ', STR_LIT("RA:1"));

        // convert RCODE to str
        itoa(num[1],10,rcode);
        const char *rcode_str = ec_tostr(ARRAY(rcode_tostr), rcode, num[1]);
        rwbuf_strcat_sep(&buf, ' ', STR_LIT("RCODE:"));
        rwbuf_strcat(&buf, rcode_str, strlen(rcode_str));

        // validate OPCODE range
        if (opcode == 3 || opcode > 5) {
            rwbuf_strcat_sep(&buf, ' ', STR_LIT("bad-opcode"));
        }

        // validate RCODE range
        if (rcode > 10) {
            rwbuf_strcat_sep(&buf, ' ', STR_LIT("bad-rcode"));
        }
    }
    else {
        // query
        int tc = (hdr->flags & DNS_FLAGS_TC) ? 1 : 0;
        int rd = (hdr->flags & DNS_FLAGS_RD) ? 1 : 0;
        int ad = (hdr->flags & DNS_FLAGS_AD) ? 1 : 0;   

        // add flags
        if (tc) rwbuf_strcat_sep(&buf, ' ', STR_LIT("TC:1"));
        if (rd) rwbuf_strcat_sep(&buf, ' ', STR_LIT("RD:1"));
        if (ad) rwbuf_strcat_sep(&buf, ' ', STR_LIT("AD:1"));

        // validate OPCODE range
        if (opcode == 3 || opcode > 5) {
            rwbuf_strcat_sep(&buf, ' ', STR_LIT("bad-opcode"));
        }
    }

    // desc PDU as we decode
    dns_wmsg(dec,
        "[%s] ID 0x%04x QR:%d OPCODE:%s %.*s\n",
        type_str, dec->hdr.id, qr, opcode_str, buf.widx, buf.data);

    return 0;
}


// Required functions
int validate_dns_packet(const uint8_t *pkt_buf, size_t pkt_len, char *emsg)
{
    struct dns_dec tmp = {
        .pkt_buf = pkt_buf,
        .pkt_len = pkt_len,
        .udp_size = DNS_MAX_UDP,
        .emsg = RWBUF_INIT(emsg, DNS_ERRBUF_SIZE)
    };
    struct dns_dec *dec = &tmp;

    if ( (dns_dec_header(dec)) != 0) goto done;
    if ( (dns_dec_questions(dec)) != 0) goto done;
    if ( (dns_dec_section(dec, DNS_DEC_ANSWER,  dec->hdr.an_count)) != 0)  goto done;
    if ( (dns_dec_section(dec, DNS_DEC_AUTHORITY, dec->hdr.ns_count)) != 0) goto done;
    if ( (dns_dec_section(dec, DNS_DEC_ADDITIONAL, dec->hdr.ar_count)) != 0) goto done;

    if (pkt_len > dec->udp_size) {
        // Check packet doesn't exceed 512 bytes (UDP) or declared length
        dns_wmsg(dec, "UDP message: packet-length %zu > max size %d\n", pkt_len, dec->udp_size);
    }

done:
    return dns_dec_genmsg(dec);
}

// DNS encoder 
static inline uint8_t *enc_u32(uint8_t *wpos, uint32_t value)
{
    *wpos++ = value >> 24;
    *wpos++ = value >> 16;
    *wpos++ = value >> 8;
    *wpos++ = value;

    return wpos;
}

static inline uint8_t *enc_u16(uint8_t *wpos, uint16_t value)
{
    *wpos++ = value >> 8;
    *wpos++ = value;

    return wpos;
}

static int dns_enc_hdr(uint8_t *buf, size_t len, const struct dns_header *hdr)  
{
    if (len < sizeof(*hdr)) {
        return -1;
    }
    
    enc_u16(buf + 0,  hdr->id);
    enc_u16(buf + 2,  hdr->flags);
    enc_u16(buf + 4,  hdr->qd_count);
    enc_u16(buf + 6,  hdr->an_count);
    enc_u16(buf + 8,  hdr->ns_count);
    enc_u16(buf + 10, hdr->ar_count);

    return 0;
}

static int dns_enc_name(uint8_t *pkt, size_t pkt_len, size_t offset, const char *name)
{
    uint8_t *dst = pkt + offset;
    uint8_t *len_pos = dst++;
    int len = 0;
    
    while (*name) {
        if (*name == '.') {
            *len_pos = len;
            len_pos = dst++;
            len = 0;
        }
        else {
            *dst++ = *name;
            len++;
        }
        name++;
    }

    // final label - drop a nul
    *len_pos = len;
    *dst++ = 0;

    // return bytes written
    return dst - (pkt + offset);
}

static int dns_enc_question(struct dns_enc *enc, struct dns_question *quest)
{
    int nw = dns_enc_name(enc->pkt_buf, enc->pkt_max, enc->offset, quest->qname);
    enc->offset += nw;

    enc_u16(enc->pkt_buf + enc->offset + 0,  quest->qtype);
    enc_u16(enc->pkt_buf + enc->offset + 2,  quest->qclass);
    enc->offset += 4;

    enc->hdr.qd_count++;

    return 0;
}

int dns_enc_start(struct dns_enc *enc, uint16_t tid, uint16_t flags)
{
    enc->offset += sizeof(enc->hdr);
    enc->hdr.id = tid;
    enc->hdr.flags = flags;

    return 0;
}

int dns_enc_end(struct dns_enc *enc)
{
    enc->pkt_len = enc->offset;
    dns_enc_hdr(enc->pkt_buf, enc->pkt_len, &enc->hdr);

    return enc->offset;
}

int dns_enc_query_start(struct dns_enc *enc, uint16_t tid, uint8_t recur_desired, uint8_t dns_sec)
{
    uint16_t opcode = DNS_OPCODE_QUERY;
    uint16_t flags = opcode << 11;
    if (recur_desired) flags |= DNS_FLAGS_RD;
    if (dns_sec) flags |= DNS_FLAGS_AD;

    return dns_enc_start(enc, tid, flags);
}

int dns_enc_add_quest(struct dns_enc *enc, const char *name, uint16_t qtype,  uint16_t qclass)
{
    struct dns_question quest;

    memcpy(quest.qname, name, strlen(name) + 1);
    quest.qtype = qtype  ?: DNS_TYPE_A;
    quest.qclass = qclass ?: DNS_CLASS_IN;

    return dns_enc_question(enc, &quest);
}
