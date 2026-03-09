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
#define DNS_MSG_SIZE (256 + 256 + 100) // big enough for 2 names + some extra

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
    // a simple error stack
    struct dns_err errs[DNS_MAX_EMSG];
    int nerr;
    // flags
    unsigned int need_emsg : 1;
    unsigned int load_msg : 1;
    unsigned int got_edns : 1;
    unsigned int dnssec_ok : 1;
    // EDNS0 Options (RFC 6891)  
    int udp_size;
    uint8_t ext_rcode;
    uint8_t edns_ver;
    // track what we write into emsg
    struct dns_header hdr;
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

/*
static const char *sect_code_tostr(int sect_code)
{
    return ec_tostr(ARRAY(dec_code_tostr), sect_code, "???");
}
*/

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

static const char *rcode_strs[] = {
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

const char *rcode_tostr(int rcode, const char *def_str)
{
    return ec_tostr(ARRAY(rcode_strs), rcode, def_str);
}

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
        errno = ENOBUFS;
        return log_errno_rn("dns_wnsg: writer failed");
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
    if (dec->pkt_len >= DNS_HDR_LEN) {
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
    if (len < DNS_HDR_LEN) {
        // too small
        return DNS_ERR_HDRLEN;
    }

    // decode hdr
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

int dns_rec_tostr(char *buf, size_t buf_len, struct dns_rec *rec)
{
    char ip_addr[INET_ADDRSTRLEN];
    char num[2][10];
    itoa(num[0], 10, rec->class); 
    itoa(num[1], 10, rec->type);

    char *wptr = buf;
    char *wptr_end = wptr + buf_len;

    // prefix
    wptr += snprintf(wptr, wptr_end - wptr,
        "  %s %s %s ",
        rec->name, 
        dns_class_tostr(rec->class, num[0]), 
        dns_type_tostr(rec->type, num[1])
    );

    const char *desc = "";

    switch(rec->type) {
    case DNS_TYPE_A: // IP4 address
        if (inet_ntop(AF_INET, rec->data.a, ip_addr, sizeof(ip_addr)) == NULL) {
            log_errno("inet_ntop failed to decode IPv4 addr");
            strcpy(ip_addr, "???");
        }
        desc = ip_addr;
        break;
    case DNS_TYPE_NS: // Authoritative Name Server
        desc = rec->data.ns_name;
        break;
    case DNS_TYPE_CNAME: // Canonical Name (Alias)
        desc = rec->data.cname;
        break;
    case DNS_TYPE_SOA: // Start of Authority
        // name + name + 5 integers
        wptr += snprintf(wptr, wptr_end - wptr, 
            "MNAME=%s RNAME=%s %u %u %u %u %u",
            rec->data.soa.mname,
            rec->data.soa.rname,
            rec->data.soa.serial,
            rec->data.soa.refresh,
            rec->data.soa.retry,
            rec->data.soa.expire,
            rec->data.soa.min);
        break;
    case DNS_TYPE_PTR:  // Domain Name Pointer (Reverse DNS)
        desc = rec->data.ptr_name;
        break;
    case DNS_TYPE_HINFO: // Host Information
        wptr += snprintf(wptr, wptr_end - wptr, 
            "cpu_len=%d os_offset=%d os_len=%d", 
            rec->data.hinfo.cpu_len,
            rec->data.hinfo.os_offset,
            rec->data.hinfo.os_len);
        break;
    case DNS_TYPE_MX: // Mail Exchange 
        wptr += snprintf(wptr, wptr_end - wptr, 
            "Pref %d MX %s",
            rec->data.mx.pref,
            rec->data.mx.name);
        break;
    case DNS_TYPE_TXT:
        desc = rec->data.txt;
        break;
    case DNS_TYPE_AAAA:  // IPv6 Address
        if (inet_ntop(AF_INET6, rec->data.aaaa, ip_addr, sizeof(ip_addr)) == NULL) {
            log_errno("inet_ntop failed to decode IPv6 addr");
            strcpy(ip_addr, "???");
        }
        desc = ip_addr;
        break;
    case DNS_TYPE_SRV: // Service Locator
        wptr += snprintf(wptr, wptr_end - wptr, 
            "Priority %d Weight %d Port %d SRV %s", 
            rec->data.srv.prior, 
            rec->data.srv.weight, 
            rec->data.srv.port,
            rec->data.srv.name);
        break;
    default:
        break;
    }

    // suffix
    wptr += snprintf(wptr, wptr_end - wptr, "  %s\n", desc);

    // bytes written
    return wptr - buf;
}

static char *msg_store_name(struct dns_msg *msg, const char *name)
{
    size_t len = strlen(name);

    // space for name + nul ?
    if (msg->names_len + len + 1 > sizeof(msg->names)) {
        errno = ENOBUFS;
        return NULL;
    }

    // copy name
    char *str = msg->names + msg->names_len;
    memcpy(str, name, len);
    str[len] = '\0';
    msg->names_len += len + 1;

    return str;
}

static int parse_record(struct dns_dec *dec, struct dns_msg *msg, 
    int sect_code, struct dns_sect *sect)
{
    // grab next section rec
    struct dns_rec *rec = NULL;
    if (dec->load_msg) {
        if (sect->num_rec >= ARR_LEN(sect->rec)) {
            return log_error_rf("No space to store %d record", sect_code);
        }
        rec = &sect->rec[sect->num_rec];
    }

    // 3.2. RR definitions
    char *wptr = dec->msg;
    char *wptr_end = wptr + sizeof(dec->msg);

    // name
    char *name = wptr;
    size_t consumed;
    int ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, name, wptr_end - wptr,  &consumed);
    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_NAME, ec);
    }
    wptr += consumed;

    if (rec) {
        rec->name = msg_store_name(msg, name);
        if (!rec->name) {
            return log_errno_rf("No space to store record name");
        }
    }

    dec->offset += consumed;

    // need 10 bytes for header (type, class, ttl, rdlen)
    if (dec->offset + 10 > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_HDR, DNS_ERR_TRUNC);
    }

    uint16_t rr_type  = dec_u16(dec->pkt_buf + dec->offset + 0);
    uint16_t rr_class = dec_u16(dec->pkt_buf + dec->offset + 2);
    uint32_t rr_ttl   = dec_u32(dec->pkt_buf + dec->offset + 4);
    uint16_t rdlen    = dec_u16(dec->pkt_buf + dec->offset + 8);

    if (rec) {
        rec->type = rr_type;
        rec->class = rr_class;
        rec->ttl = rr_ttl;
        rec->rdlen = rdlen;
    }

    // rdata
    dec->offset += 10;
    if (dec->offset + rdlen > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_RDATA, DNS_ERR_TRUNC);
    }
    const uint8_t *rdata = dec->pkt_buf + dec->offset;

    // decode rdata
    char *rdata_desc = "";
    char ip_addr[INET_ADDRSTRLEN];

    // decode rdata
    switch(rr_type) {
    case DNS_TYPE_A: // IP4 address
        // integer
        if (rdlen != 4) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_A, DNS_ERR_MINLEN);
        }
        if (rec) {
            mempcpy(rec->data.a, rdata, rdlen);
        }
        if (inet_ntop(AF_INET, rdata, ip_addr, sizeof(ip_addr)) == NULL) {
            log_errno("inet_ntop failed to decode IPv4 addr");
            strcpy(dec->msg, "???");
        }
        // decoded
        rdata_desc = ip_addr;
        break;
    case DNS_TYPE_NS: { //  Authoritative Name Server
        if (rdlen < 1) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_NS, DNS_ERR_MINLEN);
        }
        // decode name
        char *ns_name = wptr;
        int ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, ns_name, wptr_end - wptr,  &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_NS, ec);
        }
        if (rec) {
            rec->data.ns_name = msg_store_name(msg, ns_name);
            if (!rec->data.ns_name) {
                return log_errno_rf("No space to store ns_name");
            }
        }
        wptr += consumed;
        // decoded
        rdata_desc = ns_name;
        break;
    }
    case DNS_TYPE_CNAME: { // Canonical Name (Alias)
        // decode name
        char *cname = wptr;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, cname, wptr_end - wptr, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_CNAME, ec);
        }
        if (rec) {
            rec->data.cname = msg_store_name(msg, cname);
            if (!rec->data.cname) {
                return log_errno_rf("No space to store cname");
            }
        }
        wptr += consumed;
        rdata_desc = cname;
        break;
    }
    case DNS_TYPE_SOA: { // Start of Authority
        // name + name + 5 integers
        // Primary Master Name Server - MNAME
        wptr += snprintf(wptr, wptr_end - wptr, "MNAME=");
        size_t offset = dec->offset;
        char *mname = wptr;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, offset, mname, wptr_end - wptr, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, ec);
        }
        wptr += consumed;
        offset += consumed;

        if (rec) {
            rec->data.soa.mname = msg_store_name(msg, mname);
            if (!rec->data.soa.mname) {
                return log_errno_rf("No space to store mname");
            }
        }

        // Responsible Person's Email - RNAME
        wptr += snprintf(wptr, wptr_end - wptr, " RNAME=");
        char *rname = wptr;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, offset, rname, wptr_end - wptr, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, ec);
        }
        wptr += consumed;
        offset += consumed;

        if (rec) {
            rec->data.soa.rname = msg_store_name(msg, rname);
            if (!rec->data.soa.mname) {
                return log_errno_rf("No space to store rname");
            }
        }

        // serial + refresh + retry + expire + mininum (5 x 32 bit ints)
        if (offset + 20 > dec->offset + rdlen) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, DNS_ERR_TRUNC);
        }

        char *names[5] = { "serial","refresh", "retry", "expire", "mininum" };
        uint32_t vals[5];
        memcpy(vals, dec->pkt_buf + offset, 20);
        for (int i = 0; i < 5; i++) {
            vals[i] = ntohl(vals[i]);
            wptr += snprintf(wptr, wptr_end - wptr, " %s=%u", names[i], vals[i]);
        }

        if (rec) {
            rec->data.soa.serial = vals[0];
            rec->data.soa.refresh = vals[1];
            rec->data.soa.retry = vals[2];
            rec->data.soa.expire = vals[3];
            rec->data.soa.min = vals[4];
        }

        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_PTR: { // Domain Name Pointer (Reverse DNS)
        char *ptr_name = wptr;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, ptr_name, wptr_end - wptr, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_CNAME, ec);
        }
        wptr += consumed;

        if (rec) {
            rec->data.ptr_name = msg_store_name(msg, ptr_name);
            if (!rec->data.ptr_name) {
                return log_errno_rf("No space to store PTR");
            }
        }

        // decoded
        rdata_desc = ptr_name;
        break;
    }
    case DNS_TYPE_HINFO: { // Host Information
        if (rdlen < 2) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_MINLEN);
        }
        uint8_t cpu_len = dec->pkt_buf[dec->offset];
        if (cpu_len + 1 > rdlen) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        uint8_t os_offset = 1 + cpu_len;
        if (os_offset >= rdlen) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        uint8_t os_len = dec->pkt_buf[dec->offset + os_offset];
        if (os_len + 1 + os_len != rdlen) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        if (rec) {
            rec->data.hinfo.cpu_len = cpu_len;
            rec->data.hinfo.os_offset = os_offset;
            rec->data.hinfo.os_len = os_len;
        }
        wptr += snprintf(wptr, wptr_end - wptr,
            "cpu_len=%d os_offset=%d os_len=%d",
            cpu_len, os_offset, os_len);

        // decoeded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_MX: {  // Mail Exchange 
        if (rdlen < 3)  {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_MX, DNS_ERR_MINLEN);
        }
        // preference
        uint16_t pref = dec_u16(dec->pkt_buf + dec->offset);
        wptr += snprintf(wptr, wptr_end - wptr, "pref %d mx_name=", pref);

        // Mail Server Name
        char *mx_name = wptr;
        ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset + 2, mx_name, wptr_end - wptr, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_MX, ec);
        }
        wptr += consumed;

        if (rec) {
            rec->data.mx.pref = pref;
            rec->data.mx.name = msg_store_name(msg, mx_name);
            if (!rec->data.mx.name) {
                return log_errno_rf("No space to store mx_name");
            }
        }

        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_TXT: { // Text Strings
        int ridx = 0;
        char *txt_name = wptr;

        while (ridx < rdlen) {
            // Length
            uint8_t txt_len = rdata[ridx++];
            if (ridx + txt_len > rdlen) {
                return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_TXT, DNS_ERR_FLDLEN);
            }
            // Text
            if (wptr + txt_len > wptr_end) {
                log_error("DNS_TYPE_TXT string longer than desc buffer");
                break;
            }
            wptr = mempcpy(wptr, rdata + ridx , txt_len);
            *wptr++ = ' ';
            ridx += txt_len;
        }
        *wptr = '\0';

        if (rec) {
            rec->data.txt = msg_store_name(msg, txt_name);
            if (!rec->data.txt) {
                return log_errno_rf("No space to store TXT");
            }
        }

        // decoded
        rdata_desc = txt_name;
        break;
    }
    case DNS_TYPE_AAAA:  // IPv6 Address
        if (rdlen != 16) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_AAAA, DNS_ERR_MINLEN);
        }
        if (inet_ntop(AF_INET6, rdata, ip_addr, sizeof(ip_addr)) == NULL) {
            log_errno("inet_ntop failed to decode IPv6 addr");
            strcpy(ip_addr, "???");
        }
        if (rec) {
            mempcpy(rec->data.aaaa, rdata, rdlen);
        }
        // decoded
        rdata_desc = ip_addr;
        break;
    case DNS_TYPE_SRV: { // Service Locator
        // 2 + 2 + 2 + target
        if (rdlen < 7) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SRV, DNS_ERR_MINLEN);
        }
        uint16_t prior = dec_u16(dec->pkt_buf + dec->offset + 0);
        uint16_t weight = dec_u16(dec->pkt_buf + dec->offset + 2);
        uint16_t port = dec_u16(dec->pkt_buf + dec->offset + 4);
        wptr += snprintf(wptr, wptr_end - wptr, "Priority %d Weight %d port %d ", prior, weight, port);
        // name
        char *srv_name = wptr;
        int ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset + 6, srv_name, wptr_end - wptr, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SRV, ec);
        }
        wptr += consumed;

        if (rec) {
            rec->data.srv.prior = prior;
            rec->data.srv.weight = weight;
            rec->data.srv.port = port;
            rec->data.srv.name = msg_store_name(msg, srv_name);
            if (!rec->data.srv.name) {
                return log_errno_rf("No space to store srv_name");
            }
        }

        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_OPT: { // EDNS0 Options (RFC 6891)
        if (sect_code != DNS_DEC_ADDITIONAL) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_OPT, DNS_ERR_OPTSECT);
        }
        size_t offset = dec->offset - 8;
        if (!*name)  {
            name = "<Root>";
        }
        uint16_t udp_size = dec_u16(dec->pkt_buf + offset);
        uint32_t ttl_val  = dec_u32(dec->pkt_buf + offset + 2);
        uint8_t ext_rcode = (ttl_val >> 24) & 0xFF;
        uint8_t version   = (ttl_val >> 16) & 0xFF;
        uint8_t do_bit   = (ttl_val & 0x8000);

        if (rec) {
            rec->data.opt.udp_size = udp_size;
            rec->data.opt.ttl_val = udp_size;
            rec->data.opt.ext_rcode = udp_size;
            rec->data.opt.edns_ver = udp_size;
            rec->data.opt.do_bit = do_bit;
            rec->class = 0;
            rec->name = msg_store_name(msg, "<Root>");
            if (!rec->name) {
                return log_errno_rf("No space to store <Root>");
            }
        }

        wptr += snprintf(wptr, wptr_end - wptr,
            "UDP-size:%d Ext-RCODE:%d EDNS0:%d DNSEC-OK:%d",
            udp_size, ext_rcode, version, !!do_bit);

        // store these values
        dec->got_edns = 1;
        dec->udp_size = udp_size;
        dec->ext_rcode = ext_rcode;
        dec->edns_ver = version;
        dec->dnssec_ok = !!do_bit;

        // decoded
        rdata_desc = dec->msg;
        break;
    }
    case DNS_TYPE_ANY: // Wildcard match (Query only) 
        break;
    default:
        break;
    }

    // next record
    sect->num_rec++;
    dec->offset += rdlen;

    if (dec->need_emsg) {
        char num[2][10];
        itoa(num[0], 10, rr_class); 
        itoa(num[1], 10, rr_type);

        // desc PDU as we decode
        char *res = dns_wmsg(dec, "  %s: %s %s %s %s\n",
            ec_tostr(ARRAY(dec_code_tostr), sect_code, "???"),
            name, dns_class_tostr(rr_class, num[0]), dns_type_tostr(rr_type, num[1]),
            rdata_desc
        );
        if (!res) ec = -1;
    }

    // all done
    return ec;
}

static int parse_question(struct dns_dec *dec, struct dns_msg *msg)
{
    // grab next section quest
    struct dns_quest *quest = NULL;
    if (dec->load_msg) {
        if (msg->num_quest >= ARR_LEN(msg->quest)) {
            return log_error_rf("No space to store question");
        }
        quest = &msg->quest[msg->num_quest];
    }

    char *wptr = dec->msg;
    char *wptr_end = wptr + sizeof(dec->msg);

    // label
    char *name = wptr;
    size_t consumed;
    int ec = parse_dns_name(dec->pkt_buf, dec->pkt_len, dec->offset, name, wptr_end - wptr, &consumed);
    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_QUESTION, DNS_DEC_NAME, ec);
    }

    dec->offset += consumed;
    wptr += consumed;

    if (dec->offset + 4 > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_QUESTION, DNS_DEC_HDR, DNS_ERR_TRUNC);
    }

    uint16_t qtype  = dec_u16(dec->pkt_buf + dec->offset);
    uint16_t qclass = dec_u16(dec->pkt_buf + dec->offset + 2);
    dec->offset += 4;

    if (quest)  {
        quest->qtype = qtype;
        quest->qclass = qclass;
        quest->qname = msg_store_name(msg, name);
        if (!quest->qname) {
            return log_errno_rf("No space to store question name");
        }
    }

    // decoded
    msg->num_quest++;

    if (dec->need_emsg) {
        // desc PDU as we decode
        char num[2][10];
        itoa(num[0], 10, qclass); 
        itoa(num[1], 10, qtype);
        char *res= dns_wmsg(dec, "  %s: %s %s %s\n",
            "Question", name, 
            dns_class_tostr(qclass, num[0]), 
            dns_type_tostr(qtype, num[1])
        );
        if (!res) ec = -1;
    }

    // all done
    return ec;
}

static int dns_dec_sect(struct dns_dec *dec, struct dns_msg *msg, 
    int nrec, int sect_code, struct dns_sect *sect)
{
    for (int i = 0; i < nrec; i++) {
        if (parse_record(dec, msg, sect_code, sect) != 0) {
            return dns_dec_err(dec, DNS_DEC_PDU, sect_code, i);
        }
    }

    return 0;
}

static int decode_additional(struct dns_dec *dec, struct dns_msg *msg)
{
    return dns_dec_sect(dec, msg, msg->hdr.ar_count, DNS_DEC_ADDITIONAL, &msg->add);
}

static int decode_authority(struct dns_dec *dec, struct dns_msg *msg)
{
    return dns_dec_sect(dec, msg, msg->hdr.ns_count, DNS_DEC_AUTHORITY, &msg->auth);
}

static int decode_answer(struct dns_dec *dec, struct dns_msg *msg)
{
    return dns_dec_sect(dec, msg, msg->hdr.an_count, DNS_DEC_ANSWER, &msg->ans);
}

static int decode_question(struct dns_dec *dec, struct dns_msg *msg)
{
    for (int i = 0; i < msg->hdr.qd_count; i++) {
        if (parse_question(dec, msg) != 0) {
            return dns_dec_err(dec, DNS_DEC_PDU, DNS_DEC_QUESTION, i);
        }
    }

    return 0;
}

static int decode_header(struct dns_dec *dec, struct dns_header *hdr)
{
    int ec = parse_dns_header(dec->pkt_buf, dec->pkt_len, hdr);

    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_PDU, DNS_DEC_HDR, ec);
    }

    dec->offset += sizeof(struct dns_header);

    if (!dec->need_emsg) return 0;

    // copy hdr fields for dns_dec_genmsg
    dec->hdr = *hdr;

    // describe
    char num[2][10];
    uint16_t flags = hdr->flags;
    int qr = flags & DNS_FLAGS_QR ? 1 : 0;
    int opcode  = (flags & DNS_FLAGS_OPCODE) >> 11;
    const char *opcode_str = ec_tostr(ARRAY(opcode_tostr), opcode, itoa(num[0],10, opcode));
    const char *type_str = qr ? "RESPONSE" : "QUERY";

    char extra[100];
    struct rwbuf buf = RWBUF_INIT(extra, sizeof(extra));
    extra[0] = '\0';

    if (qr) {
        // query response
        int as = flags & DNS_FLAGS_AA ? 1 : 0;
        int tc = flags & DNS_FLAGS_TC ? 1 : 0;
        int rd = flags & DNS_FLAGS_RD ? 1 : 0;
        int ra = flags & DNS_FLAGS_RA ? 1 : 0;
        int rcode = flags & DNS_FLAGS_RCODE;

        // add flags
        if (as) rwbuf_strcat_sep(&buf, ' ', STR_LIT("AS:1"));
        if (tc) rwbuf_strcat_sep(&buf, ' ', STR_LIT("TC:1"));
        if (rd) rwbuf_strcat_sep(&buf, ' ', STR_LIT("RD:1"));
        if (ra) rwbuf_strcat_sep(&buf, ' ', STR_LIT("RA:1"));

        // convert RCODE to str
        itoa(num[1],10,rcode);
        const char *rcode_str = rcode_tostr(rcode, num[1]);
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
        int tc = flags & DNS_FLAGS_TC ? 1 : 0;
        int rd = flags & DNS_FLAGS_RD ? 1 : 0;
        int ad = flags & DNS_FLAGS_AD ? 1 : 0;   

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
        type_str, hdr->id, qr, opcode_str, buf.widx, buf.data);

    return 0;
}

// See rfc1035 Message format 4.1. Format
static int decode_msg(struct dns_dec *dec, struct dns_msg *msg)
{
    int rc;

    rc = decode_header(dec, &msg->hdr);
    if (rc != 0) return rc;
    rc = decode_question(dec, msg);
    if (rc)  return rc;
    rc = decode_answer(dec, msg);
    if (rc) return rc;
    rc = decode_authority(dec, msg);
    if (rc) return rc;
    rc = decode_additional(dec, msg);
    if (rc) return rc;

    // validate message size
    if (dec->need_emsg && dec->pkt_len > dec->udp_size) {
        // Check packet doesn't exceed 512 bytes (UDP) or declared length
        dns_wmsg(dec, "UDP message: packet-length %zu > max size %d\n", dec->pkt_len, dec->udp_size);
    }

    // all done
    return 0;
}


// Required functions
int validate_dns_packet(const uint8_t *pkt_buf, size_t pkt_len, char *emsg)
{
    struct dns_dec dec = {
        .pkt_buf = pkt_buf,
        .pkt_len = pkt_len,
        .udp_size = DNS_MAX_UDP,
        .need_emsg = 1,
        .load_msg = 0,
        .emsg = RWBUF_INIT(emsg, DNS_EMSG_MAXLEN)
    };

    struct dns_msg msg = { 0 };

    int rc = decode_msg(&dec, &msg);

    if (dec.need_emsg) {
        rc = dns_dec_genmsg(&dec);
    }

    return rc;
}

int dns_decode_msg(struct dns_msg *msg, uint8_t *buf, size_t len)
{
    struct dns_dec dec = {
        .pkt_buf = buf,
        .pkt_len = len,
        .udp_size = DNS_MAX_UDP,
        .load_msg = 1
    };

    return decode_msg(&dec, msg);
}

// DNS encoder 

static inline uint8_t *enc_u32(uint8_t *wptr, uint32_t value)
{
    *wptr++ = value >> 24;
    *wptr++ = value >> 16;
    *wptr++ = value >> 8;
    *wptr++ = value;

    return wptr;
}

static inline uint8_t *enc_u16(uint8_t *wptr, uint16_t value)
{
    *wptr++ = value >> 8;
    *wptr++ = value;

    return wptr;
}

static int enc_hdr(uint8_t *wptr, const struct dns_header *hdr)  
{
    wptr = enc_u16(wptr, hdr->id);
    wptr = enc_u16(wptr, hdr->flags);
    wptr = enc_u16(wptr, hdr->qd_count);
    wptr = enc_u16(wptr, hdr->an_count);
    wptr = enc_u16(wptr, hdr->ns_count);
    wptr = enc_u16(wptr, hdr->ar_count);

    return DNS_HDR_LEN;
}

// TODO add compression support
static uint8_t *enc_name(uint8_t *wptr, const char *name)
{
    uint8_t *len_pos = wptr++;
    int len = 0;
    
    while (*name) {
        if (*name == '.') {
            *len_pos = len;
            len_pos = wptr++;
            len = 0;
        }
        else {
            *wptr++ = *name;
            len++;
        }
        name++;
    }

    // final label - drop a nul
    *len_pos = len;
    *wptr++ = 0;

    // return wpos
    return wptr;
}

static inline void dns_enc_retspace(struct dns_enc *enc, size_t len)
{
    enc->pkt_len -= len;
}

static inline uint8_t *dns_enc_mkspace(struct dns_enc *enc, size_t len)
{
    if (enc->pkt_len + len > enc->pkt_max) {
        return NULL;
    }

    uint8_t *buf = enc->pkt_buf + enc->pkt_len;
    enc->pkt_len += len;

    return buf;
}

static int dns_enc_question(struct dns_enc *enc, struct dns_question *quest)
{
    uint8_t *buf = dns_enc_mkspace(enc, DNS_NAME_MAXLEN + 4);
    if (!buf) return -1;

    uint8_t *wptr = buf;
    wptr = enc_name(wptr, quest->qname);
    wptr = enc_u16(wptr, quest->qtype);
    wptr = enc_u16(wptr, quest->qclass);
    dns_enc_retspace(enc, (DNS_NAME_MAXLEN + 4) - (wptr - buf));

    enc->hdr.qd_count++;

    return 0;
}

int dns_enc_start(struct dns_enc *enc, uint16_t tid, uint16_t flags)
{
    enc->pkt_len = 0;

    if (!dns_enc_mkspace(enc, DNS_HDR_LEN)) {
        return -1;
    }

    enc->hdr.id = tid;
    enc->hdr.flags = flags;

    return 0;
}

int dns_enc_end(struct dns_enc *enc)
{
    enc_hdr(enc->pkt_buf, &enc->hdr);

    return enc->pkt_len;
}

int dns_enc_add_quest(struct dns_enc *enc, const char *name, uint16_t qtype,  uint16_t qclass)
{
    struct dns_question quest;

    memcpy(quest.qname, name, strlen(name) + 1);
    quest.qtype = qtype  ?: DNS_TYPE_A;
    quest.qclass = qclass ?: DNS_CLASS_IN;

    return dns_enc_question(enc, &quest);
}
