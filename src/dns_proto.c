/*
 *
 */

#include <arpa/inet.h>   

#include "util.h"
#include "dns_proto.h"

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


#define DNS_MAX_EMSG 10
#define DNS_NAME_SIZE 256

#define DNS_WHAT_NUL 0
#define DNS_WHAT_QRY 0
#define DNS_WHAT_RSP 1
#define DNS_WHAT_ERR 2


struct dns_err {
    int group;
    int field;
    int ec;
};

struct dns_dec {
	const unsigned char *pkt;
	size_t pkt_len;
    size_t consumed;
    size_t offset;
    struct dns_header hdr;
    // a simple error stack
    struct dns_err errs[DNS_MAX_EMSG];
    int nerr;
    // track what we write into emsg
    struct rwbuf emsg;
    char msg[256]; // dns_err_tostr
};

// XXX - use xmacros to ensure both code and string match
#define DNS_ERRORS(X) \
    X(DNS_ERR_OK, "Okay") \
    X(DNS_ERR_HDRLEN, "header len") \
    X(DNS_ERR_BADJMP, "Invalid compression pointer (outside range)") \
    X(DNS_ERR_NUMJMP, "Invalid compression pointer (loop detected)") \
    X(DNS_ERR_NAMELEN, "Name length bigger than pkt size") \
    X(DNS_ERR_OUTLEN, "Name bigger than buf size") \
    X(DNS_ERR_NONULL, "Name missing null char") \
    X(DNS_ERR_TRUNC,  "Field truncated") \
    X(DNS_ERR_MINLEN, "Field smaller than min len") \
    X(DNS_ERR_FLDLEN, "Field length bigger than pkt")

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
    X(DNS_DEC_TYPE_A,     "TYPE-A") \
    X(DNS_DEC_TYPE_NS,    "TYPE-NS") \
    X(DNS_DEC_TYPE_CNAME, "TYPE-CNAME") \
    X(DNS_DEC_TYPE_SOA,   "TYPE_SOA") \
    X(DNS_DEC_TYPE_PTR,   "TYPE-PTR") \
    X(DNS_DEC_TYPE_HINFO, "TYPE-HINFO")\
    X(DNS_DEC_TYPE_MX,    "TYPE-MX") \
    X(DNS_DEC_TYPE_TXT,   "TYPE-TXT") \
    X(DNS_DEC_TYPE_AAAA,  "TYPE-AAAA") \
    X(DNS_DEC_TYPE_SRV,   "TYPE-SRV") \
    X(DNS_DEC_TYPE_OPT,   "TYPE-OPT") \
    X(DNS_DEC_TYPE_ANY,   "TYPE-ANY") 

#define DNS_DECODE_ENUM(NAME, TEXT) NAME,
#define DNS_DECODE_TEXT(NAME, TEXT) [NAME] = TEXT,

enum dns_dec_code {
    DNS_DECODES(DNS_DECODE_ENUM)
};

static const char *dec_code_tostr[] = {
    DNS_DECODES(DNS_DECODE_TEXT)
};

const char *qlass_tostr(int ec)
{
    if (ec == 1) return "IN";
    if (ec == 3) return "CH";
    if (ec == 4) return "HS";
    if (ec == 254) return "NONE";
    if (ec == 255) return "*";
    return "???";
};

const char *qtype_tostr(int ec)
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
    if (ec == 252) return "AXFR";
    if (ec == 255)  return "ANY";
    return "???";
}

static const char *opcode_2str[] = {
    [0] = "QUERY",
    [1] = "IQUERY",
    [2] = "STATUS",
    [3] = "",
    [4] = "NOTIFY",
    [5] = "UPDATE"
};

#define DNS_FLAGS_QUERY  0x8000 
#define DNS_FLAGS_OPCODE 0x7800
#define DNS_FLAGS_RECUR  0x0100 
static inline int dns_is_query(struct dns_header *hdr)
{
    return hdr->flags & DNS_FLAGS_QUERY  ? 0 : 1;
}
static inline int dns_opcode(struct dns_header *hdr)
{
    return (hdr->flags & 0x7800) >> 11;
}
static inline int dns_recur(struct dns_header *hdr)
{
    return hdr->flags & DNS_FLAGS_RECUR ? 1 : 0;
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
        log_error("wbuffer full");
        return NULL;
    }

    // return ptr where we stored messge
    return rwbuf_wres(buf, nw);
}

int dns_dec_err(struct dns_dec *dec, int group, int field, int ec)
{
    if (dec->nerr >= ARR_LEN(dec->errs)) {
        return log_error("No room for err  %d %d %d", group, field, ec);
    }

    dec->errs[dec->nerr].group = group;
    dec->errs[dec->nerr].field = field;
    dec->errs[dec->nerr].ec = ec;
    dec->nerr++;

    // all done
    return 0;
}

// Required functions
int parse_dns_header(const uint8_t *buf, size_t len, struct dns_header *hdr)
{
    if (len < sizeof(*hdr)) {
        // too small
        return DNS_ERR_HDRLEN;
    }

    // decode the header
    hdr->id       = decode_u16(buf + 0);
    hdr->flags    = decode_u16(buf + 2);
    hdr->qd_count = decode_u16(buf + 4);
    hdr->an_count = decode_u16(buf + 6);
    hdr->ns_count = decode_u16(buf + 8);
    hdr->ar_count = decode_u16(buf + 10);

	// all done
    return 0;
}

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
       		// jmp compression 
			if (ridx == pkt_len) return DNS_ERR_BADJMP; 
			if (njmp++ > 10) return DNS_ERR_NUMJMP;
			if (njmp == 1) *bytes_consumed += 2;
			len = ((len & 0x3F) << 8) | pkt[ridx];
			if (len < 12) return DNS_ERR_BADJMP;
            if (len > pkt_len) return DNS_ERR_BADJMP;
            ridx = len;
			continue;
        }

		// label
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

static int decode_record(struct dns_dec *dec, struct dns_record *rec)
{
    size_t consumed;
    size_t offset;
	int ec; 

    // label
    ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, rec->name, sizeof(rec->name), &consumed);
    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_NAME, ec);
    }
    dec->offset += consumed;

    // need 10 bytes for header
    if (dec->offset + 10 > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_HDR, DNS_ERR_TRUNC);
    }

    rec->type   = decode_u16(dec->pkt + dec->offset + 0);
    rec->class  = decode_u16(dec->pkt + dec->offset + 2);
    rec->ttl    = decode_u32(dec->pkt + dec->offset + 4);
    rec->rdlength = decode_u16(dec->pkt + dec->offset + 8);

    // rdata
    dec->offset += 10;
    if (dec->offset + rec->rdlength > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_RDATA, DNS_ERR_TRUNC);
    }

    // decode rdata
    switch(rec->type) {
    case DNS_TYPE_A: // IP4 address
        // integer
        if (rec->rdlength != 4) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_A, DNS_ERR_MINLEN);
        }
        break;
    case DNS_TYPE_NS: //  Authoritative Name Server
        if (rec->rdlength < 1) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_NS, DNS_ERR_MINLEN);
        }
        ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_NS, ec);
        }
        break;
    case DNS_TYPE_CNAME: // Canonical Name (Alias)
        ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_CNAME, ec);
        }
        break;
    case DNS_TYPE_SOA: // Start of Authority
        // name + name + 5 integers
        // Primary Master Name Server
        offset = dec->offset;
        ec = parse_dns_name(dec->pkt, dec->pkt_len, offset, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, ec);
        }
        offset += consumed;
        // Responsible Person's Email (RNAME)
        ec = parse_dns_name(dec->pkt, dec->pkt_len, offset, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, ec);
        }
        offset += consumed;
        if (offset + 20 > dec->offset + rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SOA, DNS_ERR_TRUNC);
        }
        // serial + refresh + retry + expire + mininum
        break;
    case DNS_TYPE_PTR:  // Domain Name Pointer (Reverse DNS)
        ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_CNAME, ec);
        }
        break;
    case DNS_TYPE_HINFO: { // Host Information
        if (rec->rdlength < 2) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_MINLEN);
        }
        uint8_t cpu_len = dec->pkt[dec->offset];
        if (cpu_len + 1 > rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        uint8_t os_offset = 1 + cpu_len;
        if (os_offset >= rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        uint8_t os_len = dec->pkt[dec->offset + os_offset];
        if (os_len + 1 + os_len != rec->rdlength) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_HINFO, DNS_ERR_FLDLEN);
        }
        break;
    }
    case DNS_TYPE_MX:{   // Mail Exchange 
        if (rec->rdlength < 3)  {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_MX, DNS_ERR_MINLEN);
        }
        //int16_t preference = decode_u16(pkt + offset);
        // Mail Server Name
        ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset + 2, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_MX, ec);
        }
        break;
    }
    case DNS_TYPE_TXT: { // Text Strings
        size_t ridx = 0;
        while (ridx < rec->rdlength) {
            // len
            uint8_t str_len = dec->pkt[dec->offset + ridx];
            ridx++;
            if (ridx + str_len > rec->rdlength) {
                return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_TXT, DNS_ERR_FLDLEN);
            }
            // extract string ...
            //memcpy(dec->name, dec->pkt + dec->offset + ridx, str_len);
            //dec->name[str_len] = '\0';
        }
        break;
    }
    case DNS_TYPE_AAAA:  // IPv6 Address
        if (rec->rdlength != 16) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_AAAA, DNS_ERR_MINLEN);
        }
        break;
    case DNS_TYPE_SRV: { // Service Locator
        if (rec->rdlength < 7) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SRV, DNS_ERR_MINLEN);
        }
        //uint16_t priority = decode_u16(pkt + offset + 0);
        //int16_t weight   = decode_u16(pkt + offset + 2);
        //uint16_t port     = decode_u16(pkt + offset + 4);
        // name
        int ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset + 6, NULL, DNS_NAME_SIZE, &consumed);
        if (ec != 0) {
            return dns_dec_err(dec, DNS_DEC_RECORD, DNS_DEC_TYPE_SRV, ec);
        }
        break;
    }
    case DNS_TYPE_OPT: { // EDNS0 Options (RFC 6891)
        /*
        uint16_t udp_size = decode_u16(pkt + offset + 2);
        uint32_t ttl_val  = decode_u32(pkt + offset + 4);
        uint8_t ext_rcode = (ttl_val >> 24) & 0xFF;
        uint8_t version   = (ttl_val >> 16) & 0xFF;
        uint16_t do_bit   = (ttl_val & 0x8000);
        */
        break;
    }
    case DNS_TYPE_ANY: // Wildcard match (Query only) 
        break;
    default:
        break;
    }

    // next row
    dec->offset += rec->rdlength;

    // all done
    return 0;
}


static int decode_section(struct dns_dec *dec, int section, int rows)
{
    struct dns_record rec;

    for (int i = 0; i < rows; i++) {
        if (decode_record(dec, &rec) != 0) {
            return dns_dec_err(dec, DNS_DEC_PDU, section, i);
        }
    }

    return 0;
}

static int decode_question(struct dns_dec *dec, struct dns_question *quest)
{
    size_t consumed;
	int ec; 

    // label
    ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, quest->qname, sizeof(quest->qname), &consumed);
    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_QUESTION, DNS_DEC_NAME, ec);
    }

    dec->offset += consumed;
    if (dec->offset + 4 > dec->pkt_len) {
        return dns_dec_err(dec, DNS_DEC_QUESTION, DNS_DEC_HDR, DNS_ERR_TRUNC);
    }

    quest->qtype = decode_u16(dec->pkt + dec->offset);
    quest->qclass = decode_u16(dec->pkt + dec->offset + 2);

    dec->offset += 4;

    // desc PDU as we decode
    dns_wmsg(dec, "  %s: %s %s %s\n",
        "Question", quest->qname, qlass_tostr(quest->qclass), qtype_tostr(quest->qtype)
    );

    // all done
    return 0;
}

static int decode_questions(struct dns_dec *dec)
{
    struct dns_question quest;

    for (int i = 0; i < dec->hdr.qd_count; i++) {
        if (decode_question(dec, &quest) != 0) {
            return dns_dec_err(dec, DNS_DEC_PDU, DNS_DEC_QUESTION, i);
        } 
    }

	return 0;
}

static int decode_header(struct dns_dec *dec)
{
    int ec = parse_dns_header(dec->pkt, dec->pkt_len, &dec->hdr);

    if (ec != 0) {
        return dns_dec_err(dec, DNS_DEC_PDU, DNS_DEC_HDR, ec);
    }
    dec->offset += sizeof(struct dns_header);

    int query = dns_is_query(&dec->hdr);
    int opcode = dns_opcode(&dec->hdr);
    int recur = dns_recur(&dec->hdr);
    const char *opcode_str = ec_tostr(opcode_2str, ARR_LEN(opcode_2str), opcode, "");

    // desc PDU as we decode
    dns_wmsg(dec,
        "[%s] ID 0x%04x QR:%d OPCODE:%s RD:%d\n",
        query ? "QUERY" : "RESPONSE",
        dec->hdr.id, query, opcode_str, recur);

	return 0;
}

char *dns_err_tostr(struct dns_dec *dec, struct dns_err *err)
{
    const char *group = ec_tostr(dec_code_tostr, ARR_LEN(dec_code_tostr), err->group, "???");
    const char *field = ec_tostr(dec_code_tostr, ARR_LEN(dec_code_tostr), err->field, "???");
    const char *error = ec_tostr(dns_ec_tostr, ARR_LEN(dns_ec_tostr), err->ec, "???");

    int nw = snprintf(dec->msg, sizeof(dec->msg), "%s %s %s", group, field, error);
    if (nw < 0 || nw >= sizeof(dec->msg)) {
        return log_errorn("snprinf dns error failed nw=%d", nw);
    }

    // all done
    return dec->msg;
}

static int generate_emsg(struct dns_dec *dec)
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

    // ERROR
    return -1;
}

int validate_dns_packet(const uint8_t *pkt, size_t pkt_len, char *emsg)
{
	struct dns_dec tmp = {
		.pkt = pkt,
		.pkt_len = pkt_len,
		.emsg  = RWBUF_INIT(emsg, DNS_ERRBUF_SIZE)
    };
	struct dns_dec *dec = &tmp;

 	if ( (decode_header(dec)) != 0) goto done;
	if ( (decode_questions(dec)) != 0) goto done;
	if ( (decode_section(dec, DNS_DEC_ANSWER,  dec->hdr.an_count)) != 0)  goto done;
	if ( (decode_section(dec, DNS_DEC_AUTHORITY, dec->hdr.ns_count)) != 0) goto done;
	if ( (decode_section(dec, DNS_DEC_ADDITIONAL, dec->hdr.ar_count)) != 0) goto done;

done:
    return generate_emsg(dec);
}
