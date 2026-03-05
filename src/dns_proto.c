/*
 *
 */

#include <arpa/inet.h>   

#include "util.h"
#include "dns_proto.h"

struct dns_decoder {
	const unsigned char *pkt;
	size_t pkt_len;
    size_t consumed;
    size_t offset;
    struct dns_header hdr;
    char name[256];
	char *emsg;
    int ec;
};

static const char *err2str[] = {
    "DNS_ERR_NONE"
    "DNS_ERR_HDRLEN"
    "DNS_ERR_BADJMP"
    "DNS_ERR_NUMJMP"
    "DNS_ERR_OUTLEN"
    "DNS_ERR_NONULL"
    "DNS_ERR_TRUNC"
    "DNS_ERR_TYPE_A"
    "DNS_ERR_TYPE_NS"
    "DNS_ERR_TYPE_CNAME"
    "DNS_ERR_TYPE_SOA"
    "DNS_ERR_TYPE_PTR"
    "DNS_ERR_TYPE_HINFO"
    "DNS_ERR_TYPE_MX"
    "DNS_ERR_TYPE_TXT"
    "DNS_ERR_TYPE_AAAA"
    "DNS_ERR_TYPE_SRV"
    "DNS_ERR_TYPE_OPT"
    "DNS_ERR_TYPE_ANY"
};

static int dns_err(int ec, const char *name, char *msg_buf, const char *fmt, ...)
{
    va_list args;  
    const char *estr;
    int nw;

    estr = (ec >= 0 && ec < ARR_LEN(err2str)) ? err2str[ec] : "";

    nw = snprintf(msg_buf, DNS_ERRBUF_SIZE,  "[ERROR] decode %s", name);
    va_start(args, fmt);
    nw += vsnprintf(msg_buf + nw, DNS_ERRBUF_SIZE - nw, fmt, args);
    va_end(args);
    nw += snprintf(msg_buf + nw,  DNS_ERRBUF_SIZE -nw, " error %d (%s)", ec, estr);

    return ec;
}

// Required functions
int parse_dns_header(const uint8_t *buf, size_t len, struct dns_header *hdr)
{
    if (len < sizeof(*hdr)) {
        // too small
        return DNS_ERR_HDRLEN;
    }

    // decode the header
    hdr->id       = decode_u32(buf + 0);
    hdr->flags    = decode_u32(buf + 2);
    hdr->qd_count = decode_u32(buf + 4);
    hdr->an_count = decode_u32(buf + 6);
    hdr->ns_count = decode_u32(buf + 8);
    hdr->ar_count = decode_u32(buf + 10);

	// all done
    return 0;
}

int parse_dns_name(
    const uint8_t *pkt, size_t pkt_len, size_t offset, 
	char *out, size_t out_len, 
    size_t *bytes_consumed)
{
	int ridx = 0;
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
		if (len > pkt_rem) return -3;
		if (len > out_len) return -4;
		if (!njmp) *bytes_consumed += 1 + len;

		// null check
		if (len == 0) break;
	
		// copy label
		memcpy(out, pkt + ridx, len);
		out += len;
		out_len -= len;
		ridx += len;

		// add a dot	
		if (!out_len) return DNS_ERR_OUTLEN;
		if (ridx < pkt_len && pkt[ridx] != 0) {
			// store the dot
			*out = '.';
			out_len--;
		}
    }

	// did we stop at 0
	if (len != 0) return DNS_ERR_NONULL;

    // null-terminate
	if (!out_len) return DNS_ERR_OUTLEN;
	*out = '\0';

	// all done    
    return 0;
}

static int decode_section(struct dns_decoder *dec, const char *sec_name, int rows)
{
	int ec;
    size_t consumed;

    for (int i = 0; i < rows; i++) {

        // label
        ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, dec->name, sizeof(dec->name), &consumed);
        if (ec != 0) {
            return dns_err(ec, sec_name, dec->emsg, "row %d name");
        }
        dec->offset += consumed;

        // need 10 bytes for header
        if (dec->offset + 10 > dec->pkt_len) {
            return dns_err(DNS_ERR_TRUNC, sec_name, dec->emsg, "row  %d hdr truncatd", i);
        }
        uint16_t type   = decode_u16(dec->pkt + dec->offset + 0);
        //uint16_t class  = decode_u16(dec->pkt + dec->offset + 2);
        //uint32_t ttl    = decode_u32(dec->pkt + dec->offset + 4);
        uint16_t rdlen  = decode_u16(dec->pkt + dec->offset + 8);

        // rdata
        dec->offset += 10;
        if (dec->offset + rdlen > dec->pkt_len) {
            return dns_err(DNS_ERR_TRUNC,sec_name,  dec->emsg, "row %d rdata trunceted", i);
        }

        // decode rdata
        switch(type) {
        case DNS_TYPE_A: // IP4 address
            // integer
            if (rdlen != 4) {
                return dns_err(DNS_ERR_TYPE_A, sec_name, dec->emsg, "row %d DNS_TYPE_A trunceted", i);
            }
            break;
        case DNS_TYPE_NS: //  Authoritative Name Server
            if (rdlen < 1) {
                return dns_err(DNS_ERR_TYPE_NS, sec_name, dec->emsg, "row %d DNS_TYPE_NS trunceted", i);
            }
            ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_NS, sec_name, dec->emsg, "row %d DNS_TYPE_NS trunceted", i);
            }
            break;
        case DNS_TYPE_CNAME: // Canonical Name (Alias)
            ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_CNAME, sec_name, dec->emsg, "row %d DNS_TYPE_CNAME trunceted", i);
            }
            break;
        case DNS_TYPE_SOA:{ // Start of Authority
            // name + name + 5 integers
            // Primary Master Name Server
            int sub_offset = dec->offset;
            ec = parse_dns_name(dec->pkt, dec->pkt_len, sub_offset, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_SOA, sec_name, dec->emsg, "row %d primary master", i);
            }
            sub_offset += consumed;
            // Responsible Person's Email (RNAME)
            ec = parse_dns_name(dec->pkt, dec->pkt_len, sub_offset, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_SOA, sec_name, dec->emsg, "row %d RNAME", i);
            }
            sub_offset += consumed;
            if (sub_offset + 20 > dec->offset + rdlen) {
                return dns_err(DNS_ERR_TYPE_SOA, sec_name, dec->emsg, "row %d truncated", i);
            }
            // serial + refresh + retry + expire + mininum
            break;
        }
        case DNS_TYPE_PTR:  // Domain Name Pointer (Reverse DNS)
            ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_CNAME, sec_name, dec->emsg, "row %d name  ", i);
            }
            break;
        case DNS_TYPE_HINFO: { // Host Information
            if (rdlen < 2) {
                return dns_err(DNS_ERR_TYPE_HINFO, sec_name, dec->emsg, "row %d min rdlen", i);
            }
            uint8_t cpu_len = dec->pkt[dec->offset];
            if (cpu_len + 1 > rdlen) {
                return dns_err(DNS_ERR_TYPE_HINFO, sec_name, dec->emsg, "row %d cpu_len", i);
            }
            uint8_t os_offset = 1 + cpu_len;
            if (os_offset >= rdlen) {
                return dns_err(DNS_ERR_TYPE_HINFO, sec_name, dec->emsg, "row %d os_offset", i);
            }
            uint8_t os_len = dec->pkt[dec->offset + os_offset];
            if (os_len + 1 + os_len != rdlen) {
                return dns_err(DNS_ERR_TYPE_HINFO,sec_name, dec->emsg,  "row %d os_len", i);
            }
            break;
        }
        case DNS_TYPE_MX:{   // Mail Exchange 
            if (rdlen < 3)  {
                return dns_err(DNS_ERR_TYPE_MX, sec_name, dec->emsg, "row %d rdata min len", i);
            }
            //int16_t preference = decode_u16(pkt + offset);
            // Mail Server Name
            ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset + 2, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_MX, sec_name, dec->emsg, "row %d mail server name ", i);
            }
            break;
        }
        case DNS_TYPE_TXT: { // Text Strings
            size_t ridx = 0;
            while (ridx < rdlen) {
                // len
                uint8_t str_len = dec->pkt[dec->offset + ridx];
                ridx++;
                if (ridx + str_len > rdlen) {
                    return dns_err(DNS_ERR_TYPE_TXT, sec_name, dec->emsg, "row %d str_len ", i);
                }
                // extract string ...
                memcpy(dec->name, dec->pkt + dec->offset + ridx, str_len);
                dec->name[str_len] = '\0';
            }
            break;
        }
        case DNS_TYPE_AAAA:  // IPv6 Address
            if (rdlen != 16) {
                return dns_err(DNS_ERR_TYPE_AAAA, sec_name, dec->emsg, "row %d min_lend", i);
            }
            break;
        case DNS_TYPE_SRV: { // Service Locator
            if (rdlen < 7) {
                return dns_err(DNS_ERR_TYPE_SRV, sec_name, dec->emsg, "row %d min len", i);
            }
            //uint16_t priority = decode_u16(pkt + offset + 0);
            //int16_t weight   = decode_u16(pkt + offset + 2);
            //uint16_t port     = decode_u16(pkt + offset + 4);
            // name
            int ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset + 6, dec->name, sizeof(dec->name), &consumed);
            if (ec != 0) {
                return dns_err(DNS_ERR_TYPE_SRV, sec_name, dec->emsg, "row %d name field ", i);
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
        dec->offset += rdlen;

    }

    return 0;
}

static int decode_questions(struct dns_decoder *dec)
{
	int ec; 
    size_t consumed;

    for (int i = 0; i < dec->hdr.qd_count; i++) {
        // label
		ec = parse_dns_name(dec->pkt, dec->pkt_len, dec->offset, dec->name, sizeof(dec->name), &consumed);
		if (ec != 0) {
        	return dns_err(ec, "Questions", dec->emsg, "row %d name");
		}
        dec->offset += consumed;
        if (dec->offset + 4 > dec->pkt_len) {
        	return dns_err(DNS_ERR_TRUNC, "Questions", dec->emsg, "row %d truncated hdr", i);
        }
        //uint16_t qtype  = decode_u16(pkt + offset);
        //uint16_t qclass = decode_u16(pkt + offset + 2);
        dec->offset += 4;
	}

	return 0;
}

static int decode_header(struct dns_decoder *dec)
{
    int ec = parse_dns_header(dec->pkt, dec->pkt_len, &dec->hdr);

    if (ec != 0) {
        return dns_err(ec, "Header", dec->emsg, "packet len %d too small", dec->pkt_len);
    }
    dec->offset += sizeof(struct dns_header);

	return 0;
}

int validate_dns_packet(const uint8_t *pkt, size_t pkt_len, char *emsg)
{
	struct dns_decoder tmp = {  
		.pkt = pkt,
		.pkt_len = pkt_len,
		.emsg  = emsg
	};

	struct dns_decoder *dec = &tmp;
    int ec;

 	if ( (ec = decode_header(dec)) != 0) return ec;
	if ( (ec = decode_questions(dec)) != 0) return ec;
	if ( (ec = decode_section(dec, "Answers", dec->hdr.an_count)) != 0) return ec;
	if ( (ec = decode_section(dec, "Authority", dec->hdr.ns_count)) != 0) return ec;
	if ( (ec = decode_section(dec, "Additional", dec->hdr.ar_count)) != 0)  return ec;

    // all done
    return 0;
}
