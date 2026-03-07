/*
 * PCAP - A packet capture file reader 
 *
 * API
 * ---
 * - pcap_open_read : open file
 * - pcap_read      : read a packet
 * - pcap_close     : close file
 */

#include <stdlib.h>

#include "util.h"
#include "pcap.h"

#define PCAP_ZERO 0
#define PCAP_ERR -1
#define PCAP_EOF -2

#define pcap_log(what, fmt, ...) log_info(what, fmt, ##__VA_ARGS__)

#define pcap_errorn(ec, fmt, ...) ({ \
	_log_error(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__); \
    errno = (ec); \
	(void *)NULL; \
})

#define pcap_errori(ec, fmt, ...) ({ \
	_log_error(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__); \
    errno = (ec); \
	PCAP_ERR; \
})

#define pcap_errorz(ec, fmt, ...) ({ \
	_log_error(__FILE__, __LINE__, __func__, 0, fmt, ##__VA_ARGS__); \
    errno = (ec); \
	PCAP_ZERO; \
})

static uint32_t inline pad_len(uint32_t cap_len)
{
    return  (4 - (cap_len % 4)) % 4;
}

// wrapper around fread call - track/log errors
static int pcap_read_data(struct pcap_file *file, const char *name, void *data, size_t len)
{
    size_t nread = fread(data, 1, len, file->fp);

    if (nread != len) {
        if (nread == 0 && feof(file->fp)) {
            file->have_eof = 1;
            return PCAP_EOF;
        }
        if (!ferror(file->fp)) {
            // should never happen ?
            errno = EBADMSG;
        }
        file->sys_err = 1;
        return pcap_errori(errno, "pcap: Read %s #%lu size %zu failed", name, file->rec_cnt + 1,  len);
    }

    return 0;
}

// read strt of a new block/record
static int pcap_read_block(struct pcap_file *file, const char *name, void *block, size_t len)
{
    if (pcap_read_data(file, name, block, len) != 0) {
        return -1;
    }

    file->rec_cnt++;

    return 0;
}

// wrapper around fseek call - track/log errors
static int pcap_seek_data(struct pcap_file *file, const char *name, long len, int whence)
{
    if (fseek(file->fp, len, whence) != 0) {
        file->sys_err = 1;
        return pcap_errori(errno, "pcap: %s seek %lu whence %d failed", name, len, whence);
    }

    return 0;
}

static int pcap_data_skip(struct pcap_file *file, const char *name, long len)
{
    return pcap_seek_data(file, name, len, SEEK_CUR);
}

static int pcap_data_rewind(struct pcap_file *file, const char *name, long len)
{
    return pcap_data_skip(file, name, -len);
}

static int pcap_detect_fmt(struct pcap_file *file)
{
    uint32_t magic;

    if (pcap_read_data(file, "magic", &magic, sizeof(magic)) != 0) {
        return -1;
    }

    if (fseek(file->fp, 0, SEEK_SET) == -1) {
        file->sys_err = 1;
        return pcap_errori(errno, "pcap: magic rewind failed");
    }

    if (pcap_islegacy(magic)) return PCAP_FMTLEG;
    if (pcap_isng(magic)) return PCAP_FMTNG;

    return pcap_errori(EBADMSG, "Not a pcap file");
}

// classic pcap
static int pcap_read_hdr(struct pcap_file *file)
{
    struct pcap_hdr *hdr = &file->hdr.pcap;
    size_t nread = fread(hdr, 1, sizeof(*hdr), file->fp);

    if (nread < sizeof(file->hdr.pcap)) {
        if (!ferror(file->fp)) errno = EBADMSG;
        return pcap_errori(errno, "Read %zu byte pcap-hdr failed", sizeof(*hdr));
    }

    if (!pcap_isnative(hdr->magic_num)) {
        file->must_swap = 1;
        hdr->magic_num = __builtin_bswap32(hdr->magic_num);
        hdr->major_ver = __builtin_bswap16(hdr->major_ver);
        hdr->minor_ver = __builtin_bswap16(hdr->minor_ver);
        hdr->rsvd1 = __builtin_bswap32(hdr->rsvd1);
        hdr->rsvd2 = __builtin_bswap32(hdr->rsvd2);
        hdr->snap_len = __builtin_bswap32(hdr->snap_len);
        hdr->link_type = __builtin_bswap32(hdr->link_type);
    }
    
    if (file->trace_rec) {
        pcap_log("PCAP-HDR",
            "magic=0x%08x major=%d minor=%d resv1=%u resv2=%u snap_len=%u link_type=%u", 
            hdr->magic_num,
            hdr->major_ver, hdr->minor_ver, 
            hdr->rsvd1, hdr->rsvd2,
            hdr->snap_len, hdr->link_type);
    }

    return 0;
}

static size_t pcap_read_pkt(struct pcap_file *file, void *buf, size_t len)
{
    struct pcap_rec rec;

    // read the packet record
    if (pcap_read_block(file, "pcap-rec", &rec, sizeof(rec)) != 0) {
        // tell caller to stop reading
        return 0;
    }

    if (file->must_swap) {
        rec.ts_sec = __builtin_bswap32(rec.ts_sec);
        rec.ts_usec = __builtin_bswap32(rec.ts_usec);
        rec.incl_len = __builtin_bswap32(rec.incl_len);
        rec.orig_len = __builtin_bswap32(rec.orig_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAP-REC",
            "rec=%lu ts_sec=%u ts_usec=%u inc_len=%u orig_len=%u",
            file->rec_cnt, 
            rec.ts_sec, rec.ts_usec, rec.incl_len, rec.orig_len);
    }

    // can we fit the packet
    if (rec.incl_len > len) {
       return pcap_errori(EBADMSG, "pcap-read pkt-len %u too big for buf %zu", rec.incl_len, len);
    }

    // read the packet data
    if (pcap_read_data(file, "pcap-rec", buf, rec.incl_len) != 0) {
        return -1;
    }

    // packet len
    return rec.incl_len;
}


static int pcap_read_shb(struct pcap_file *file)
{
    struct pcapng_shb_hdr *shb = &file->hdr.pcapng;

    if (pcap_read_block(file, "SHB", shb, sizeof(*shb)) != 0) {
        return -1;
    }

    if (!pcap_bom_isng(shb->magic)) {
        return pcap_errori(EBADMSG, "pcapng: Bad SHB bom 0x%08x", shb->magic);
    }

    file->must_swap = pcapng_isnative(shb->magic) ? 0 : 1; 

    if (file->must_swap) {
        shb->type = __builtin_bswap32(shb->type);
        shb->total_len = __builtin_bswap32(shb->total_len);
        shb->magic = __builtin_bswap32(shb->magic);
        shb->ver_major = __builtin_bswap16(shb->ver_major);
        shb->ver_minor = __builtin_bswap16(shb->ver_minor);
        shb->sec_len = (int64_t) __builtin_bswap64(shb->sec_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x total_len=%u magic=0x%08x ver_major=%d ver_minor=%d sec_len=%ld", 
            file->rec_cnt, "SHB", shb->type, shb->total_len, 
            shb->magic, shb->ver_major, shb->ver_minor, (signed long) shb->sec_len);
    }

    if (shb->total_len < sizeof(*shb)) {
        return pcap_errori(EBADMSG, "pcapng: bad block %lu type %s len %u", file->rec_cnt, "SHB", shb->total_len);
    }

    // skip options + footer
    uint32_t skip_len = shb->total_len - sizeof(*shb);
    return pcap_data_skip(file, "SHB", skip_len);
}

static int pcap_read_idb(struct pcap_file *file)
{
    struct pcapng_idb_hdr *idb = &file->idb;

    if (pcap_read_block(file, "IDB", idb, sizeof(*idb)) != 0) {
        return -1;
    }

    file->have_idb = 1;

    if (file->must_swap) {
        idb->type = __builtin_bswap32(idb->type);
        idb->total_len = __builtin_bswap32(idb->total_len);
        idb->link_type = __builtin_bswap16(idb->link_type);
        idb->reserved = __builtin_bswap16(idb->reserved);
        idb->snap_len = __builtin_bswap32(idb->snap_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x total_len=%u link_type=%d rsvd=%d snap_len=%u", 
            file->rec_cnt, "IDB", idb->type, idb->total_len, 
            idb->link_type, idb->reserved, idb->snap_len);
    }

    if (idb->total_len < sizeof(*idb)) {
        return pcap_errori(EBADMSG, "pcapng: bad block %lu type %s len %u", file->rec_cnt, "IDB", idb->total_len);
    }

    // skip options + footer;
    uint32_t skip_len = idb->total_len - sizeof(*idb);
    return pcap_data_skip(file, "IDB", skip_len);
}

static size_t pcap_read_epb(struct pcap_file *file, void *buf, size_t len)
{
    if (!file->have_idb) {
        return pcap_errori(EBADMSG, "pcapng: bad block %lu type %s %s", file->rec_cnt, "EPB", "missing IDB");
    }

    // read the header
    struct pcapng_epb_hdr epb;
    if (pcap_read_block(file, "EPB", &epb, sizeof(epb)) != 0) {
        return 0; 
    }

    if (file->must_swap) {
        epb.type = __builtin_bswap32(epb.type);
        epb.total_len = __builtin_bswap32(epb.total_len);
        epb.if_id = __builtin_bswap32(epb.if_id);
        epb.ts_high = __builtin_bswap32(epb.ts_high);
        epb.ts_low = __builtin_bswap32(epb.ts_low);
        epb.incl_len = __builtin_bswap32(epb.incl_len);
        epb.orig_len = __builtin_bswap32(epb.orig_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x total_len=%u"
            " if_id=%d ts_high=%d ts_low=%u inc_len=%u orig_len=%u",
            file->rec_cnt, "EPB", epb.type, epb.total_len, 
            epb.if_id, epb.ts_high, epb.ts_low, epb.incl_len, epb.orig_len);
    }

    if (epb.total_len < sizeof(epb)) {
        return pcap_errori(EBADMSG, "pcapng: bad block %lu type %s len %u", file->rec_cnt, "EPB", epb.total_len);
    }

    // read packet data
    uint32_t cap_len = epb.incl_len;
    if (pcap_read_data(file, "EPB", buf, epb.incl_len) != 0) {
        return 0;
    }

    // skip padding + options
    uint32_t skip_len = epb.total_len - (sizeof(epb) + cap_len);
    if (pcap_data_skip(file, "EPB", skip_len) != 0) {
        return 0;
    }

    // report packet length
    return epb.incl_len;
}

static ssize_t pcap_read_spb(struct pcap_file *file, void *buf, size_t len)
{
    if (!file->have_idb) {
        return pcap_errori(EBADMSG, "pcapng: bad block %lu type %s %s", file->rec_cnt, "SPB", "missing IDB");
    }

    // read the header
    struct pcapng_epb_hdr spb;
    if (pcap_read_block(file, "SPB", &spb, sizeof(spb)) != 0) {
        return -1;
    }

    if (file->must_swap) {
        spb.type = __builtin_bswap32(spb.type);
        spb.total_len = __builtin_bswap32(spb.total_len);
        spb.orig_len = __builtin_bswap32(spb.orig_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x len=%u"
            " orig_len=%u incl_len=%u",
            file->rec_cnt, "SPB", spb.type, spb.total_len, 
            spb.orig_len, spb.total_len - (int) sizeof(spb) + 4); 
    }

    if (spb.total_len < sizeof(spb)) {
        return pcap_errori(EBADMSG, "pcapng: bad block %lu type %s len %u", file->rec_cnt, "SPB", spb.total_len);
    }

    // read packet data
    uint32_t cap_len = spb.total_len - (sizeof(spb) + 4);
    if (pcap_read_data(file, "SPB", buf, cap_len) != 0) {
        return 0;
    }

    // skip padding + footer
    uint32_t skip_len = spb.total_len - (sizeof(spb) + cap_len);
    if (pcap_data_skip(file, "SPB", skip_len) != 0) {
        return 0;
    }

    // report packet length
    return cap_len;
}

static int pcap_skip_block(struct pcap_file *file)
{
    struct {
        uint32_t type; 
        uint32_t total_len;
    } blk;

    if (pcap_read_block(file, "skip", &blk, sizeof(&blk)) != 0) {
        return -1;
    }

    if (file->must_swap) {
        blk.type = __builtin_bswap32(blk.type);
        blk.total_len = __builtin_bswap32(blk.total_len);
    }

    if (blk.total_len < sizeof(blk)) {
        return pcap_errori(EBADMSG, "pcap: Bad block %lu total_len %u", file->rec_cnt + 1, blk.total_len);
    }

    // skip options
    return pcap_data_skip(file, "skip-block", blk.total_len - sizeof(blk) + 4);
}

static int pcap_peek_block(struct pcap_file *file)
{
    uint32_t type;

    int nr = pcap_read_data(file, "peek-block", &type, sizeof(type));
    if (nr != 0) return nr;

    nr = pcap_data_rewind(file, "peek-rewind", sizeof(type));
    if (nr != 0) return nr;

    if (file->must_swap) {
        type = __builtin_bswap32(type);
    }

    return type;
}

static size_t pcapng_read_pkt(struct pcap_file *file, void *buf, size_t len)
{
	int block_type;

	while ((block_type = pcap_peek_block(file)) >= 0) {
		switch(block_type) {
		case PCAP_SHB_TYPE: 
            if (pcap_read_shb(file) != 0) return -1;
            break;
		case PCAP_IDB_TYPE: 
            if (pcap_read_idb(file) != 0) return -1; 
            break;
		case PCAP_EPB_TYPE: 
            return pcap_read_epb(file, buf, len);
		case PCAP_SPB_TYPE: 
            return pcap_read_spb(file, buf, len);
        default: 
            if (pcap_skip_block(file) != 0) return -1;
	    }
    }

    // eof or error
    return 0;
}

static void pcap_close_werr(struct pcap_file *file, int ec)
{
    pcap_close(file);
    errno = ec;
}

static int pcap_setup_fptrs(struct pcap_file *file)
{

    switch(file->fmt) {
    case PCAP_FMTLEG:
        file->read_hdr = pcap_read_hdr;
        file->read_pkt = pcap_read_pkt;
        break;
    case PCAP_FMTNG: 
        file->read_hdr = pcap_read_shb;
        file->read_pkt = pcapng_read_pkt;
        break;
    default: 
        break;
    }

    return 0;

}

struct pcap_file *pcap_open(const char *path, int flags)
{
    struct pcap_file *file;

    // check read|write mode
    int mode = flags & (PCAP_READ | PCAP_WRITE);
    if (mode == 0 || mode == (PCAP_READ | PCAP_WRITE)) {
        return pcap_errorn(EINVAL, "Read or Write flag must be set");
    }

    file = malloc(sizeof(*file));
    if (!file) {
        return pcap_errorn(errno, "malloc state");
    }
    memset(file, 0, sizeof(*file));

    if (flags & PCAP_TRACE) file->trace_rec = 1;
    if (flags & PCAP_READ) file->is_reader = 1;

    char *open_mode = file->is_reader ? "rb" : "wb";

    file->fp = fopen(path, open_mode);
    if (!file->fp) {
        pcap_close_werr(file, errno);
        return pcap_errorn(errno, "fopen %s", path);
    }

    // detect the file
    file->fmt = pcap_detect_fmt(file);
    if (pcap_setup_fptrs(file) != 0) {
        pcap_close_werr(file, EPROTONOSUPPORT);
        return NULL;
    }

    if (file->read_hdr(file) != 0) {
        pcap_close_werr(file, errno);
        file = NULL;
    }

    return file;
}

void pcap_close(struct pcap_file *file)
{
    if (file->fp) {
        fclose(file->fp);
        file->fp = NULL;
    }

    free(file);
}


size_t pcap_read(struct pcap_file *file, void *buf, size_t len)
{
    if (file->sys_err) {
        return 0;
    }
   
    size_t nread = file->read_pkt(file, buf, len);

    if (nread > 0) {
        file->pkt_cnt++;
    }

    // all done
    return nread;
}
