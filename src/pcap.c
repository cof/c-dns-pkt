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

#define PCAP_FAIL -1
#define PCAP_EOF -2

#define pcap_log(what, fmt, ...) \
    log_info(what, fmt, ##__VA_ARGS__)

// save errno, log errno, return FAIL
#define pcap_log_errno_rf(file, fmt, ...) ({ \
    if (!file->sys_err) { \
        file->sys_err = 1; \
        file->sys_errno = errno; \
    } \
    _log_error(__FILE__, __LINE__, __func__, errno, fmt, ##__VA_ARGS__); \
    UTIL_FAIL; \
})

static uint32_t inline pad_len(uint32_t cap_len)
{
    return  (4 - (cap_len % 4)) % 4;
}

static int pcap_open_file(struct pcap_file *file, const char *path_name)
{
    char *open_mode = file->is_reader ? "rb" : "wb";

    file->fp = fopen(path_name, open_mode);
    if (!file->fp) {
        return pcap_log_errno_rf(file, "fopen %s", path_name);
    }

    return 0;
}

// wrapper around fread call - track/log errors
static int pcap_read_data(struct pcap_file *file, const char *name, void *data, size_t len)
{
    size_t nread = fread(data, 1, len, file->fp);

    if (nread != len) {
        if (ferror(file->fp)) {
            return pcap_log_errno_rf(file, "pcap: Read %s #%lu size %zu failed", name, file->rec_cnt + 1,  len);
        }
        if (nread == 0 && feof(file->fp)) {
            file->have_eof = 1;
            return PCAP_EOF;
        }
        // should never happen
        file->sys_errno = EIO;
        return PCAP_FAIL;
    }

    return 0;
}

// read strt of a new block/record
static int pcap_read_block(struct pcap_file *file, const char *name, void *block, size_t len)
{
    int nr = pcap_read_data(file, name, block, len);
    if (nr != 0) return nr;

    file->rec_cnt++;

    return 0;
}

// wrapper around fseek call - track/log errors
static int pcap_seek_data(struct pcap_file *file, const char *name, long len, int whence)
{
    if (fseek(file->fp, len, whence) != 0) {
        return pcap_log_errno_rf(file, "pcap: %s seek %lu whence %d failed", name, len, whence);
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
    int ec;

    ec = pcap_read_data(file, "magic", &magic, sizeof(magic));
    if (ec) return ec;

    ec = pcap_seek_data(file, "magic rewind", 0, SEEK_SET);
    if (ec) return ec;

    if (pcap_islegacy(magic)) return PCAP_FMTLEG;
    if (pcap_isng(magic)) return PCAP_FMTNG;

    return log_error_rf("Not a pcap file");
}

// classic pcap
static int pcap_read_hdr(struct pcap_file *file)
{
    struct pcap_hdr *hdr = &file->hdr.pcap;

    int rc = pcap_read_data(file, "pcap-hdr", hdr, sizeof(*hdr));
    if (rc) return rc;

    if (!pcap_isnative(hdr->magic_num)) {
        file->must_swap = 1;
    }

    if (file->must_swap) {
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
    int rc = pcap_read_block(file, "pcap-rec", &rec, sizeof(rec));
    if (rc) return rc;

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
       return log_error_rf("pcap-read pkt-len %u too big for buf %zu", rec.incl_len, len);
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

    int rc = pcap_read_block(file, "SHB", shb, sizeof(*shb));
    if (rc) return rc;

    if (!pcap_bom_isng(shb->magic)) {
        return log_error_rf("pcapng: Bad SHB bom 0x%08x", shb->magic);
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
        return log_error_rf("pcapng: bad block %lu type %s len %u", file->rec_cnt, "SHB", shb->total_len);
    }

    // skip options + footer
    return pcap_data_skip(file, "SHB", shb->total_len - sizeof(*shb));
}

static int pcap_read_idb(struct pcap_file *file)
{
    struct pcapng_idb_hdr *idb = &file->idb;

    int rc = pcap_read_block(file, "IDB", idb, sizeof(*idb));
    if (rc) return rc;

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
        return log_error_rf("pcapng: bad block %lu type %s len %u", file->rec_cnt, "IDB", idb->total_len);
    }

    // skip options + footer;
    return pcap_data_skip(file, "IDB", idb->total_len - sizeof(*idb));
}

// return packet length or zero on error or eof
static size_t pcap_read_epb(struct pcap_file *file, void *buf, size_t len)
{
    if (!file->have_idb) {
        return log_error_rz("pcapng: bad block %lu type %s %s", file->rec_cnt, "EPB", "missing IDB");
    }

    // read the header
    struct pcapng_epb_hdr epb;
    int rc = pcap_read_block(file, "EPB", &epb, sizeof(epb));
    if (rc) return 0;

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
        return log_error_rz("pcapng: bad block %lu type %s len %u", file->rec_cnt, "EPB", epb.total_len);
    }

    // read packet data
    uint32_t cap_len = epb.incl_len;
    rc = pcap_read_data(file, "EPB", buf, epb.incl_len);
    if (rc) return 0;

    // skip padding + options
    uint32_t skip_len = epb.total_len - (sizeof(epb) + cap_len);
    rc = pcap_data_skip(file, "EPB", skip_len);
    if (rc) return 0;

    // report packet length
    return epb.incl_len;
}

// return packet length or zero on error or eof
static size_t pcap_read_spb(struct pcap_file *file, void *buf, size_t len)
{
    if (!file->have_idb) {
        return log_error_rz("pcapng: bad block %lu type %s %s", file->rec_cnt, "SPB", "missing IDB");
    }

    // read the header
    struct pcapng_epb_hdr spb;
    int rc = pcap_read_block(file, "SPB", &spb, sizeof(spb));
    if (rc) return 0;

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
        return log_error_rz("pcapng: bad block %lu type %s len %u", file->rec_cnt, "SPB", spb.total_len);
    }

    // read packet data
    uint32_t cap_len = spb.total_len - (sizeof(spb) + 4);
    rc = pcap_read_data(file, "SPB", buf, cap_len);
    if (rc) return 0;

    // skip padding + footer
    uint32_t skip_len = spb.total_len - (sizeof(spb) + cap_len);
    rc = pcap_data_skip(file, "SPB", skip_len);
    if (rc) return 0;

    // report packet length
    return cap_len;
}

static int pcap_skip_block(struct pcap_file *file)
{
    struct {
        uint32_t type; 
        uint32_t total_len;
    } blk;

    int rc = pcap_read_block(file, "skip", &blk, sizeof(&blk));
    if (rc) return rc;

    if (file->must_swap) {
        blk.type = __builtin_bswap32(blk.type);
        blk.total_len = __builtin_bswap32(blk.total_len);
    }

    if (blk.total_len < sizeof(blk)) {
        return log_error_rf("pcap: Bad block %lu total_len %u", file->rec_cnt + 1, blk.total_len);
    }

    // skip options
    return pcap_data_skip(file, "skip-block", blk.total_len - sizeof(blk) + 4);
}

static int pcap_peek_block(struct pcap_file *file)
{
    uint32_t type;

    int rc = pcap_read_data(file, "peek-block", &type, sizeof(type));
    if (rc) return rc;

    rc = pcap_data_rewind(file, "peek-rewind", sizeof(type));
    if (rc) return rc;

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

static int pcap_setup_fmt(struct pcap_file *file)
{
    file->fmt = pcap_detect_fmt(file);

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
        return log_error_rf("pcap fmt %d unsupported", file->fmt);
    }

    return 0;
}

struct pcap_file *pcap_open(const char *path_name, int flags)
{
    struct pcap_file *file;

    // check flags 
    int mode = flags & (PCAP_READ | PCAP_WRITE);
    if (mode == 0 || mode == (PCAP_READ | PCAP_WRITE)) {
        return log_error_rn("Read or Write flag must be set");
    }

    file = malloc(sizeof(*file));
    if (!file) {
        return log_errno_rn("malloc state");
    }

    // init
    memset(file, 0, sizeof(*file));
    if (flags & PCAP_TRACE) file->trace_rec = 1;
    if (flags & PCAP_READ) file->is_reader = 1;

    if (pcap_open_file(file, path_name) != 0) goto err;
    if (pcap_setup_fmt(file) != 0) goto err;
    if (file->read_hdr(file) != 0) goto err;

    // all done
    return file;

err:
    pcap_close(file);
    return NULL;
}

void pcap_close(struct pcap_file *file)
{
    if (file->fp) {
        if (fclose(file->fp) != 0) {
            log_errno("fclose failed");
        }
    }

    if (file->sys_errno) {
        // restore errno
        errno = file->sys_errno;
    }

    free(file);
}


size_t pcap_read(struct pcap_file *file, void *buf, size_t len)
{
    if (file->sys_err || file->have_eof) {
        // nothing to read
        return 0;
    }
   
    size_t nread = file->read_pkt(file, buf, len);

    if (nread > 0) {
        file->pkt_cnt++;
    }

    // all done
    return nread;
}
