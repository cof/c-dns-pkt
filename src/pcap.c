/*
 * PCAP - A packet capture file reader and writer
 *
 * Supports
 * - read | write classic/legacy pcap file format
 * - read | write pcapng file format
 *
 * API
 * ---
 * - pcap_open  : open file (path, mode)
 * - pcap_read  : read a packet
 * - pcap_write : write a packet
 * - pcap_close : close file
 */

#include <stdlib.h>
#include <time.h>
#include <errno.h>

#include "util.h"
#include "log.h"
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

static inline uint32_t calc_padlen(uint32_t cap_len)
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
    int rc = pcap_read_data(file, name, block, len);
    if (rc) return rc;

    file->rec_cnt++;

    return 0;
}

// wrapper around fwrite call - track/log errors
static int pcap_write_data(struct pcap_file *file, const char *name, void *data, size_t len)
{
    size_t nwrite = fwrite(data, 1, len, file->fp);

    if (nwrite != len) {
        if (ferror(file->fp)) {
            return pcap_log_errno_rf(file, "pcap: write %s #%lu size %zu failed", name, file->rec_cnt + 1,  len);
        }
        // should never happen
        file->sys_errno = EIO;
        return PCAP_FAIL;
    }

    return 0;
}

// this tracks both records and blocks
static int pcap_write_block(struct pcap_file *file, const char *name, void *block, size_t len)
{
    int rc = pcap_write_data(file, name, block, len);
    if (rc) return rc;

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

    if (pcap_islg(magic)) return PCAP_FMTLG;
    if (pcap_isng(magic)) return PCAP_FMTNG;

    return log_error_rf("Not a pcap file");
}

/*  
 * classic pcap
 *  pcap_read_hdr
 *  pcap_read_rec
 *  pcap_write_hdr
 *  pcap_wrte_rec
 */
static int pcap_read_hdr(struct pcap_file *file)
{
    struct pcap_hdr *hdr = &file->hdr;

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

static ssize_t pcap_read_rec(struct pcap_file *file, void *buf, size_t len)
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
    rc = pcap_read_data(file, "pcap-rec", buf, rec.incl_len);
    if (rc) return rc;

    // packet len
    return rec.incl_len;
}

static int pcap_write_hdr(struct pcap_file *file)
{
    struct pcap_hdr *hdr = &file->hdr;

    // set header
    hdr->magic_num = PCAP_MAGIC_LE_USEC;
    hdr->major_ver = 2;
    hdr->minor_ver = 4;
    hdr->rsvd1 = 0;
    hdr->rsvd2 = 0;
    hdr->snap_len = PCAP_SNAPLEN;
    hdr->link_type = LINKTYPE_ETHERNET;

    int rc = pcap_write_data(file, "pcap-hdr", hdr, sizeof(*hdr));
    if (rc) return rc;
    
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

static uint64_t pcap_get_ts(struct pcap_file *file)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        log_errno_rf("clock_gettime MONOTTONIC failed");
        return 0;
    }
    uint64_t mono_usec = (uint64_t) ts.tv_sec * 1000000LL + (ts.tv_nsec / 1000);

    return mono_usec + file->epoch_usec;
}

static int pcap_write_rec(struct pcap_file *file, void *buf, size_t len)
{
    uint64_t usec_ts = pcap_get_ts(file);

    struct pcap_rec rec = {
        .ts_sec   = usec_ts / 1000000,
        .ts_usec  = usec_ts % 1000000,
        .incl_len = len,
        .orig_len = len
    };

    int rc = pcap_write_block(file, "pcap-rec", &rec, sizeof(rec));
    if (rc) return rc;

    if (file->trace_rec) {
        pcap_log("PCAP-REC",
            "rec=%lu ts_sec=%u ts_usec=%u inc_len=%u orig_len=%u",
            file->rec_cnt, 
            rec.ts_sec, rec.ts_usec, rec.incl_len, rec.orig_len);
    }

    // write the packet data
    rc = pcap_write_data(file, "pcap-rec", buf, len);
    if (rc) return rc;

    // all done
    return 0;
}

/* 
 * pcapng block layout
 * Section Header
 * |
 * +- Interface Description
 * |  +- Simple Packet
 * |  +- Enhanced Packet
 * |  +- Interface Statistics
 * |
 * +- Name Resolution
 */
static int pcap_read_shb(struct pcap_file *file)
{
    struct pcap_shb_hdr *shb = &file->shb;

    int rc = pcap_read_block(file, "SHB", shb, sizeof(*shb));
    if (rc) return rc;

    if (!pcap_bom_isng(shb->magic)) {
        return log_error_rf("pcapng: Bad SHB bom 0x%08x", shb->magic);
    }

    file->must_swap = pcapng_isnative(shb->magic) ? 0 : 1; 

    if (file->must_swap) {
        shb->type = __builtin_bswap32(shb->type);
        shb->tot_len = __builtin_bswap32(shb->tot_len);
        shb->magic = __builtin_bswap32(shb->magic);
        shb->ver_major = __builtin_bswap16(shb->ver_major);
        shb->ver_minor = __builtin_bswap16(shb->ver_minor);
        shb->sec_len = (int64_t) __builtin_bswap64(shb->sec_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x tot_len=%u magic=0x%08x ver_major=%d ver_minor=%d sec_len=%ld", 
            file->rec_cnt, "SHB", shb->type, shb->tot_len, 
            shb->magic, shb->ver_major, shb->ver_minor, (signed long) shb->sec_len);
    }

    if (shb->tot_len < sizeof(*shb)) {
        return log_error_rf("pcapng: bad block %lu type %s len %u", file->rec_cnt, "SHB", shb->tot_len);
    }

    // skip options + footer
    return pcap_data_skip(file, "SHB", shb->tot_len - sizeof(*shb));
}

static int pcap_write_shb(struct pcap_file *file)
{
    struct pcap_shb_hdr *shb = &file->shb;

    shb->type = PCAP_SHB_TYPE;
    shb->tot_len   = sizeof(*shb) + 4;
    shb->ver_major = 1;
    shb->ver_minor = 0;
    shb->magic     =  PCAP_BOM_NATIVE;
    shb->sec_len   = -1;
  
    // write hdr + footer
    int rc = pcap_write_block(file, "SHB", shb, sizeof(*shb));
    if (rc) return rc;
    rc = pcap_write_data(file, "SHB", &shb->tot_len, sizeof(shb->tot_len));
    if (rc) return rc;

    // write an IDB on next packet
    file->have_idb = 0;

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x tot_len=%u magic=0x%08x ver_major=%d ver_minor=%d sec_len=%ld", 
            file->rec_cnt, "SHB", shb->type, shb->tot_len, 
            shb->magic, shb->ver_major, shb->ver_minor, (signed long) shb->sec_len);
    }

    return 0;
}

static int pcap_read_idb(struct pcap_file *file)
{
    struct pcap_idb_hdr *idb = &file->idb;

    int rc = pcap_read_block(file, "IDB", idb, sizeof(*idb));
    if (rc) return rc;

    file->have_idb = 1;

    if (file->must_swap) {
        idb->type = __builtin_bswap32(idb->type);
        idb->tot_len = __builtin_bswap32(idb->tot_len);
        idb->link_type = __builtin_bswap16(idb->link_type);
        idb->reserved = __builtin_bswap16(idb->reserved);
        idb->snap_len = __builtin_bswap32(idb->snap_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x tot_len=%u link_type=%d rsvd=%d snap_len=%u", 
            file->rec_cnt, "IDB", idb->type, idb->tot_len, 
            idb->link_type, idb->reserved, idb->snap_len);
    }

    if (idb->tot_len < sizeof(*idb)) {
        return log_error_rf("pcapng: bad block %lu type %s len %u", file->rec_cnt, "IDB", idb->tot_len);
    }

    // skip options + footer;
    return pcap_data_skip(file, "IDB", idb->tot_len - sizeof(*idb));
}

static int pcap_write_idb(struct pcap_file *file)
{
    struct pcap_idb_hdr *idb = &file->idb;

    idb->type = PCAP_IDB_TYPE;
    idb->tot_len = sizeof(*idb) + 4;
    idb->link_type = LINKTYPE_ETHERNET;
    idb->reserved = 0;
    idb->snap_len = PCAP_SNAPLEN;

    // write hdr + footer
    int rc = pcap_write_block(file, "IDB", idb, sizeof(*idb));
    if (rc) return rc;
    rc = pcap_write_data(file, "IDB", &idb->tot_len, sizeof(idb->tot_len));
    if (rc) return rc;

    file->have_idb = 1;

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x tot_len=%u link_type=%d rsvd=%d snap_len=%u", 
            file->rec_cnt, "IDB", idb->type, idb->tot_len, 
            idb->link_type, idb->reserved, idb->snap_len);
    }

    return 0;
}

// return packet length or zero on error or eof
static size_t pcap_read_epb(struct pcap_file *file, void *buf, size_t buf_len)
{
    if (!file->have_idb) {
        return log_error_rz("pcapng: bad block %lu type %s %s", file->rec_cnt, "EPB", "missing IDB");
    }

    // read the header
    struct pcap_epb_hdr epb;
    int rc = pcap_read_block(file, "EPB", &epb, sizeof(epb));
    if (rc) return 0;

    if (file->must_swap) {
        epb.type = __builtin_bswap32(epb.type);
        epb.tot_len = __builtin_bswap32(epb.tot_len);
        epb.if_id = __builtin_bswap32(epb.if_id);
        epb.ts_high = __builtin_bswap32(epb.ts_high);
        epb.ts_low = __builtin_bswap32(epb.ts_low);
        epb.incl_len = __builtin_bswap32(epb.incl_len);
        epb.orig_len = __builtin_bswap32(epb.orig_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x tot_len=%u"
            " if_id=%d ts_high=%d ts_low=%u inc_len=%u orig_len=%u",
            file->rec_cnt, "EPB", epb.type, epb.tot_len, 
            epb.if_id, epb.ts_high, epb.ts_low, epb.incl_len, epb.orig_len);
    }

    if (epb.tot_len < sizeof(epb)) {
        return log_error_rz("pcapng: bad block %lu type %s len %u", file->rec_cnt, "EPB", epb.tot_len);
    }

    if (epb.incl_len > buf_len) {
        return log_error_rz("pcapng: block %lu type %s len %u > buf %zu",
            file->rec_cnt, "EPB", epb.incl_len, buf_len);
    }

    // read packet data
    uint32_t cap_len = epb.incl_len;
    rc = pcap_read_data(file, "EPB", buf, epb.incl_len);
    if (rc) return 0;

    // skip padding + options
    uint32_t skip_len = epb.tot_len - (sizeof(epb) + cap_len);
    rc = pcap_data_skip(file, "EPB", skip_len);
    if (rc) return 0;

    // report packet length
    return epb.incl_len;
}

static int pcap_write_epb(struct pcap_file *file, void *buf, size_t buf_len)
{
    uint64_t usec_ts = pcap_get_ts(file);
    uint32_t pad_len = calc_padlen(buf_len);

    struct pcap_epb_hdr epb = {
        .type = PCAP_EPB_TYPE,
        .tot_len  = sizeof(epb) + buf_len + pad_len + 4,
        .if_id    = 0,
        .ts_high  = usec_ts >> 32,
        .ts_low   = usec_ts & 0xFFFFFFFF,
        .incl_len = buf_len,
        .orig_len = buf_len
    };

    int rc = pcap_write_block(file, "EPB", &epb, sizeof(epb));
    if (rc) return rc;

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x tot_len=%u"
            " if_id=%d ts_high=%d ts_low=%u inc_len=%u orig_len=%u",
            file->rec_cnt, "EPB", epb.type, epb.tot_len, 
            epb.if_id, epb.ts_high, epb.ts_low, epb.incl_len, epb.orig_len);
    }

    // write the  packet data
    rc = pcap_write_data(file, "EPB", buf, buf_len);
    if (rc) return 0;

    // padding
    if (pad_len) {
        uint8_t padding[3] = { 0, };
        rc = pcap_write_data(file, "EPB", &padding, pad_len);
        if (rc) return rc;
    }

    // footer
    rc = pcap_write_data(file, "EPB", &epb.tot_len, sizeof(epb.tot_len));
    if (rc) return rc;

    return 0;
}

// return packet length or zero on error or eof
static size_t pcap_read_spb(struct pcap_file *file, void *buf, size_t buf_len)
{
    if (!file->have_idb) {
        return log_error_rz("pcapng: bad block %lu type %s %s", file->rec_cnt, "SPB", "missing IDB");
    }

    // read the header
    struct pcap_spb_hdr spb;
    int rc = pcap_read_block(file, "SPB", &spb, sizeof(spb));
    if (rc) return 0;

    if (file->must_swap) {
        spb.type = __builtin_bswap32(spb.type);
        spb.tot_len = __builtin_bswap32(spb.tot_len);
        spb.orig_len = __builtin_bswap32(spb.orig_len);
    }

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x len=%u"
            " orig_len=%u incl_len=%u",
            file->rec_cnt, "SPB", spb.type, spb.tot_len, 
            spb.orig_len, spb.tot_len - (int) sizeof(spb) + 4); 
    }

    if (spb.tot_len < sizeof(spb)) {
        return log_error_rz("pcapng: bad block %lu type %s len %u", file->rec_cnt, "SPB", spb.tot_len);
    }

    uint32_t cap_len = spb.tot_len - (sizeof(spb) + 4);
    if (cap_len > buf_len) {
        return log_error_rz("pcapng: block %lu type %s len %u > buf %zu",
            file->rec_cnt, "SPB", cap_len, buf_len);
    }

    // read packet data
    rc = pcap_read_data(file, "SPB", buf, cap_len);
    if (rc) return 0;

    // skip padding + footer
    uint32_t skip_len = spb.tot_len - (sizeof(spb) + cap_len);
    rc = pcap_data_skip(file, "SPB", skip_len);
    if (rc) return 0;

    // report packet length
    return cap_len;
}

static int pcap_write_spb(struct pcap_file *file, void *buf, size_t buf_len)
{
    // write the header
    uint32_t pad_len = calc_padlen(buf_len);

    struct pcap_spb_hdr spb = {
        .type = PCAP_SPB_TYPE,
        .tot_len = sizeof(spb) + buf_len + pad_len + 4,
        .orig_len = buf_len
    };

    int rc = pcap_write_block(file, "SPB", &spb, sizeof(spb));
    if (rc) return rc;

    if (file->trace_rec) {
        pcap_log("PCAPNG",
            "blk=%lu name=%s type=0x%08x len=%u"
            " orig_len=%u incl_len=%u",
            file->rec_cnt, "SPB", spb.type, spb.tot_len, 
            spb.orig_len, spb.tot_len - (int) sizeof(spb) + 4); 
    }

    // write the  packet data
    rc = pcap_write_data(file, "SPB", buf, buf_len);
    if (rc) return 0;

    // padding
    if (pad_len) {
        uint8_t padding[3] = { 0, };
        rc = pcap_write_data(file, "SPB", &padding, pad_len);
        if (rc) return rc;
    }

    // footer
    rc = pcap_write_data(file, "SPB", &spb.tot_len, sizeof(spb.tot_len));
    if (rc) return rc;

    return 0;
}


static int pcap_skip_block(struct pcap_file *file)
{
    struct {
        uint32_t type; 
        uint32_t tot_len;
    } blk;

    int rc = pcap_read_block(file, "skip", &blk, sizeof(&blk));
    if (rc) return rc;

    if (file->must_swap) {
        blk.type = __builtin_bswap32(blk.type);
        blk.tot_len = __builtin_bswap32(blk.tot_len);
    }

    if (blk.tot_len < sizeof(blk)) {
        return log_error_rf("pcap: Bad block %lu tot_len %u", file->rec_cnt + 1, blk.tot_len);
    }

    // skip options
    return pcap_data_skip(file, "skip-block", blk.tot_len - sizeof(blk) + 4);
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

// read pcapng packet data from either SPB or EPB
static ssize_t pcap_read_xpb(struct pcap_file *file, void *buf, size_t len)
{
    int block_type;

    while ((block_type = pcap_peek_block(file)) >= 0) {
        switch(block_type) {
        case PCAP_SHB_TYPE: if (pcap_read_shb(file)) return -1; break;
        case PCAP_IDB_TYPE: if (pcap_read_idb(file)) return -1; break;
        case PCAP_EPB_TYPE: return pcap_read_epb(file, buf, len);
        case PCAP_SPB_TYPE: return pcap_read_spb(file, buf, len);
        default: if (pcap_skip_block(file)) return -1;
        }
    }

    // eof or error
    return 0;
}

// write PCAPNG packet data block using either SPB or EPB
static int pcap_write_xpb(struct pcap_file *file, void *buf, size_t len)
{
    if (!file->have_idb) {
        int rc = pcap_write_idb(file);
        if (rc) return rc;
    }
   
    int rc = file->use_spb
        ? pcap_write_spb(file, buf, len)
        : pcap_write_epb(file, buf, len);
        
    return rc;
}

static int pcap_setup_ts(struct pcap_file *file)
{
    struct timespec real_ts, mono_ts;

    if (clock_gettime(CLOCK_REALTIME, &real_ts) != 0) {
        return log_errno_rf("clock_gettime REALTIME failed");
    }
    if (clock_gettime(CLOCK_MONOTONIC, &mono_ts) != 0) {
        return log_errno_rf("clock_gettime MONOTONIC failed");
    }

    // calc epoch offset
    uint64_t real_usec = real_ts.tv_sec * 1000000LL + (real_ts.tv_nsec / 1000);
    uint64_t mono_usec = mono_ts.tv_sec * 1000000LL + (mono_ts.tv_nsec / 1000);

    if (real_usec >= mono_usec) {
        file->epoch_usec = real_usec - mono_usec;
    }
    else {
        log_error("clock_gettime REALTIME < MONOTONIC !!!");
        file->epoch_usec = 0;
    }

    return 0;
}

static int pcap_setup_fmt(struct pcap_file *file)
{
    if (!file->fmt) {
        // select a file fmt
        file->fmt = file->is_reader 
            ? pcap_detect_fmt(file)
            : PCAP_FMTLG;
    }

    // set up func ptrs
    switch(file->fmt) {
    case PCAP_FMTLG:
        file->read_hdr  = pcap_read_hdr;
        file->read_pkt  = pcap_read_rec;
        file->write_hdr = pcap_write_hdr;
        file->write_pkt = pcap_write_rec;
        break;
    case PCAP_FMTNG: 
        file->read_hdr  = pcap_read_shb;
        file->read_pkt  = pcap_read_xpb;
        file->write_hdr = pcap_write_shb;
        file->write_pkt = pcap_write_xpb;
        break;
    default: 
        return log_error_rf("pcap fmt %d unsupported", file->fmt);
    }



    return 0;
}

static int pcap_setup_hdr(struct pcap_file *file)
{
    return file->is_reader
        ? (file->read_hdr)(file)
        : (file->write_hdr)(file);
}

struct pcap_file *pcap_open(const char *path_name, uint32_t flags)
{
    struct pcap_file *file;

    // check flags 
    int mode = flags & (PCAP_READ | PCAP_WRITE);
    if (mode == 0 || mode == (PCAP_READ | PCAP_WRITE)) {
        return log_error_rn("Mode must be ether Read or Write");
    }

    int fmt = flags & (PCAP_FMTLG | PCAP_FMTNG);
    if (fmt != 0 && fmt == (PCAP_FMTLG | PCAP_FMTNG)) {
        return log_error_rn("pcap Format must be either legacy or ng");
    }

    file = malloc(sizeof(*file));
    if (!file) {
        return log_errno_rn("malloc state");
    }

    // init
    memset(file, 0, sizeof(*file));
    file->fmt = fmt;
    if (flags & PCAP_TRACE) file->trace_rec = 1;
    if (flags & PCAP_READ) file->is_reader = 1;
    if (flags & PCAP_SPB) file->use_spb = 1;

    if (pcap_open_file(file, path_name) != 0) goto err;
    if (pcap_setup_fmt(file) != 0) goto err;
    if (pcap_setup_hdr(file) != 0) goto err;
    if (pcap_setup_ts(file)  != 0) goto err;

    // all done
    return file;

err:
    pcap_close(file);
    return NULL;
}

int pcap_close(struct pcap_file *file)
{
    int rc = 0;

    if (file->fp) {
        if (fclose(file->fp) != 0) {
            log_errno("fclose failed");
            rc = -1;
        }
    }

    if (file->sys_errno) {
        // restore errno
        errno = file->sys_errno;
    }

    free(file);

    return rc;
}


size_t pcap_read(struct pcap_file *file, void *buf, size_t len)
{
    if (file->sys_err || file->have_eof) {
        // nothing to read
        return 0;
    }
   
    ssize_t nread = file->read_pkt(file, buf, len);

    if (nread < 0) nread = 0;
    if (nread > 0) {
        file->pkt_cnt++;
    }

    // all done
    return nread;
}

int pcap_write(struct pcap_file *file, void *buf, size_t len)
{
    if (file->sys_err) {
        return  -1;
    }

    int rc = file->write_pkt(file, buf, len);
    if (rc) return rc;

    file->pkt_cnt++;

    return 0;
}
