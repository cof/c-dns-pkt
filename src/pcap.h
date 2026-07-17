/* SPDX-License-Identifier: MIT | (c) 2026 [cof] */

/*
 * PCAP - A packet capture file API
 * --------------------------------
 * An api  for reading and wrting packet capture files featuring
 * - Both PCAP and PCAPNG file format support
 * - Auto-detect pcap or pcapng format when reading
 * - write either simple or enhanced packet blocks SPB|EPB
 * - uses clock_getime for timestamps
 * - trace mode for debugging pcap files
 *
 * Example usage:
 * --------------
 *  char buf[BUFSIZ];
 *  size_t pkt_len;
 *  pcap = pcap_open(sniff->filename, PCAP_READ | PCAP_TRACE);
 *  while ((pkt_len = pcap_read(cap, buf, sizeof(buf)) > 0) {
 *      // buf has a raw ethernet packet with size pkt_len
 *  }
 *  pcap_close(pcap);
 *
 * API
 * ---
 * pcap_open(file_name, mode) : open pcap file
 * pcap_close(pf)             : close pcap file
 * pcap_read(pf, buf, len)    : read packet from file into buffe
 * pcap_write(pf, buf, len)   : write packet to file
 *
 * mode:  bit-wise mask of the following flags
 * -------------------------------------------
 * PCAP_READ   : open file for reading
 * PCAP_WRITE  : open file for wrting
 * PCAP_FMTDET : detect file fmt if not given
 * PCAP_FMTLG  : pcap legacy/classic
 * PCAP_FMTNG  : pcap nextgen (pcapng)
 * PCAP_TRACE  : trace pcap records
 * PCAP_SPB    : Use Simple Packet Blocks for PCAPNG
 *
 * See below for file fmts and state.
 */
#ifndef _PCAP_H_
#define _PCAP_H_

#include <stdio.h>
#include <stdint.h>

// link types
#define LINKTYPE_ETHERNET 1

/*
 * PCAP file format
 * ----------------
 * pcap_file = global_header, { packet_record } ;
 * packet_record = packet_header, packet_data ;
 *
 * Refs:
 * ----
 * draft-ietf-opsawg-pcap-06 - PCAP Capture File Format
 */

// endian codes
#define PCAP_MAGIC_LE_USEC 0xA1B2C3D4
#define PCAP_MAGIC_LE_NSEC 0xA1B23C4D
#define PCAP_MAGIC_BE_USEC 0xD4C3B2A1
#define PCAP_MAGIC_BE_NSEC 0x4D3C2B1A

// 24 byte header
struct pcap_hdr {
    uint32_t magic_num;
    uint16_t major_ver;
    uint16_t minor_ver;
    uint32_t rsvd1;
    uint32_t rsvd2;
    uint32_t snap_len;
    uint32_t link_type;
};

// 16 byte record header
struct pcap_rec {
    uint32_t ts_sec;   //  Timestamp (Seconds)
    uint32_t ts_usec;  // Timestamp (Microseconds or nanoseconds)
    uint32_t incl_len; // Captured Packet Length
    uint32_t orig_len; // Original Packet Length
};

/*
 *  PCAPng file format
 *  -------------------
 *  pcapng_file    = pcapng_section, { pcapng_section } ;
 *  pcapng_section = section_header, { pcapng_block } ;
 *  pcapng_block = interface_desc
 *      | enhanced_packet
 *      | simple_packet
 *      | name_resolution
 *      | interface_statistics
 *      | custom_block ;
 *
 *  Refs:
 *  -----
 *  draft-ietf-opsawg-pcapng-04 - PCAP Now Generic (pcapng) Capture File Format
 */

// block types
#define PCAP_SHB_TYPE    0x0A0D0D0A
#define PCAP_IDB_TYPE    0x00000001
#define PCAP_EPB_TYPE    0x00000006
#define PCAP_SPB_TYPE    0x00000003

// endian codes
#define PCAP_BOM_NATIVE  0x1A2B3C4D
#define PCAP_BOM_SWAP    0x4D3C2B1A

// 28 byte section header
struct pcap_shb_hdr {
    uint32_t type;      // Block Type = 0x0A0D0D0A
    uint32_t tot_len;   // Block Total Length
    uint32_t bom;       // Byte-Order Magic
    uint16_t ver_major; // Major Version
    uint16_t ver_minor; // Minor Version
    int64_t  sec_len;   // Section Length
};

// 16 byte - interface description header
struct pcap_idb_hdr {
    uint32_t type;      // Block Type = 0x00000001
    uint32_t tot_len;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
};

// 12 byte - Simple Packet Block header
struct pcap_spb_hdr {
    uint32_t type;      // Block Type = 0x00000003
    uint32_t tot_len; // Block Total Length
    uint32_t orig_len;  // Original Packet Length
};

// 32 byte - Enhanced Packet Block header
struct pcap_epb_hdr {
    uint32_t type;      // Block Type = 0x00000006
    uint32_t tot_len;   // Block Total Length
    uint32_t if_id;     // Interface ID
    uint32_t ts_high;   // Timestamp Upper 32 bits
    uint32_t ts_low;    // Timesgtamp lower 32 bits
    uint32_t incl_len;  // Captured Packet Length
    uint32_t orig_len;  // Original Packet Length
};

/* pcap api */

// api state
struct pcap_file {
    FILE *fp;
    union {
        struct pcap_hdr     hdr;
        struct pcap_shb_hdr shb;
    };
    struct pcap_idb_hdr idb;
    int (*read_hdr)(struct pcap_file *file);
    ssize_t (*read_pkt)(struct pcap_file *file, void *buf, size_t len);
    int (*write_hdr)(struct pcap_file *file);
    int (*write_pkt)(struct pcap_file *file, void *buf, size_t len);
    int sys_errno; // saved errno
    uint64_t epoch_usec;
    unsigned int is_reader : 1; // we read pcap
    unsigned int is_ng     : 1; // pcapng fmt
    unsigned int must_swap : 1; // need to swap endian
    unsigned int have_idb  : 1; // read or set IDB
    unsigned int use_spb   : 1; // Use SPB instead of default EPB
    unsigned int sys_err   : 1; // file error
    unsigned int have_eof  : 1; // reach file end
    unsigned int trace_rec : 1; // log record description
    unsigned long pkt_cnt;
    unsigned long rec_cnt;
};

#define PCAP_SNAPLEN 65535

/*
 * mode:  bit-wise mask of the following flags
 * -------------------------------------------
 */
#define PCAP_READ   (1 << 0) // open file for reading
#define PCAP_WRITE  (1 << 1) // open file for wrting
#define PCAP_FMTDET (1 << 2) // detect file fmt if not given
#define PCAP_FMTLG  (1 << 3) // pcap legacy/classic
#define PCAP_FMTNG  (1 << 4) // pcap nextgen (pcapng)
#define PCAP_TRACE  (1 << 5) // trace pcap records
#define PCAP_SPB    (1 << 6) // Use Simple Packet Blocks for PCAPNG

/*
 * pcap_file API
 * -------------
 *  pcap_open(file_name, mode) : open pcap file
 *  pcap_close(pf)             : close pcap file
 *  pcap_read(pf, buf, len)    : read packet from file into buffe
 *  pcap_write(pf, buf, len)   : write packet to file
 */
struct pcap_file *pcap_open(const char *path, uint32_t flags);
int pcap_close(struct pcap_file *file);
size_t pcap_read(struct pcap_file *file, void *buf, size_t len);
int pcap_write(struct pcap_file *file, void *buf, size_t len);

/* helper functions
 * ----------------
 * pcap_islg : true if file is legacy fmt
 * pcap_isng : true if file is ng fmt
 * pcap_isnative : true if pcap hdr magic field is native
 * pcap_bom_isng : true if xpb magic field is valid bom code
 * pcap_bom_isnative : true if xpb magic fieid is native
 */
static inline int pcap_islg(uint32_t magic)
{
    if (magic == PCAP_MAGIC_LE_USEC) return 1;
    if (magic == PCAP_MAGIC_LE_NSEC) return 1;
    if (magic == PCAP_MAGIC_BE_USEC) return 1;
    if (magic == PCAP_MAGIC_BE_NSEC) return 1;

    return 0;
}

static inline int pcap_isng(uint32_t magic)
{
    return magic == PCAP_SHB_TYPE;
}

static inline int pcap_isnative(uint32_t magic)
{
    return magic == PCAP_MAGIC_LE_USEC || magic == PCAP_MAGIC_LE_NSEC;
}

static inline int pcap_bom_isng(uint32_t magic)
{
    if (magic == PCAP_BOM_NATIVE) return 1;
    if (magic == PCAP_BOM_SWAP) return 1;
    return 0;
}

static inline int pcap_bom_isnative(uint32_t magic)
{
    return magic == PCAP_BOM_NATIVE;
}

#endif
