/*
 * PCAP - A packet capture file reader and writer
 *
 * API
 * ---
 *  pcap_open - open pcap file  (pathname, flags)
 *  pcap_read - read ethernet packet from the file
 *  pcap_write - write an ethernet packet to the file
 *  pcap_close - close pcap file
 *   
 * Flags
 * -----
 *  PCAP_READ   - open packet captue file for reading
 *  PCAP_WRITE  - open a new packet capture for writing
 *  PCAP_FMTLEG - pcap classic (default)
 *  PCAP_FMTNG  - pcap nextgen (pcapng)
 *  PCAP_FMTDET - Detect file fmt if fmt not given
 *  PCAP_TRACE  - trace pcap records
 *
 * File formats
 * ------------
 *  pcap_file = global_header, { packet_record } ;
 *  packet_record = packet_header, packet_data ;
 *
 *  pcapng_file    = pcapng_section, { pcapng_section } ;
 *  pcapng_section = section_header, { pcapng_block } ;
 *  pcapng_block = interface_desc
 *      | enhanced_packet
 *      | simple_packet
 *      | name_resolution
 *      | interface_statistics
 *      | custom_block ;
 *
 * 
 * References
 *  ----------
 * - draft-ietf-opsawg-pcap-06 - PCAP Capture File Format
 * - draft-ietf-opsawg-pcapng-04 - PCAP Now Generic (pcapng) Capture File Format
*/

#ifndef __PCAP_H__
#define __PCAP_H__

#include <stdio.h>
#include <stdint.h>

// File Endian Information

// pcap legacy
#define PCAP_MAGIC_LE_USEC 0xA1B2C3D4
#define PCAP_MAGIC_LE_NSEC 0xA1B23C4D
#define PCAP_MAGIC_BE_USEC 0xD4C3B2A1 
#define PCAP_MAGIC_BE_NSEC 0x4D3C2B1A

// pcap-ng
#define PCAP_SHB_TYPE    0x0A0D0D0A 
#define PCAP_IDB_TYPE    0x00000001
#define PCAP_EPB_TYPE    0x00000006
#define PCAP_SPB_TYPE    0x00000003

#define PCAP_BOM_NATIVE  0x1A2B3C4D
#define PCAP_BOM_SWAP    0x4D3C2B1A

// link types
#define LINKTYPE_ETHERNET 1

// PCAP Capture File Format - draft-ietf-opsawg-pcap-06

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

// PCAPng file format - draft-ietf-opsawg-pcapng-04

// 28 byte section header
struct pcap_shb_hdr {
    uint32_t type;      // Block Type = 0x0A0D0D0A
    uint32_t tot_len;   // Block Total Length
    uint32_t magic;     // Byte-Order Magic
    uint16_t ver_major; // Major Version
    uint16_t ver_minor; // Minor Version
    int64_t  sec_len;  // Section Length
};

// 16 byte interface description header
struct pcap_idb_hdr {
    uint32_t type; //  Block Type = 0x00000001
    uint32_t tot_len;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
};

// 32 byte Enhanced Packet Block header
struct pcap_epb_hdr {
    uint32_t type;      // Block Type = 0x00000006
    uint32_t tot_len; // Block Total Length
    uint32_t if_id;     // Interface ID
    uint32_t ts_high;   // Timestamp Upper 32 bits
    uint32_t ts_low;    // Timesgtamp lower 32 bits
    uint32_t incl_len;  // Captured Packet Length 
    uint32_t orig_len;  // Original Packet Length  
};

// 12 byte Simple Packet Block header
struct pcap_spb_hdr {
    uint32_t type;      // Block Type = 0x00000003
    uint32_t tot_len; // Block Total Length
    uint32_t orig_len;  // Original Packet Length  
};

struct pcap_file {
    FILE *fp;
    union {
        struct pcap_hdr     hdr;
        struct pcap_shb_hdr shb;
    };
    struct pcap_idb_hdr idb;  
    int fmt; // PCAP_FMTLEG, PCAP_FMTNG
    int (*read_hdr)(struct pcap_file *file);
    ssize_t (*read_pkt)(struct pcap_file *file, void *buf, size_t len);
    int (*write_hdr)(struct pcap_file *file);
    int (*write_pkt)(struct pcap_file *file, void *buf, size_t len);
    int sys_errno; // saved errno
    uint64_t usec_ts;
    unsigned int is_reader : 1; // we read pcap
    unsigned int must_swap : 1; // need to swap endian
    unsigned int have_idb  : 1; // read or set IDB
    unsigned int use_epb   : 1; // write a epb or spb
    unsigned int sys_err   : 1;
    unsigned int have_eof  : 1;
    unsigned int trace_rec : 1;
    unsigned long pkt_cnt;
    unsigned long rec_cnt;
};

// mode flags
#define PCAP_READ   0x01 // open for reading
#define PCAP_WRITE  0x02 // open for writing
#define PCAP_FMTDET 0x04 // detect pcap|pcapng
#define PCAP_FMTLG  0x08 // pcap legacy/classic
#define PCAP_FMTNG  0x10 // pcap nextgen (pcapng)
#define PCAP_TRACE  0x20 // trace pcap records

#define PCAP_SNAPLEN 65535

// helper functions
static inline int pcap_islg(uint32_t magic)
{
    if (magic == PCAP_MAGIC_LE_USEC) return 1;
    if (magic == PCAP_MAGIC_LE_NSEC) return 1;
    if (magic == PCAP_MAGIC_BE_USEC) return 1;
    if (magic == PCAP_MAGIC_BE_USEC) return 1;

    return 0;
}

static inline int pcap_isng(uint32_t magic)
{
    return magic == PCAP_SHB_TYPE;
}

static inline int pcap_bom_isng(uint32_t magic)
{
    if (magic == PCAP_BOM_NATIVE) return 1;
    if (magic == PCAP_BOM_SWAP) return 1;
    return 0;
}

static inline int pcap_isnative(uint32_t magic)
{
    return magic == PCAP_MAGIC_LE_USEC || magic == PCAP_MAGIC_LE_NSEC;
}

static inline int pcapng_isnative(uint32_t magic)
{
    return magic == PCAP_BOM_NATIVE;
}


// API
struct pcap_file *pcap_open(const char *path, uint32_t mode);
int pcap_close(struct pcap_file *pf);
size_t pcap_read(struct pcap_file *pf, void *buf, size_t len);
int pcap_write(struct pcap_file *pf, void *buf, size_t len);


#endif
