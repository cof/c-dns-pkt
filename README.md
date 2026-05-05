# DNS packet

A high performance DNS packet inspector and message generator.

This project began as a 4-day "impossible sprint" to implement a DNS subsystem from first principles with just plain old vim,tmux and gcc. 
It has since evolved into a research work on deep packet inspection and DNS testing.

There are two parts to this project:

- `dns-inspect` a DNS packet inspector
- `dns-gen`     a DNS message generator

## Prerequisites

### Required
- **GCC**: Version 9.0 or higher.
- **make**: Version 4.0 or higher.

### Optional
- **Bash**: Version 4.0+ for the test runner.
- **bpf-gcc**:  Version 12.0+ for compiling BPF programs
- **bpf-objdump** : Version 2.38+ for generating BPF filter

## Building the Project

- **make all** (Default): Compiles dns-inspect and dns-gen
- **make test** : Compiles and test dns-inspect and dns-gen
- **make install** : install to /usr/local/bin (default) (caps enabled)
- **make clean**: Removes all compiled binaries, object files
- **make debug**: Compile code with debug flags

## Design notes

This project is basically an exercise in minimalist system programming.
In an an era where large third party frameworks are often the default,
its far too easy these days for developers to lose sight of the underlying
algorithms, resource costs or the actual kernel ABI being used.

By implementing DNS RFC's, pcap file formats, and XDP packet filtering from first
principles, this project aims to show that a zero-dependency C stack remains a highly
effective choice for writing network packet test tools.

Code is organised as follows:

- single-threaded applications written in C with no 3rd party libs
- DNS API  - DNS message codec in `dns_proto.h` and `dns_proto.c`
- PCAP API - PCAP/PCAPNG read/write support in `pcap.h` and `pcap.c`
- LOG API  - Info and error logging in `log.h` and `log.c`
- UTIL API - string,cmd-line,signal handling in `util.h` and `util.c`

## 1. dns-inspect
A DNS packet inspector that can read DNS messages from a network interface or pcap file.

Tool supports both legacy and state-of-the-art capture modes, including AF_PACKET, PACKET_MMAP and XDP.

**Usage**

    $ dns-inspect 
    Usage: dns-inspect [MODE] [OPTIONS]

    Modes:
     
      capture   Capture DNS messages from a network interface
      readpcap  Read DNS messages from a pcap file
      tracepcap Read record/block info from a pcap file

    capture options:

      --interface <name> network interface to listen on
      --type      <raw|mmap|xdp> capture method (default=raw)
      --file      <path> path to save captured packets
      --log-level <level> logging level (default=3)
      --pcapng    use pcapng file fmt

    readpcap options:

      --file <path> path to capture file to read

    tracepcap options:

      --file <path> path to capture file to read

    Examples:
     
      dns-inspect capture --interface eth0
      dns-inspect capture --interface eth0 --type mmap
      dns-inspect capture --interface eth0 --file dns.pcap
      dns-inspect capture --interface eth0 --file dns.pcapng --pcapng
      dns-inspect readpcap --file dns.pcap
      dns-inspect tracepcap --file dns.pcap


### 1.1 **Capture mode**

Captures, decodes, and prints DNS traffic from a network interface in real-time.

**Features**

- Flexible attachment: supports raw, mmap, and xdp capture types
- Kernel filtering: Uses BPF/eBPF to filter DNS packets in kernel space
- PCAP support: can save DNS traffic to a pcap file
- RFC 1035 compliant: can decode and validate any DNS message
- SETCAP: can be installed with non-root sniffer capabilities

**Design**

- raw  : `AF_PACKET`, `SOCK_RAW`, `cBPF` and `recvmmsg()`
- mmap : `AF_PACKET`, `SOCK_RAW`, `cBPF` and `PACKET_RX_RING` (TPACKET_V3)
- xdp  : `veth-tap`, `AF_XDP`, `eBPF`, `UMEM` (fill/rx rings) and BPF map patching

**Example usage**

    $ make
    $ sudo make install 
    install -D -m 755 dns-inspect /usr/local/bin/dns-inspect
    install -D -m 755 dns-gen /usr/local/bin/dns-gen
    sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf=eip' /usr/local/bin/dns-inspect || true
    $ (sleep 1; dig @8.8.8.8 example.com A example.com AAAA +short >/dev/null) & dns-inspect capture --interface wlp2s0 --file dns.pcap  
    [1] 97975
    [+] DNS active on wlp2s0
    [QUERY] ID 0x57b4 QR:0 OPCODE:QUERY RD:1 AD:1
      Question: example.com IN A
      Additional: <Root> OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0x57b4 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: example.com IN A
      Answer: example.com 26 IN A 104.18.27.120
      Answer: example.com 26 IN A 104.18.26.120
      Additional: <Root> OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [QUERY] ID 0xbdd4 QR:0 OPCODE:QUERY RD:1 AD:1
      Question: example.com IN AAAA
      Additional: <Root> OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0xbdd4 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: example.com IN AAAA
      Answer: example.com 286 IN AAAA 2606:4700::6812:1b78
      Answer: example.com 286 IN AAAA 2606:4700::6812:1a78
      Additional: <Root> OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    ^C
    [+] PID:0 shutting down: got signal 2 (Interrupt) from UID:0 PID:0 
    [1]+  Done ( sleep 1; dig @8.8.8.8 example.com A example.com AAAA +short > /dev/null )


### 1.2 **Readpcap mode**
Reads DNS message from packet capture flle, decodes and prints them to stdout.

**Features**

- PCAP support: auto-detects and reads both legacy `pcap` and `pcapng` files
- RFC 1035 compliant: can decode and validate any DNS message

**Design**

- PCAP api to read packets
- DNS api to decode and validate DNS message

**Example usage**

    $ dns-inspect readpcap --file tests/pcaps/dns.pcap
    [QUERY] ID 0x57b4 QR:0 OPCODE:QUERY RD:1 AD:1
      Question: example.com IN A
      Additional: <Root> OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0x57b4 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: example.com IN A
      Answer: example.com 26 IN A 104.18.27.120
      Answer: example.com 26 IN A 104.18.26.120
      Additional: <Root> OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [QUERY] ID 0xbdd4 QR:0 OPCODE:QUERY RD:1 AD:1
      Question: example.com IN AAAA
      Additional: <Root> OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0xbdd4 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: example.com IN AAAA
      Answer: example.com 286 IN AAAA 2606:4700::6812:1b78
      Answer: example.com 286 IN AAAA 2606:4700::6812:1a78
      Additional: <Root> OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0

### 1.2 **Tracepcap mode**
Reads records/blocks from a packet capture flle, and prints their metadata to stdout.

**Features**

- PCAP support: auto-detects and reads both legacy `pcap` and `pcapng` files
- Displays text version of pcap records or pcapng blocks

**Example usage**

    $ dns-inspect tracepcap --file tests/pcaps/dns.pcap
    [PCAP-HDR] magic=0xa1b2c3d4 major=2 minor=4 resv1=0 resv2=0 snap_len=65535 link_type=1
    [PCAP-REC] rec=1 ts_sec=1774957781 ts_usec=340673 inc_len=94 orig_len=94
    [PCAP-REC] rec=2 ts_sec=1774957781 ts_usec=367179 inc_len=114 orig_len=114
    [PCAP-REC] rec=3 ts_sec=1774957781 ts_usec=367537 inc_len=94 orig_len=94
    [PCAP-REC] rec=4 ts_sec=1774957781 ts_usec=396184 inc_len=138 orig_len=138

    $ dns-inspect tracepcap --file tests/pcaps/dns.pcapng 
    [PCAPNG] blk=1 name=SHB type=0x0a0d0d0a tot_len=28 magic=0x1a2b3c4d ver_major=1 ver_minor=0 sec_len=-1
    [PCAPNG] blk=2 name=IDB type=0x00000001 tot_len=20 link_type=1 rsvd=0 snap_len=65535
    [PCAPNG] blk=3 name=EPB type=0x00000006 tot_len=128 if_id=0 ts_high=413264 ts_low=3195997049 inc_len=94 orig_len=94
    [PCAPNG] blk=4 name=EPB type=0x00000006 tot_len=148 if_id=0 ts_high=413264 ts_low=3196034893 inc_len=114 orig_len=114
    [PCAPNG] blk=5 name=EPB type=0x00000006 tot_len=128 if_id=0 ts_high=413264 ts_low=3196035241 inc_len=94 orig_len=94
    [PCAPNG] blk=6 name=EPB type=0x00000006 tot_len=172 if_id=0 ts_high=413264 ts_low=3196068454 inc_len=138 orig_len=138

## 2. dns-gen
A DNS message and DNS pcap file generator tool.

**Usage**

    $ dns-gen --help
    Usage: dns-gen [MODE] [OPTIONS]

    Modes:
     
      query Send DNS query to a server
      resp  Generate a DNS response
      fuzz  Send fuzzed DNS message to server or pcap

    query options:

      --name    <NAME> domain name to lookup
      --type    <A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV> query type
      --class   <IN|CS|CH|HS|ANY> query class
      --flags   <AD|CD|RD> list of query flags e.g AD:0|RD:1
      --server  <ADDR> Server IP address
      --timeout <TimeOut> Response timeout in ms
      --tcp     Use TCP to send msg (instead of UDP)
      --log     Log DNS message that are sent

    resp options:

      --id         <ID> A DNS header id
      --name       <NAME> A DNS name
      --flags      <FLAGS> Query flags name:value name=AD|CD|RD and val=0|1
      --answer     <ANS>  answer record
      --authority  <AUTH> auth record
      --additional <ADD>  add record
      --output     <FILE> pcap file name
      --pcapng     Use pcapng file fmt

    fuzz options:

      --type   <hdr-trunc|hdr-opcode|hdr-rcode|hdr-qdcnt|qd-cmploop|qd-badjmp> fuzz type
      --id     <ID> A DNS header id
      --server <ADDR> Server address to send pdu to
      --output <FILE> pcap file name
      --pcapng Use pcapng file fmt

    Examples:

      dns-gen query --name example.com --type A --server 8.8.8.8
      dns-gen query --name example.com --type A --server 8.8.8.8 --flags 'AD:0|CD:0|RD:1'
      dns-gen query --name example.com --type MX --server 8.8.8.8 --tcp
      dns-gen resp --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin
      dns-gen fuzz --type qd-cmploop --server 127.0.0.1
      dns-gen fuzz --type qd-badjmp --output f.pcapng --pcapng


### 2.1 **Query mode**
Sends a DNS query to a DNS server

**Features**

- Multiple query option supported
- Both UDP and TCP connections supported
- Timeouts for send/receive messages
- Measures query response time

**Design**

- Uses blocking sockets for simple send|recv state
- Uses clock_gettime() for timestamps
- DNS API to encode|decode query|resp
- LOG API to catch and logs them to stderr

**Example usage**

    $ dns-gen query --name example.com --type A --server 8.8.8.8
    Send query (UDP) ID:0xb45e for example.com IN A
    Received response in 29ms: example.com IN A 104.20.23.154

### 2.1 **Response mode**
Generates DNS response messages and save them to packet capture file.

**Features**

- Uses cmd line opts to control message generation
- Supports multiple sections (AN|NS|AR) and record types
- Supports both PCAP and PCAPNG file formats

**Design**

- UTIL API : to gather cmd-line options
- DNS API  : build and encode a DNS message
- PCAP API : to generate pcap file

**Example usage**

    $ dns-gen resp --id 0x1234 --name test.local --answer 192.168.1.1 --answer 172.168.0.10 --authority example.com --output f.pcapng --pcapng
    Wrote 79 bytes to f.pcapng

    $ dns-inspect readpcap --file f.pcapng 
    [RESPONSE] ID 0x1234 QR:1 OPCODE:QUERY RCODE:NoError
      Answer: test.local 0 IN A 192.168.1.1
      Answer: test.local 0 IN A 172.168.0.10
      Authority: test.local 0 IN CNAME example.com

### 2.1 **Fuzz mode**
Generates invalid DNS query messages for sending to a server or pcap file.

**Features**

- Uses cmd-line options to control message generation
- Writes DNS messages to a pcap file
- Supports both PCAP and PCAPNG file formats

**Example usage**

    $ dns-gen fuzz --type qd-cmploop --server 8.8.8.8
    [+] Response ID 0x53cf failed with error FormErr

    $ dns-gen fuzz --type qd-badjmp --id 0x1234 --output a.pcap
    Wrote 18 bytes to a.pcap

    $ dns-inspect readpcap --file a.pcap
    [QUERY] ID 0x1234 QR:0 OPCODE:QUERY 
    [ERROR] ID 0x1234 / Question Name Invalid compression pointer (outside range)

    $ tshark -r a.pcap 
    1  0.000000 0.000000  0.0.0.0 → 0.0.0.0  53 53 DNS 60 Standard query 0x1234[Malformed Packet] 

