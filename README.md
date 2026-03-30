# DNS Packet
A DNS packet inspector and DNS message generator.

- **dns-inspect**  a DNS packet inspector
- **dns-gen**      A DNS message generator

## Prerequisites

- **GCC**: Version 9.0 or higher.
- **make**: Version 4.0 or higher.
- **Bash**: Version 4.0+ for the test runner.

## Building the Project

- **make all** (Default): Compiles dns-inspect and dns-gen
- **make test** : Compiles and test dns-inspect and dns-gen
- **make clean**: Removes all compiled binaries, object files and test logs
- **make debug**: Comple all code with debug flags

## Design Notes

- Single-threaded applicaton written in C with no 3rd party libs
- Both dns-inspect and dns-gen use custom apis
- DNS api  - DNS message encode/decode in dns_proto.(h|c)
- PCAP api - PCAP/PCAPNG read/write support in pcap.(h|c)
- SOCK api - socket layer wrapper in sock.(h|c)
- LOG api  - info and error logging in log(.h|.c)
- UTIL api - strings,cmd-line parsing,signal handling

## 1. dns-inspect
A DNS packet inspector that capture DNS messages from a local interface and displays them.

**Supported Commands:**

- **capture**   Capture DNS traffic from a local interface and log them
- **readpcap**  Read DNS traffic from a packet capture and log them
- **tracepcap** Debug a packet capture file.

**Supported featues**

### 1.1 **Command: capture**
Captures, decodes, and prints DNS traffic from a local network interface in real-time.

**Supported featues**

- Can attach to any interface and decode DNS trafic
- Can decode any DNS message (rfc1035) compliant
- Can read packet capture files legacy/pcapng 

**Design**

- Single-threaded applicaton written in C with no 3rd party libs
- Uses signal API to catch SIGTERM and SIGINT
- Uses AF_PACKET raw socket to receive ethernet packets
- Uses BPF to only receive UDP packets for port 53
- Uses SO_RCVBUF to set receive buffer size
- Sets promisc mode on interface
- Uses recvmmsg to read a block of packets from socket
- Extracts the DNS message from the packet
- Uses validate_dns_packet to decode and describe DNS message
- Displays described version of DNS message to stdout
- Uses LOG api to catch all error and logs them to stderr

**Example usage**

    $ sudo ./dns-inspect capture --interface wlp2s0
    [dns-sniff] DNS active on wlp2s0
    [QUERY] ID 0x1d43 QR:0 OPCODE:QUERY RD:1 AD:1
      Question: example.com IN A
      Additional: <Root>  OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0x1d43 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: example.com IN A
      Answer: example.com IN A 104.18.26.120
      Answer: example.com IN A 104.18.27.120
      Additional: <Root>  OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0

### 1.2 **Command: readpcap**
Reads a packet capture flle, decodes and prints DNS trafic

**Supported featues**

- Can read both legacy pcap and pcapng files
- Can detect if a file is pcap or pcapng:
- Displays text version of decoded message to stdout

**Design**

- Uses PCAP api to read packets
- Uses DNS api tor decode and validate DNS message

**Example usage**

    $ ./dns-inspect readpcap --file tests/pcaps/dns.pcap 
    [QUERY] ID 0xecc2 QR:0 OPCODE:QUERY RD:1 AD:1
      Question: www.google.com IN A
      Additional: <Root>  OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0xecc2 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: www.google.com IN A
      Answer: www.google.com IN A 74.125.193.147
      Answer: www.google.com IN A 74.125.193.99
      Answer: www.google.com IN A 74.125.193.103
      Answer: www.google.com IN A 74.125.193.106
      Answer: www.google.com IN A 74.125.193.104
      Answer: www.google.com IN A 74.125.193.105
      Additional: <Root>  OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0

### 1.2 **Command: tracepcap**
Reads packet records from a capture flle, and prints them

**Supported features**

- Can read both legacy pcap and pcapng files
- Can detect if a file is pcap or pcapng
- Displays text version of pcap records

**Example usage**

    $ ./dns-inspect tracepcap --file tests/pcaps/dns.pcap
    [PCAP-HDR] magic=0xa1b2c3d4 major=2 minor=4 resv1=0 resv2=0 snap_len=262144 link_type=1
    [PCAP-REC] rec=1 ts_sec=1772736506 ts_usec=633805 inc_len=97 orig_len=97
    [PCAP-REC] rec=2 ts_sec=1772736506 ts_usec=653222 inc_len=181 orig_len=181

    $ ./dns-inspect tracepcap --file tests/pcaps/dns.pcapng 
    [PCAPNG] blk=1 name=SHB type=0x0a0d0d0a total_len=28 magic=0x1a2b3c4d ver_major=1 ver_minor=0 sec_len=-1
    [PCAPNG] blk=2 name=IDB type=0x00000001 total_len=20 link_type=1 rsvd=0 snap_len=262144
    [PCAPNG] blk=3 name=EPB type=0x00000006 total_len=132 if_id=0 ts_high=412747 ts_low=1640111693 inc_len=97 orig_len=97
    [PCAPNG] blk=4 name=EPB type=0x00000006 total_len=216 if_id=0 ts_high=412747 ts_low=1640131110 inc_len=181 orig_len=181


## 2. dns-gen
A DNS message and DNS packet file generator tool.

**Example usage**

    Usage: dns-gen [MODE] [OPTIONS]

    MODE:
      query      send DNS query message to a server
      response   create a dns mesage with bad values
      fuzz       create a dns reponse message

    query Options:
      --name       <NAME> A DNS name
      --type       <TYPE> A DNS type A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV
      --class      <CLASS> A DNS class IN|CS|CH|HS|ANY
      --flags      <FLAGS> Query flags AD:0|CD:0|RD:0
      --server     <ADDR> Server IP address or name
      --timeout    <TimeOut> Response timeout
      --tcp        Use TCP to send msg (instead of UDP)
      --log        Log DNS message that are sent

    response Options:
      --id         <ID> A DNS header id
      --name       <NAME> A DNS name
      --flags      <FLAGS> Query flags name:value name=AD|CD|RD and val=0|1
      --answer     <ANS>  answer record
      --authority  <AUTH> auth record
      --additional <ADD>  add record
      --output     <FILE> pcap file name
      --pcapng     Use pcapng file fmt

    fuzz Options:
      --type       <FUZZ> type must be hdr-trunc|hdr-opcode|hdr-rcode|hdr-qdcnt|qd-cmploop|qd-badjmp
      --server     <ADDR> Server address to send pdu to
      --output     <FILE> pcap file name
      --pcapng     Use pcapng file fmt

    Examples:
      dns-gen query --name example.com --type A --server 8.8.8.8
      dns-gen query --name example.com --type A --server 8.8.8.8 --flags 'AD:1|CD:1|RD:0'
      dns-gen query --name example.com --type MX --server 8.8.8.8 --tcp
      dns-gen fuzz --type qd-cmploop --server 127.0.0.1
      dns-gen fuzz --type qd-badjmp --output f.pcapng --pcapng
      dns-gen response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin


### 2.1 **Command: query**
Sends a DNS query message to a server

**Supported featues**

- Can send a DNS query message to a server
- Supports multiple query options
- Can validate message before they are sent
- Supports both UDP and TCP
- Supports timeouts for send/receive messages

**Design**

- Uses SOCK api to create UDP|TCP connections to DNS server
- Uses SOCK api to set send|recv timeouts
- Uses blocking sockets for simple send|recv state
- Uses clock_gettime() for timestamps
- Uses DNS api to encode|decode query|resp
- Uses SOCK api to send|recv DNS pdu's
- Uses LOG api to catch and logs them to stderr

**Example usage**

    $ ./dns-gen query --name example.com --type A --server 8.8.8.8
    Connected to 8.8.8.8
    Send query (UDP) ID:0x6d6a for example.com IN A
    Received response in 28ms: 
      example.com IN A                
      example.com IN A                

### 2.1 **Command: response**
Generates DNS messages and save them to packet capture file.

**Supported featues**

- Uses cmd line opts to control message generation
- Supports multiple sections (AN|NS|AR) and record types
- Writes DNS messages to a pcap file
- Supports both PCAP and PCAPNG file formats

**Design**

- Uses UTIL api to gather cmd-line options
- Uses DNS api to build and encode a DNS message
- Uses PCAP api to generate pcap file

**Example usage**

    $ ./dns-gen response --id 0x1234 --name test.local --answer 192.168.1.1 --answer 172.168.0.10 --authority example.com --output f.pcapng --pcapng
    Wrote 79 bytes to f.pcapng

    $ ./dns-inspect readpcap --file f.pcapng 
    [QUERY] ID 0x1234 QR:0 OPCODE:QUERY 
      Answer: test.local IN A 192.168.1.1
      Answer: test.local IN A 172.168.0.10
      Authority: test.local IN CNAME example.com

### 2.1 **Command: fuzz**
Generates invalid DNS messages for sending to a server or pcap file.

**Supported featues**

- Uses cmd line opts to control message generation
- Writes DNS messages to a pcap file
- Supports both PCAP and PCAPNG file formats

**Example usage**

    $ ./dns-gen fuzz --type qd-badjmp --id 0x1234 --output a.pcap
    Wrote 18 bytes to a.pcap
	$ ./dns-inspect readpcap --file a.pcap
	[QUERY] ID 0x1234 QR:0 OPCODE:QUERY 
	[ERROR] ID 0x1234 / Question Name Invalid compression pointer (outside range)
