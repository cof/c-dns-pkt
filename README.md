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
- **make setcap** : make setpcap - add non-root sniffer capabilities to dns-inspect
- **make install** : install to /usr/local/bin (default) (caps enabled)
- **make clean**: Removes all compiled binaries, object files and test logs
- **make debug**: Comple all code with debug flags

## Design Notes

- Both tools are single-threaded written in C with no 3rd party libs
- Both dns-inspect and dns-gen use custom apis
- DNS api  - DNS message encode/decode in dns_proto.(h|c)
- PCAP api - PCAP/PCAPNG read/write support in pcap.(h|c)
- LOG api  - info and error logging in log(.h|.c)
- UTIL api - strings,cmd-line parsing,signal handling

## 1. dns-inspect
A DNS packet inspector that capture DNS messages from a local interface and displays them.

**Supported Usage**

	$ ./dns-inspect --help
	Usage: dns-inspect [MODE] [OPTIONS]

	MODE:
	  capture         capture DNS msgs from an interface
	  readpcap        Read a packet capture file
	  tracepcap       trace a packet capture file

	capture Options:
	  --interface     Name of interface to sniff DNS msgs
	  --file          Name of packet capture file
	  --pcapng        Use pcapng file fmt

	readpcap Options:
	  --file          Name of packet capture file

	tracepcap Options:
	  --file          Name of packet capture file

	Examples:
	  dns-inspect capture --interface eth0
	  dns-inspect capture --interface eth0 --file dns.pcap
	  dns-inspect capture --interface eth0 --file dns.pcapng --pcapng
	  dns-inspect readpcap --file dns.pcap
	  dns-inspect tracepcap --file dns.pcap



### 1.1 **Command: capture**
Captures, decodes, and prints DNS traffic from a local network interface in real-time.

**Supported featues**

- Can attach to any interface and decode DNS traffic
- Can save DNS traffic to pcap file
- Can decode any DNS message - rfc1035 compliant
- Native read/write for both Legacy Pcap and PcapNG formats.
- Can be used with non-root sniffer capabilities

**Design**

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

	$ make
	$ sudo make install
	install -D -m 755 dns-inspect /usr/local/bin/dns-inspect
	install -D -m 755 dns-gen /usr/local/bin/dns-gen
	sudo setcap 'cap_net_raw,cap_net_admin=eip' /usr/local/bin/dns-inspect || true
	$ (sleep 1; dig @8.8.8.8 example.com A example.com AAAA +short >/dev/null) & dns-inspect capture --interface wlp2s0 --file dns.pcap  
	[1] 97975
	[dns-sniff] DNS active on wlp2s0
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
	[dns-sniff] PID:0 shutting down: got signal 2 (Interrupt) from UID:0 PID:0 
	[1]+  Done ( sleep 1; dig @8.8.8.8 example.com A example.com AAAA +short > /dev/null )


### 1.2 **Command: readpcap**
Reads DNS message from packet capture flle, decodes and prints them to stdout.

**Supported featues**

- Can read both legacy pcap and pcapng files
- Can detect if file fmt is either pcap or pcapng
- Displays text version of decoded message to stdout

**Design**

- Uses PCAP api to read packets
- Uses DNS api tor decode and validate DNS message

**Example usage**

	$ ./dns-inspect readpcap --file tests/pcaps/dns.pcap
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

### 1.2 **Command: tracepcap**
Reads records from a packet capture flle, and prints their metadata to stdout.

**Supported features**

- Can read both legacy pcap and pcapng files
- Can detect if file fmt is either pcap or pcapng
- Displays text version of pcap records

**Example usage**

    $ ./dns-inspect tracepcap --file tests/pcaps/dns.pcap
    [PCAP-HDR] magic=0xa1b2c3d4 major=2 minor=4 resv1=0 resv2=0 snap_len=65535 link_type=1
    [PCAP-REC] rec=1 ts_sec=1774957781 ts_usec=340673 inc_len=94 orig_len=94
    [PCAP-REC] rec=2 ts_sec=1774957781 ts_usec=367179 inc_len=114 orig_len=114
    [PCAP-REC] rec=3 ts_sec=1774957781 ts_usec=367537 inc_len=94 orig_len=94
    [PCAP-REC] rec=4 ts_sec=1774957781 ts_usec=396184 inc_len=138 orig_len=138

    $ ./dns-inspect tracepcap --file tests/pcaps/dns.pcapng 
    [PCAPNG] blk=1 name=SHB type=0x0a0d0d0a tot_len=28 magic=0x1a2b3c4d ver_major=1 ver_minor=0 sec_len=-1
    [PCAPNG] blk=2 name=IDB type=0x00000001 tot_len=20 link_type=1 rsvd=0 snap_len=65535
    [PCAPNG] blk=3 name=EPB type=0x00000006 tot_len=128 if_id=0 ts_high=413264 ts_low=3195997049 inc_len=94 orig_len=94
    [PCAPNG] blk=4 name=EPB type=0x00000006 tot_len=148 if_id=0 ts_high=413264 ts_low=3196034893 inc_len=114 orig_len=114
    [PCAPNG] blk=5 name=EPB type=0x00000006 tot_len=128 if_id=0 ts_high=413264 ts_low=3196035241 inc_len=94 orig_len=94
    [PCAPNG] blk=6 name=EPB type=0x00000006 tot_len=172 if_id=0 ts_high=413264 ts_low=3196068454 inc_len=138 orig_len=138

## 2. dns-gen
A DNS message and DNS packet file generator tool.

**Supported Usage**

	./dns-gen 
	Usage: dns-gen [MODE] [OPTIONS]

	MODE:
	  query           Send DNS query to a server
	  resp            Generate a DNS response
	  fuzz            Send fuzzed DNS message to server or pcap

	query Options:
	  --name          <NAME> A DNS name
	  --type          <TYPE> A DNS type A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV
	  --class         <CLASS> A DNS class IN|CS|CH|HS|ANY
	  --flags         <FLAGS> Query flags AD:0|CD:0|RD:0
	  --server        <ADDR> Server IP address or name
	  --timeout       <TimeOut> Response timeout in ms
	  --tcp           Use TCP to send msg (instead of UDP)
	  --log           Log DNS message that are sent

	resp Options:
	  --id            <ID> A DNS header id
	  --name          <NAME> A DNS name
	  --flags         <FLAGS> Query flags name:value name=AD|CD|RD and val=0|1
	  --answer        <ANS>  answer record
	  --authority     <AUTH> auth record
	  --additional    <ADD>  add record
	  --output        <FILE> pcap file name
	  --pcapng        Use pcapng file fmt

	fuzz Options:
	  --type          <FUZZ> type must be hdr-trunc|hdr-opcode|hdr-rcode|hdr-qdcnt|qd-cmploop|qd-badjmp
	  --id            <ID> A DNS header id
	  --server        <ADDR> Server address to send pdu to
	  --output        <FILE> pcap file name
	  --pcapng        Use pcapng file fmt

	Examples:
	  dns-gen query --name example.com --type A --server 8.8.8.8
	  dns-gen query --name example.com --type A --server 8.8.8.8 --flags 'AD:1|CD:1|RD:0'
	  dns-gen query --name example.com --type MX --server 8.8.8.8 --tcp
	  dns-gen resp --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin
	  dns-gen fuzz --type qd-cmploop --server 127.0.0.1
	  dns-gen fuzz --type qd-badjmp --output f.pcapng --pcapng

### 2.1 **Command: query**
Sends a DNS query message to a server

**Supported featues**

- Can send a DNS query message to a server
- Supports multiple query options
- Can validate message before they are sent
- Supports both UDP and TCP
- Supports timeouts for send/receive messages

**Design**

- Uses blocking sockets for simple send|recv state
- Uses clock_gettime() for timestamps
- Uses DNS api to encode|decode query|resp
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

- Uses cmd-line options to control message generation
- Writes DNS messages to a pcap file
- Supports both PCAP and PCAPNG file formats

**Example usage**

    $ ./dns-gen fuzz --type qd-badjmp --id 0x1234 --output a.pcap
    Wrote 18 bytes to a.pcap
	$ ./dns-inspect readpcap --file a.pcap
	[QUERY] ID 0x1234 QR:0 OPCODE:QUERY 
	[ERROR] ID 0x1234 / Question Name Invalid compression pointer (outside range)
