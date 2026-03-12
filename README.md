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
- **make test** : Compiles dns-inspect and dns-gen
- **make clean**: Removes all compiled binaries, object files and test logs

## Design Notes

- DNS message encode/decode logic in dns_proto.c and API exposed in dns_proto.h
- PCAP record read/write logic in pcap.c and API exposed in pcap.
- String processing, cmd-line parsing and logging in util.c and API exposed in util.h
- Both dns-inspect and dns-gen use UTIL api for strings,cmd-lines and error logging.
- Both dns-inspect and dns-gen use DNS api to read/write DNS messages
- Both dns-inspect and dns-gen use PCAP api to read/write pcap files.

## 1. dns-inspect
A DNS packet inspector that capture DNS messages from a local interface and displays them.

**Supported Commands:**

- **capture**  Send a DNS query to server
- **readpcap**  Generate a DNS response message to pcap file:
- **tracepcap** Create a malformed DNS message

**Supported featues**

### 1.1 **Command: capture**
Captures, decodes, and prints DNS traffic from a local network interface in real-time.

**Supported featues**

- Can attach to any interface and decode DNS trafic
- Can decode any DNS message (rfc1035) compliant
- Can read packet capture files legacy/pcapng 

**Design**

- Uses signal to catch SIGTERM and SIGINT
- Uses AF_PACKET raw socket to receive ethernet packets
- Uses BPF to only receive UDP packets for port 53
- Uses SO_RCVBUF to set receive buffer size
- Sets promisc mode on interface
- Uses recvmmsg to read a block of ethrnet packets
- Extracts the DNS message from the packet
- Uses validate_dns_packet to decode DNS message
- Displays text version of decoded message to stdout
- Captures all error and logs them to stderr

**Example usage**

    $ sudo ./dns-inspect capture --interface wlp2s0
    [dns-sniff] DNS active on wlp2s0
    [QUERY] ID 0x1e0e QR:0 OPCODE:QUERY RD:1 AD:1
      Question: example.com IN A
      Additional: <Root> 1232 OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0x1e0e QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: example.com IN A
      Answer: ex104.18.26.120 IN A 104.18.26.120
      Answer: ex104.18.27.120 IN A 104.18.27.120
      Additional: <Root> 512 OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0



### 1.2 **Command: readpcap**
Reads a packet capture flle, decodes and prints DNS trafic

**Supported featues**

- Can read both legacy pcap and pcapng files
- Can detect if a file is pcap or pcapng:
- Uses validate_dns_packet to decode message
- Displays text version of decoded message to stdout

**Design**

- Uses pcap api to open a pcap file and read packets
- Uses validate_dns_packet to decode message
- Displays text version of decoded message to stdout

**Example usage**

    $ ./dns-inspect readpcap --file dns.pcap
    [QUERY] ID 0xecc2 QR:0 OPCODE:QUERY RD:1 AD:1
     Question: www.google.com IN A
      Additional: <Root> 1232 OPT UDP-size:1232 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0
    [RESPONSE] ID 0xecc2 QR:1 OPCODE:QUERY RD:1 RA:1 RCODE:NoError
      Question: www.google.com IN A
      Answer: ww74.125.193.147 IN A 74.125.193.147
      Answer: ww74.125.193.99 IN A 74.125.193.99
      Answer: ww74.125.193.103 IN A 74.125.193.103
      Answer: ww74.125.193.106 IN A 74.125.193.106
      Answer: ww74.125.193.104 IN A 74.125.193.104
      Answer: ww74.125.193.105 IN A 74.125.193.105
      Additional: <Root> 512 OPT UDP-size:512 Ext-RCODE:0 EDNS0:0 DNSEC-OK:0


### 1.2 **Command: tracepcap**
Reads packet records from a capture flle, and prints them

**Supported features**

- Can read both legacy pcap and pcapng files
- Can detect if a file is pcap or pcapng
- Displays text version of pcap records

**Example usage**

	$ ./dns-inspect tracepcap --file dns.pcap
	[PCAP-HDR] magic=0xa1b2c3d4 major=2 minor=4 resv1=0 resv2=0 snap_len=262144 link_type=1
	[PCAP-REC] rec=1 ts_sec=1772736506 ts_usec=633805 inc_len=97 orig_len=97
	[PCAP-REC] rec=2 ts_sec=1772736506 ts_usec=653222 inc_len=181 orig_len=181

	$ ./dns-inspect tracepcap --file dns.pcapng 
	[PCAPNG] blk=1 name=SHB type=0x0a0d0d0a total_len=28 magic=0x1a2b3c4d ver_major=1 ver_minor=0 sec_len=-1
	[PCAPNG] blk=2 name=IDB type=0x00000001 total_len=20 link_type=1 rsvd=0 snap_len=262144
	[PCAPNG] blk=3 name=EPB type=0x00000006 total_len=132 if_id=0 ts_high=412747 ts_low=1640111693 inc_len=97 orig_len=97
	[PCAPNG] blk=4 name=EPB type=0x00000006 total_len=216 if_id=0 ts_high=412747 ts_low=1640131110 inc_len=181 orig_len=181


## 2. dns-gen
A DNS message and DNS packet file generator tool.

**Example usage**

    $ Usage: dns-gen [MODE] [OPTIONS]
    MODE:
    query      send DNS query message to a server
     fuzz      create a dns mesage with bad values
    response   create a dns reponse message

    query Options:
      --name    <NAME> A DNS name
      --type    <TYPE> A DNS type A|NS|CNAME|SOA|PTR|HINFO|MX|TXT|AAAA|SRV
      --class   <CLASS> A DNS class IN|CS|CH|HS|ANY
      --flags   <FLAGS> Query flags AD:0|CD:0|RD:0
      --server  <ADDR> Server IP address or name
      --timeout <TIMEOUT> Response timeout
      --tcp      Use TCP to send msg (instead of UDP)
      --log      Log DNS message that are sent
    response Options:
      --id        <ID> A DNS header id
      --flags   <FLAGS> Query flags Query flags name:value name=AD|CD|RD and val=0|1
      --name      <NAME> A DNS name
      --answer    <ANS> answer record
      --authority <AUTH> answer record
      --additional <ADD> adrecord
      --output    <FILE> pcap file name
    fuzz Options:
      --type   <FUZZ> Fuzz type  hdr-trunc|hdr-opcode|hdr-rcode|hdr-qd|qd-cmploop|qd-badjmp
      --server  <ADDR> Server IP address or name
      --output  <FILE> pcap file name
    
    Examples:
      dns-gen query --name example.com --type A --server 8.8.8.8
      dns-gen query --name example.com --type A --server 8.8.8.8 --flags 'AD:1|CD:1|RD:0'
      dns-gen fuzz --type qd-cmploop --server 127.0.0.1
      dns-gen response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin

### 2.1 **Command: query**
Sends a DNS query message to a server

**Supported featues**

- Can send a DNS query message to a server
- Supports multiple query options
- Can validate message befor they are sent
- Supports both UDP and TCP
- Supports timeouts for send/receive messages

**Design**

- Uses getaddrinfo() to get a server address TCP/UDP 
- Uses setsockopt SO_SNDTIMEO to set a send timeout
- Uses setsockopt SO_RCVTIMEO to set a recv timeout
- Uses clock_gettime() for timestamps
- Uses socket/pdu wrapper code to track/log errors 
- Captures all error and logs them to stderr


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

**Design**

- Uses cmd line option to create a DNS message
- USes DNS api to encode a raw DNS message
- Uses pcap api to generate pcap file

**Example usage**

	$ ./dns-gen response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.pcap
	Wrote 38 bytes to packet.pcap

