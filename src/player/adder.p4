
/* -*- P4_16 -*- */
/*
 * Define the headers the program will recognize
 */
#include <core.p4>
#include <v1model.p4>
//const type
const bit<16>  TYPE_data   = 1234;
const bit<16>  TYPE_IPV4    = 0x0800;
const bit<16>  TYPE_ARP     = 0x0806;
const bit<8>   TYPE_TCP     = 0x06;
const bit<8>   TYPE_UDP     = 0x11;
/*
 * This is a custom protocol header for the calculator. We'll use
 * etherType 0x1234 for it (see parser)
 */

// the address of hosts
const bit<48> HOST_1_ADDR         = 0x080000000101;
const bit<48> HOST_2_ADDR         = 0x080000000102;
const bit<48> HOST_3_ADDR         = 0x080000000103;
const bit<48> HOST_4_ADDR         = 0x080000000104;
const bit<48> DST_MAC             = 0x080000000105;
const bit<32> HOST_1_IP           = 0x0a000101;
const bit<32> HOST_2_IP           = 0x0a000102;
const bit<32> HOST_3_IP           = 0x0a000103;
const bit<32> HOST_4_IP           = 0x0a000104;
const bit<32> DST_IP              = 0x0a000105;
const bit<9>  HOST_1_PORT         = 1;
const bit<9>  HOST_2_PORT         = 2;
const bit<9>  HOST_3_PORT         = 3;
const bit<9>  HOST_4_PORT         = 4;
const bit<9>  DST_PORT            = 5;

// buffer size
const bit<32> BUFFER_SIZE         = 0xfffff;

/*
        1               2               3               4
Ethernet header
+---------------+---------------+---------------+---------------+
|                         dst_addr<48>                          |
+---------------+---------------+---------------+---------------+
|                         src_addr<48>                          |
+---------------+---------------+---------------+---------------+
|           ether_type          |                               |
+---------------+---------------+---------------+---------------+   

IP header
+---------------+---------------+---------------+---------------+                               
|   version     |       ihl     |    diffserv   |   totalLen    |
+---------------+---------------+---------------+---------------+
|        identification         | flags<3>|      fragOffset<13> |
+---------------+---------------+---------------+---------------+
|       ttl     |   protocol    |           hdrChecksum         |
+---------------+---------------+---------------+---------------+
|                            srcAddr                            |
+---------------+---------------+---------------+---------------+
|                            dstAddr                            |
+---------------+---------------+---------------+---------------+

UDP header
+---------------+---------------+---------------+---------------+   
|            Src_port           |            Dst_port           |
+---------------+---------------+---------------+---------------+
|             length            |            Chechsum           |
+---------------+---------------+---------------+---------------+


data header
+---------------------------------------------------------------+
|                              NUM                              |
+---------------------------------------------------------------+
*/
//UDP+IP+ETHENET header
/*
 * Standard Ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


header data_t {
    bit<32> num;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    data_t       data;
}
error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    bit<16> ipv4_totalLen;
    bit<16> tcp_length; // tcp header length using at checksum calculation
    bit<16> tot_length; // total length with data header 
    bit<1>  ack_valid;
    bit<1>  sack_valid;
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4     : parse_ipv4;
            default       : accept;
        }
    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        meta.ipv4_totalLen = hdr.ipv4.totalLen;
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP  : parse_udp;
            default   : accept;
        }
    }

    state parse_udp{
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.totalLen - 32) {
            0 : accept;
            default : parse_data;
        }
    }
    state parse_data {
        packet.extract(hdr.data);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
    }
    action multicast() {
        standard_metadata.mcast_grp = 1;
    }

    action modify_dst(){
        hdr.ipv4.dstAddr = 0x0a000103;
        hdr.udp.dstPort = 54321;
    }
    table ipv4_lookup {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        if(hdr.udp.isValid()){
            /*  Demonstration of packet modification

                Uncomment the following line to modify the packet destination
                Original Ip address is 0x0a000102 (host2)
                Original UDP port is 12345

                Then, 

                modify_dst action changes the destination IP address and UDP port
                Oirginal IP destination will be modify to host3's IP address 
                Which change 0x0a000102 to 0x0a000103 in header ipv4.dstAddr

                Original UDP destination port will be modify to 54321
                which modify hdr.udp.dstPort from 12345 to 54321
            */

            // modify_dst();
            

            /*  Your can pracitce for fun: 
                Try to modify the packet destination Host4 and UDP port to 44444
            */

        }
        if (hdr.ipv4.isValid()) {
            ipv4_lookup.apply();
        }
        else if (hdr.ethernet.isValid()) {
            if (hdr.ethernet.etherType == TYPE_ARP) {
                multicast();
            }
        }
        else {
            drop();
        }
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),  // condition: true if IPv4 header is valid
            {
                hdr.ipv4.version, 
                hdr.ipv4.ihl, 
                hdr.ipv4.diffserv, 
                hdr.ipv4.totalLen,
                hdr.ipv4.identification, 
                hdr.ipv4.flags, 
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, 
                hdr.ipv4.protocol, 
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,  // field to update with computed checksum
            HashAlgorithm.csum16  // checksum algorithm
        );
         update_checksum_with_payload(hdr.data.isValid(),{
            //tcp checksum is usually calculated with the following fields
            //pseudo header+tcp header+tcp payload
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,               //zero padding with protocol
            hdr.ipv4.protocol,
            hdr.udp.length,
            hdr.udp.srcPort,
            hdr.udp.dstPort,
            hdr.udp.length,
            hdr.data.num
        }, hdr.udp.checksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.data);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
