/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*
  Headers设置
*/
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> IHL;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header dns_t {
    bit<16> transactionID;
    bit<16> flags;
    bit<16> questions;
    bit<16> answers;
    bit<16> authorityRRs;
    bit<16> additionalRRs;
    bit<16> query;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    dns_t dns;
}

/*
  MyParser阶段
*/
parser MyParser(packet_in packet, out headers_t hdr) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        /* 
            如果 UDP 数据包中的端口是 DNS 服务的端口（一般为 53），
            则进入解析 DNS 头部的状态
        */
        transition select(hdr.udp.dstPort) {
            DNS_PORT: parse_dns;
            default: accept;
        }
    }

    state parse_dns {
        packet.extract(hdr.dns);
        transition accept;
    }
}



/*
 MyIngress阶段
*/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action forward_query() {
        /*执行 DNS 查询的操作动作 */
    }

    action forward_response() {
        /* 执行 DNS 响应的操作动作 */
    }

    table dns_packet_classification {
        key = {
            hdr.dns.flags; /* 假设 DNS 查询标志位为 hdr.dns.flags */
        }
        actions = {
            forward_query;
            forward_response;
            drop; /* drop或者是NoAction */
        }
        size = 1024;
        default_action = drop(); /* 默认情况下丢弃数据包 */   
    }

    apply {
        if (hdr.dns.isValid()) {
            dns_packet_classification.apply();
        }
    }
}

/*
 MyEgress阶段
*/ 

/*
    Deparser阶段
*/


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
