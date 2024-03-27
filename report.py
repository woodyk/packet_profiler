#!/usr/bin/env python3
#
# report.py

import json
import sys
import getopt
import pyshark

def init_fields():
    return {
        "packets": {"Total": 0},
        "ip_src_dst_dist": {},
        "ip_version_dist": {},
        "ip_header_length_dist": {},
        "ip_ttl_dist": {},
        "ip_fragment_offset_dist": {},
        "ip_checksum_dist": {},
        "ip_flags_dist": {},
        "ip_protocol_dist": {},
        "tcp_src_dst_port_dist": {},
        "tcp_seq_num_dist": {},
        "tcp_ack_num_dist": {},
        "tcp_window_size_dist": {},
        "tcp_checksum_dist": {},
        "tcp_flags_dist": {},
        "udp_src_dst_port_dist": {},
        "udp_length_dist": {},
        "udp_checksum_dist": {},
        "icmp_type_dist": {},
        "icmp_code_dist": {},
        "icmp_checksum_dist": {},
    }

def add_one(fields, key, value):
    if key not in fields:
        fields[key] = {}

    if value not in fields[key]:
        fields[key][value] = 0

    fields[key][value] += 1

def parse_packet(packet, fields):
    fields["packets"]["Total"] += 1

    transport_layer = packet.transport_layer

    if "ip" in packet:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        ip_version = packet.ip.version
        ip_header_length = packet.ip.ihl * 4
        ip_ttl = packet.ip.ttl
        ip_fragment_offset = packet.ip.frag_offset

        if ip_fragment_offset:
            add_one(fields["ip_fragment_offset_dist"], ip_fragment_offset, 1)

        add_one(fields["ip_src_dst_dist"], ip_src, 1)
        add_one(fields["ip_src_dst_dist"], ip_dst, 1)
        add_one(fields["ip_version_dist"], ip_version, 1)
        add_one(fields["ip_header_length_dist"], ip_header_length, 1)
        add_one(fields["ip_ttl_dist"], ip_ttl, 1)

        if "tcp" in packet:
            tcp_src_port = packet.tcp.srcport
            tcp_dst_port = packet.tcp.dstport
            tcp_seq_num = packet.tcp.seq
            tcp_ack_num = packet.tcp.ack
            tcp_window_size = packet.tcp.window_size
            tcp_checksum = packet.tcp.checksum
            tcp_flags = packet.tcp.flags

            add_one(fields["tcp_seq_num_dist"], tcp_seq_num, 1)
            add_one(fields["tcp_ack_num_dist"], tcp_ack_num, 1)
            add_one(fields["tcp_window_size_dist"], tcp_window_size, 1)
            add_one(fields["tcp_checksum_dist"], tcp_checksum, 1)
            add_one(fields["tcp_flags_dist"], tcp_flags, 1)

            add_one(fields["tcp_src_dst_port_dist"], tcp_src_port, 1)
            add_one(fields["tcp_src_dst_port_dist"], tcp_dst_port, 1)

        elif "udp" in packet:
            udp_src_port = packet.udp.srcport
            udp_dst_port = packet.udp.dstport
            udp_length = packet.udp.length
            udp_checksum = packet.udp.checksum

            add_one(fields["udp_src_dst_port_dist"], udp_src_port, 1)
            add_one(fields["udp_src_dst_port_dist"], udp_dst_port, 1)
            add_one(fields["udp_length_dist"], udp_length, 1)
            add_one(fields["udp_checksum_dist"], udp_checksum, 1)

    elif "icmp" in packet:
        icmp_type = packet.icmp.type
        icmp_code = packet.icmp.code
        icmp_checksum = packet.icmp.checksum

        add_one(fields["icmp_type_dist"], icmp_type, 1)
        add_one(fields["icmp_code_dist"], icmp_code, 1)
        add_one(fields["icmp_checksum_dist"], icmp_checksum, 1)

def detect_anomalies(fields):
    anomalies = []

    # Check for major known anomalies
    if "ip" in fields:
        ip_ver
