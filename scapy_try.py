#!/usr/bin/env python3
#
# tt.py

import argparse
import json
import logging
import os
import re
import socket
import struct
import time
from datetime import datetime
from uuid import uuid4
from scapy.all import *

def main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--count", type=int, help="Number of packets to process")
    parser.add_argument("--bytes", type=int, help="Number of bytes to collect from the payload")
    parser.add_argument("--debug", action="store_true", help="Output debug information to STDOUT")
    parser.add_argument("--geoip", action="store_true", help="Enable geoip collection")
    parser.add_argument("-i", "--interface", help="Network interface to listen to")
    parser.add_argument("--json", action="store_true", help="Output JSON array to STDOUT")
    parser.add_argument("--l7", action="store_true", help="Enable layer 7 data collection")
    parser.add_argument("-p", "--pcap", help="Pcap file for reading")
    parser.add_argument("-r", "--reverse-dns", action="store_true", help="Enable reverse DNS lookup. (much slower)")
    parser.add_argument("-t", "--tag", help="Label name for your datasource")
    args = parser.parse_args()

    # Initialize required structures
    packets = []

    def process_packet(packet):
        nonlocal packets

        timestamp = int(time.time())

        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        ethertype = packet[Ether].type

        if ethertype == 2054:  # ARP
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst

        elif ethertype == 2048:  # IP
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                sequence = packet[TCP].seq
                acknowledgment = packet[TCP].ack

                payload = packet[TCP].payload

                if args.l7:
                    if TCP in packet:
                        if packet[TCP].payload:
                            if packet[TCP].payload.haslayer(Raw):
                                decoded_payload = packet[TCP].payload.getlayer(Raw).load.decode("utf-8", "ignore")
                                split_payload = decoded_payload.split('\r\n\r\n', 1)
                                if len(split_payload) > 1:
                                    headers = split_payload[0]
                                    body = split_payload[1]
                                    headers_dict = dict(x.split(': ') for x in headers.split('\r\n') if ':' in x)
                                    request_url = headers_dict['host'] + headers_dict['path']
                                    packets.append(
                                        {
                                            "timestamp": timestamp,
                                            "source_mac": src_mac,
                                            "destination_mac": dst_mac,
                                            "ethertype": ethertype,
                                            "protocol": packet[IP].proto,
                                            "src_ip": src_ip,
                                            "dst_ip": dst_ip,
                                            "src_port": src_port,
                                            "dst_port": dst_port,
                                            "payload": body,
                                            "request_url": request_url,
                                        }
                                    )

            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload = packet[UDP].payload

        packets.append(
            {
                "timestamp": timestamp,
                "source_mac": src_mac,
                "destination_mac": dst_mac,
                "ethertype": ethertype,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": payload,
            }
        )

    # Start capturing packets based on the specified method
    if args.interface:
        try:
            conf.iface = args.interface

            while True:
                packet = sniff(count=args.count)
                for p in packet:
                    process_packet(p)
        except KeyboardInterrupt:
            pass

    elif args.pcap:
        pcap_reader = rdpcap(args.pcap)
        for p in pcap_reader:
            process_packet(p)

    # Post-processing and output
    if args.json:
        print(json.dumps(packets))


if __name__ == "__main__":
    main()
