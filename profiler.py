#!/usr/bin/env python3
#
# profiler.py

#import matplotlib.pyplot as plt
#import numpy as np
import json
import sys
import getopt
import pyshark
import collections

dev = "en0"
pktCount = 1
fields = {}
fields["packets"] = 0

def help():
    print(__file__)
    print("\t-c\tNumber of packets to capture and process.")
    print("\t-d\tProfile a specific destination address.")
    print("\t-f\tPcap file you want to profile.")
    print("\t-h\tThis help output.")
    print("\t-i\tInterface name to listen to.")
    exit()

# Get options for execution
argv = sys.argv[1:]

try:
    opts, args = getopt.getopt(argv, "i:c:d:f:h:")

except:
    help()

if not opts:
    help()

for opt, arg in opts:
    if opt == '-i':
        dev = arg
    elif opt == '-c':
        pktCount = int(arg)
    elif opt == '-d':
        dstHost = arg
    elif opt == '-f':
        pcapFile = arg
    elif opt == '-h':
        help()

if 'dstHost' in locals():
    displayFilter = "ip.dst == " + dstHost
else:
    displayFilter = ""


def addOne(key, value):
    if key not in fields:
        fields[key] = {}

    if value in fields[key]:
        fields[key][value] +=1
    else:
        fields[key][value] = 1

if 'pcapFile' in locals():
    # file capture
    capture = pyshark.FileCapture(pcapFile, display_filter=displayFilter)
else:
    # live capture
    capture = pyshark.LiveCapture(interface=dev, display_filter=displayFilter)
    capture.sniff(packet_count=pktCount)

# Evaluate each packet
for p in capture:
    proto = "UNKNOWN"
    srcport = ""
    dstport = ""
    ipsrc = ""
    ipdst = ""

#    for i in dir(p):
#        print(i)
#
#    print(p.highest_layer)
#    print(p.transport_layer)
#    print(p.layers)

    # Determine layer 2 
    if 'arp' in p:
        proto = "ARP"
        ipsrc = p.arp.src_proto_ipv4
        ipdst = p.arp.dst_proto_ipv4

        addOne("ipSrcIpDist", p.arp.src_proto_ipv4)
        addOne("ipDstIpDist", p.arp.dst_proto_ipv4)

        #print(p.arp.field_names)

    # Deterimine layer 3 ipv4 vs ipv6
    if 'ip' in p:
        ipsrc = p.ip.src
        ipdst = p.ip.dst

        ipChecksum = int(p.ip.checksum, base=16)
        ipFlag = int(p.ip.flags, base=16)

        addOne("ipSrcIpDist", p.ip.src)
        addOne("ipDstIpDist", p.ip.dst)
        addOne("ipLenDist", p.ip.len)
        addOne("ipTtlDist", p.ip.ttl)
        addOne("ipVersionDist", p.ip.version)
        addOne("ipFlagsDist", ipFlag)
        addOne("ipChecksumDist", ipChecksum)

        #print(p.ip.field_names)

    if 'ipv6' in p:
        ipsrc = p.ipv6.src
        ipdst = p.ipv6.dst

        addOne("ipSrcIpDist", p.ipv6.src)
        addOne("ipDstIpDist", p.ipv6.dst)

        #print(p.ipv6.field_names)

    if 'icmpv6' in p:
        proto = "ICMPv6"
        icmpv6Checksum = int(p.icmpv6.checksum, base=16)

        addOne("icmpv6TypeDist", p.icmpv6.type)
        addOne("icmpv6CodeDist", p.icmpv6.code)
        addOne("icmpv6ChecksumDist", icmpv6Checksum)

        #print(p.icmpv6.field_names)
    
    if 'icmp' in p:
        proto = "ICMP"
        icmpChecksum = int(p.icmp.checksum, base=16)

        addOne("icmpTypeDist", p.icmp.type)
        addOne("icmpCodeDist", p.icmp.code)
        addOne("icmpChecksumDist", icmpChecksum)

        #print(p.icmp.field_names)

    if 'igmp' in p:
        proto = "IGMP"

        #print(p.igmp.field_names)

    # Determine layer 4 protocol
    if 'tcp' in p:
        proto = "TCP"
        tcpFlags = p.tcp.flags_str
        tcpFlags = tcpFlags.replace("\\xc2\\xb7", "")
        tcpFlags = tcpFlags.replace("·", "")
        tcpChecksum = int(p.tcp.checksum, base=16)

        addOne("tcpFlagDist", tcpFlags)
        addOne("tcpWinSizeDist", p.tcp.window_size)
        addOne("tcpSrcPortDist", p.tcp.srcport)
        addOne("tcpDestPortDist", p.tcp.dstport)
        addOne("tcpLengthDist", p.tcp.len)
        addOne("tcpChecksumDist", tcpChecksum)

        #print(p.tcp.field_names)

    if 'udp' in p:
        proto = "UDP"
        udpChecksum = int(p.udp.checksum, base=16)

        addOne("udpSrcPortDist", p.udp.srcport)
        addOne("udpDestPortDist", p.udp.dstport)
        addOne("udpLengthDist", p.udp.length)
        addOne("udpChecksumDist", udpChecksum)

        #print(p.udp.field_names)

    addOne("ipProtoDist", proto)
    fields["packets"] += 1

import json

def summarize_network_traffic(json_doc):
    data = json_doc

    if 'packets' in data:
        # Get basic statistics
        num_packets = data.pop("packets")
        print("\nSummary of Network Traffic:")
        print(f"Total Packets: {num_packets}\n")

    if 'icmpTypeDist' in data:
        # Process icmpTypeDist
        icmp_types = sorted(list(data['icmpTypeDist'].keys()))
        icmp_type_freq = sorted(list(data['icmpTypeDist'].values()))
        print("ICMP Types Distribution:")
        print("Types:", ", ".join([f"{typ} ({frq})" for typ, frq in zip(icmp_types, icmp_type_freq)]))

    if 'ipProtoDist' in data:
        # Process ipProtocolDist
        ip_protos = sorted(list(data['ipProtoDist'].keys()))
        ip_proto_freq = sorted(list(data['ipProtoDist'].values()))
        print("\nIP Protocol Distribution:")
        print("Protocols:", ", ".join([f"{prot} ({frq})" for prot, frq in zip(ip_protos, ip_proto_freq)]))

    if 'ipSrcIpDist' in data:
        # Process ipSourceIpDist
        ip_srcs = sorted(list(data['ipSrcIpDist'].keys()))
        ip_src_freq = sorted(list(data['ipSrcIpDist'].values()))
        print("\nIP Source IP Distribution:")
        print("Sources:", ", ".join([f"{src} ({frq})" for src, frq in zip(ip_srcs, ip_src_freq)]))

    if 'ipDstIpDist' in data:
        # Process ipDestinationIpDist
        ip_dests = sorted(list(data['ipDstIpDist'].keys()))
        ip_dest_freq = sorted(list(data['ipDstIpDist'].values()))
        print("\nIP Destination IP Distribution:")
        print("Destinations:", ", ".join([f"{dst} ({frq})" for dst, frq in zip(ip_dests, ip_dest_freq)]))

    if 'ipTtlDist' in data:
        # Process ipTimeToLiveDist
        ttls = sorted(list(data['ipTtlDist'].keys()))
        ttl_freq = sorted(list(data['ipTtlDist'].values()))
        print("\nIP Time To Live Distribution:")
        print("Values:", ", ".join([f"{val} ({frq})" for val, frq in zip(ttls, ttl_freq)]))

    if 'ipLenDist' in data:
        # Process ipLengthDist
        lengths = sorted(list(data['ipLenDist'].keys()))
        length_freq = sorted(list(data['ipLenDist'].values()))
        print("\nIP Packet Length Distribution:")
        print("Lengths:", ", ".join([f"{lengh} ({frq})" for lengh, frq in zip(lengths, length_freq)]))

    if 'unknown' in data:
        # Process ipIdentificationDist
        ids = sorted(list(data['ipIdentification'].keys()))
        id_freq = sorted(list(data['ipIdentification'].values()))
        print("\nIP Identification Distribution:")
        print("IDs:", ", ".join([f"{id} ({frq})" for id, frq in zip(ids, id_freq)]))

    if 'unknown' in data:
        # Process ipFragmentOffsetDist
        frag_offsets = sorted(list(data['ipFragmentOffset'].keys()))
        frag_offset_freq = sorted(list(data['ipFragmentOffset'].values()))
        print("\nIP Fragment Offset Distribution:")
        print("Offsets:", ", ".join([f"{frag_offset} ({frq})" for frag_offset, frq in zip(frag_offsets, frag_offset_freq)]))

    if 'tcpSrcPortDist' in data:
        # Process tcpSrcPortDist
        tcp_src_ports = sorted(list(data['tcpSrcPortDist'].keys()))
        tcp_src_port_freq = sorted(list(data['tcpSrcPortDist'].values()))
        print("\nTCP Source Port Distribution:")
        print("Ports:", ", ".join([f"{port} ({frq})" for port, frq in zip(tcp_src_ports, tcp_src_port_freq)]))

    if 'packets' in data:
        # Process tcpDestPortDist
        tcp_dest_ports = sorted(list(data['tcpDestPort'].keys()))
        tcp_dest_port_freq = sorted(list(data['tcpDestPort'].values()))
        print("\nTCP Destination Port Distribution:")
        print("Ports:", ", ".join([f"{port} ({frq})" for port, frq in zip(tcp_dest_ports, tcp_dest_port_freq)]))

    if 'packets' in data:
        # Process udpSrcPortDist
        udp_src_ports = sorted(list(data['udpSrcPort'].keys()))
        udp_src_port_freq = sorted(list(data['udpSrcPort'].values()))
        print("\nUDP Source Port Distribution:")
        print("Ports:", ", ".join([f"{port} ({frq})" for port, frq in zip(udp_src_ports, udp_src_port_freq)]))

    if 'packets' in data:
        # Process udpDestPortDist
        udp_dest_ports = sorted(list(data['udpDestPort'].keys()))
        udp_dest_port_freq = sorted(list(data['udpDestPort'].values()))
        print("\nUDP Destination Port Distribution:")
        print("Ports:", ", ".join([f"{port} ({frq})" for port, frq in zip(udp_dest_ports, udp_dest_port_freq)]))

    '''
    # Read JSON document from a file
    with open("network_traffic.json", "r") as f:
        json_doc = json.load(f)

    # Summarize network traffic
    summarize_network_traffic(json_doc)
    '''

for d in fields:
    if d == "packets":
        continue
    else:
        for dt in fields[d]:
            newVal = fields[d][dt] / fields["packets"] * 100
            newVal = round(newVal, 2)
            fields[d][dt] = newVal

sortFields = collections.OrderedDict(sorted(fields.items()))

output = json.dumps(sortFields, ensure_ascii=False, sort_keys=True, indent=4)
print(output)
