#!/usr/bin/env python3
#
# profiler.py -- <woody@smallroom.com>
# profiler.py -i <interface> -c <packet_count> -d <destination_IP>

import matplotlib.pyplot as plt
import numpy as np
import json
import sys
import getopt
import pyshark

dev = "en0"
pktCount = 1
dstHost = '192.168.1.202'

# Get options for execution
argv = sys.argv[1:]

try:
    opts, args = getopt.getopt(argv, "i:c:d:")

except:
	print("profiler.py -i <interface> -c <packet count> -d <destination>")
	exit()

for opt, arg in opts:
    if opt == '-i':
        dev = arg
    elif opt == '-c':
        pktCount = int(arg)
    elif opt == '-d':
        dstHost = arg

displayFilter = "ip.dst == " + dstHost

fields = {}
fields["destIp"] = dstHost
fields["packets"] = 0
'''
fields["ipLenDist"] = {}
fields["ipTtlDist"] = {}
fields["tcpFlagDist"] = {}
fields["tcpWinSizeDist"] = {}
fields["tcpSrcPortDist"] = {}
fields["tcpDestPortDist"] = {}
fields["ipProtoDist"] = {}
fields["udpSrcPortDist"] = {}
fields["udpDestPortDist"] = {}
fields["ipSrcIpDist"] = {}
'''

def addOne(fieldOne, fieldTwo):
    if fieldOne not in fields:
        fields[fieldOne] = {}

    if fieldTwo in fields[fieldOne]:
        fields[fieldOne][fieldTwo] +=1
    else:
        fields[fieldOne][fieldTwo] = 1

def graphData(fieldName):
    x = list(fields[fieldName].keys())
    y = list(fields[fieldName].values())

    plt.scatter(x, y)
    plt.title(fieldName)
    plt.xticks(x, x, rotation='vertical')
    plt.subplots_adjust(bottom=0.15)
    plt.show()

# Init capture
capture = pyshark.LiveCapture(interface=dev, display_filter=displayFilter)

# Evaluate each packet
for p in capture.sniff_continuously(packet_count=pktCount):
    proto = "UNKNOWN"
    srcport = ""
    dstport = ""
    ipsrc = ""
    ipdst = ""

    # Determine layer 2 
    if 'arp' in p:
        proto = "ARP"
        continue
        ipsrc = p.arp.src_proto_ipv4
        ipdst = p.arp.dst_proto_ipv4

    # Deterimine layer 3 ipv4 vs ipv6
    if 'ip' in p:
        ipsrc = p.ip.src
        ipdst = p.ip.dst
        addOne("ipSrcIpDist", p.ip.src)
        addOne("ipLenDist", p.ip.len)
        addOne("ipTtlDist", p.ip.ttl)

        #print(p.ip.field_names)

    if 'ipv6' in p:
        ipsrc = p.ipv6.src
        ipdst = p.ipv6.dst
        addOne("ipSrcIpDist", p.ipv6.src)

        #print(p.ipv6.field_names)

    if 'icmpv6' in p:
        proto = "ICMPv6"

        #print(p.icmpv6.field_names)
    
    if 'icmp' in p:
        proto = "ICMP"

        #print(p.icmp.field_names)

    if 'igmp' in p:
        proto = "IGMP"

        #print(p.igmp.field_names)

    # Determine layer 4 protocol
    if 'tcp' in p:
        proto = "TCP"
        srcport = p.tcp.srcport
        dstport = p.tcp.dstport
        tcpflags = p.tcp.flags_str
        tcpflags = tcpflags.replace("·", "")

        addOne("tcpFlagDist", tcpflags)
        addOne("tcpWinSizeDist", p.tcp.window_size)
        addOne("tcpSrcPortDist", p.tcp.srcport)
        addOne("tcpDestPortDist", p.tcp.dstport)
        addOne("tcpLengthDist", p.tcp.len)

        #print(p.tcp.field_names)

    if 'udp' in p:
        proto = "UDP"
        srcport = p.udp.srcport
        dstport = p.udp.dstport

        addOne("udpSrcPortDist", p.udp.srcport)
        addOne("udpDestPortDist", p.udp.dstport)
        addOne("udpLengthDist", p.udp.length)

        #print(p.udp.field_names)

    if proto == "ICMP" or proto == "ICMPv6" or proto == "IGMP":
        print('{} {} --> {}'.format(proto, ipsrc, ipdst))
    else:
        print('{} {}:{} --> {}:{}'.format(proto, ipsrc, srcport, ipdst, dstport))


    addOne("ipProtoDist", proto)
    fields["packets"] += 1

#output = json.dumps(fields, ensure_ascii=False, sort_keys=True, indent=4).encode('utf8')
output = json.dumps(fields, ensure_ascii=False, sort_keys=True, indent=4)
print(output)

#graphData('tcpWinSizeDist')
#graphData('tcpLengthDist')
#graphData('tcpFlagDist')
