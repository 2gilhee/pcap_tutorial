#!/usr/bin/python
import sys
import pcap
from hex_print import hex_print
from mac_header import mac_header
from ip_header import ip_header

def sniffer(ifs):
    sniffer = pcap.pcap(name=ifs, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        print("----packet----")
        mac_type = mac_header(pkt[0:14].hex())
        ip_header(pkt[14:34].hex(), mac_type)
        print()

if __name__=='__main__':
    sniffer(sys.argv[1])
