import sys
import pcap
from hex_print import hex_print

def mac_header(header):
    print("--mac header--")

    dest_addr = header[0:12]
    sour_addr = header[12:24]
    mac_type = header[24:28]
    
    print("dest_addr: ", end='')
    hex_print(dest_addr)
    print("sour_addr: ", end='')
    hex_print(sour_addr)
    print("mac_type: ", end='')
    hex_print(mac_type)

    return mac_type
