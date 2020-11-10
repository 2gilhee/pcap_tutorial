import pcap
import struct

def hex_print(address):
    for i in range(int(len(address)/2)):
        print(address[i*2:(i*2)+2], end=' ')
    print()

def mac_header(pkt):
    destination = pkt[0:6].hex()
    source = pkt[6:12].hex()
    mac_type = pkt[12:14].hex()

    print("mac dest address: ", end='')
    hex_print(destination)
    print("mac sour address: ", end='')
    hex_print(source)
    print("mac type: ", end='')
    hex_print(mac_type)

    return mac_type

def sniffer(ifs):
    sniffer = pcap.pcap(name=ifs, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        mac_type = pkt[12:14].hex()
        if mac_type=='0800':
            print("----packet----")
            mac_header(pkt)
            print()
        else:
            print("It's not IP packet!")
            print()
        


if __name__=='__main__':
    sniffer('ens33')
