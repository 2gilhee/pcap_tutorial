import pcap

def hex_print(temp):
    for i in range(int(len(temp)/2)):
        print(temp[i*2:(i*2)+2], end=' ')
    print()

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

def ip_header(header, ip_check):
    if ip_check=="0800":
        print("--ip header--")
        version = header[0:1]
        header_length = header[1:2]
        type_of_service = header[2:4]
        total_length = header[4:8]
        identification = header[8:12]
        fragment = header[12:16]
        null_bit = None
        dont_fragment = None
        more_fragment = None
        fragment_offset = None
        time_to_leave = header[16:18]
        protocol = header[18:20]
        header_checksom = header[20:24]
        sour_ip = header[24:32]
        dest_ip = header[32:40]
        option = None

        print(type(version))
        print(version)

        byte = version.encode()
        print(type(byte))
        print(byte)

        binary = ' '.join(format(ord(x),'b') for x in fragment)
        print(type(binary))
        full = ' '.join(format(x) for x in [binary[5],binary[9:13],binary[16:20],binary[23:27]])
        print(full)

    else:
        print("IT'S NOT IP HEADER")


def sniffer(ifs):
    sniffer = pcap.pcap(name=ifs, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        print("----packet----")
        #mac_type = mac_header(pkt[0:14].hex())
        ip_header(pkt[14:34].hex(), "0800")
        #temp = pkt[14:15].hex()
        #byte_array = bytearray(temp,"utf8")
        #print("type: ",type(pkt))
        #print("type: ",type(bin(pkt)))
        #print("packet: ",pkt)
        print()

if __name__=='__main__':
    sniffer('ens33')
