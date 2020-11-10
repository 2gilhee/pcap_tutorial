import pcap
from hex_print import hex_print

def fragment_parsing(header):
    fr_bit = ' '.join(format(ord(x),'b') for x in header)
    null_bit = fr_bit[2]
    dont_fragment = fr_bit[3]
    more_fragment = fr_bit[4]
    fragment_offset = ' '.join(format(x) for x in [fr_bit[5],fr_bit[9:13],fr_bit[16:20],fr_bit[23:27]])

    print("null_bit: ", end='')
    print(null_bit)
    print("dont_fragment(bit): ", end='')
    print(dont_fragment)
    print("more_fragment(bit): ", end='')
    print(more_fragment)
    print("fragment_offset(bit): ", end='')
    print(fragment_offset)

def ip_address(address):
    for i in range(4):
        print(int(address[i*2:(i*2)+2].encode(),16), end='.')
    print()


def ip_header(header, ip_check):
    if ip_check=="0800":
        print("--ip header--")

        version = int(header[0:1].encode(),16)
        header_length = int(header[1:2].encode(),16)
        type_of_service = header[2:4]
        total_length = int(header[4:8].encode(),16)
        identification = header[8:12]
        fragment = header[12:16]
        time_to_leave = header[16:18]
        protocol = header[18:20]
        header_checksom = header[20:24]
        sour_ip = header[24:32]
        dest_ip = header[32:40]
        option = None

        print("version: ", end='')
        print(version)
        print("header_length: ", end='')
        print(header_length)
        print("type_of_service: ", end='')
        hex_print(type_of_service)
        print("total_length: ", end='')
        print(total_length)
        print("identification: ", end='')
        hex_print(identification)
        print("fragment: ", end='')
        hex_print(fragment)
        fragment_parsing(fragment)
        print("time_to_leave: ", end='')
        hex_print(time_to_leave)
        print("protocol: ", end='')
        hex_print(protocol)
        print("header_checksom: ", end='')
        hex_print(header_checksom)
        print("sour_ip: ", end='')
        ip_address(sour_ip)
        print("dest_ip: ", end='')
        ip_address(dest_ip)
    else:
        print("IT'S NOT IP HEADER")
