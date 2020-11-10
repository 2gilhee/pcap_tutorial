import pcap

def macprint(address):
    for i in range(int(int(len(address))/2)):
        print(address[i*2:(i*2)+2], end=' ')
    print()

def macaddress(ifs):
    sniffer = pcap.pcap(name=ifs, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        print("----packet----")
        destination = pkt[0:6].hex()
        source = pkt[6:12].hex()
        print("destination address: ", end='')
        macprint(destination)
        print("source address: ", end='')
        macprint(source)
        print()


if __name__=='__main__':
    macaddress('ens33')
