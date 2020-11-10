import pcap

def sniffer(ifs):
    sniffer = pcap.pcap(name=ifs, promisc=True, immediate=True, timeout_ms=50)
    for ts, pkt in sniffer:
        #print(type(pkt.hex()))
        print('hex type')
        hexstring = pkt.hex()
        #length=len(hexstring)
        #print(length)
        for i in range(int(int(len(hexstring))/2)):
            #print(i)
            print(hexstring[i*2:(i*2)+2], end=' ')
        print()
        print()
        #print(hexstring)
        
        #print('string type')
        #print('%s\t' % str(pkt))

if __name__=='__main__':
    sniffer('ens33')
