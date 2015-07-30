import os
import binascii,struct
from binascii import hexlify,unhexlify
PCAP_HEAD = '!IHHIIII'
#DATA_HEAD = '!IIII'
ETHERNET_DATA = '!6B6BH'
IP_HEAD='!BBHHBBBBHII'  #len,dscp,data_len,ident,flags,livetime,protype,srcip,dstip
TCP_HEAD ='!HHIIHHHH'
UDP_HEAD ='!HHHH'
TCP_OPT ='%dB'
PCAP_HEAD_LEN = 24



def read_file(fname):
    with open(fname) as f:
        if not is_pcaphead(f.read(PCAP_HEAD_LEN)):
            print "Valid pcap file"
            return
        else:
            n = 0
            while 1:
                print "Packet Seq", n+1
                processing_in_memory(f)
                n = n+1
            

def processing_in_memory(infile):
    data_head = infile.read(16)
    if not data_head:
        print "no more packets,exiting ...."
        exit()
    #print "data head",hexlify(data_head)
    seconds,unseconds = struct.unpack('!II',data_head[:8])
    packet_len,raw_len = struct.unpack('II',data_head[8:])
    print "packet raw len %d" % raw_len
    packet_buf = infile.read(raw_len)
    link_packet = struct.unpack(ETHERNET_DATA,packet_buf[:14])
    #print "link Type",link_packet[-1]
    if link_packet[-1] != 0x800:
        print "link type 0x%04x" % link_packet[-1]
        return 
    if link_packet[-1] == 0x806:
        #infile.read(raw_len - 16)
        print "this is ARP"
        print "file pos 0x%04x" % infile.tell()
        print "---------------------------------------------------------------"
        return

    if link_packet[-1] == 0x86dd:
        print "this is IPV6"
        print "file pos 0x%04x" % infile.tell()
        print "---------------------------------------------------------------"
        return

    proto_v = binascii.hexlify(packet_buf[14])
    ip_headsize = int(proto_v[1])*4
    #print "ip version " + proto_v[0]
    #print "ip head size %d" % ip_headsize
    ip_pos = 14+ip_headsize
    ip_packet = struct.unpack(IP_HEAD,packet_buf[14:ip_pos])
    #print "ip packet " , ip_packet
    ip_pro_type = int(hexlify(packet_buf[0x17]))
    if ip_pro_type == 6:
        packet_len = ip_packet[2]
        #print "total lenght %d" % packet_len
        tcp_headsize = int(binascii.hexlify(packet_buf[0x2e])[0],16) * 4
        tcp_packet = struct.unpack('%s%s' % (TCP_HEAD,TCP_OPT %(tcp_headsize-20)),packet_buf[ip_pos:ip_pos+tcp_headsize])
        #print "tcp head size",tcp_headsize
        #print "tcp packet" , tcp_packet
        segment_pos = 34+tcp_headsize
        print "segment data pos",segment_pos
        print "segment data",hexlify(packet_buf[segment_pos:])
    elif ip_pro_type == 17:
        """ UDP protocol"""
        udp_packet = struct.unpack(UDP_HEAD,packet_buf[34:42])
        print "udp packet head",udp_packet 
        print "udp data",packet_buf[42:]
    #print "file pos 0x%04x" % infile.tell()
    #print "---------------------------------------------------------------"



    

        
    

def is_pcaphead(ghead):
    magic_num,major,minor,timezone,timestamp,max_package_len,link_type = struct.unpack(PCAP_HEAD,ghead)
    if magic_num == 0xD4C3B2A1 or magic_num == 0xA1B2C3D4:
        return True
    else:
        return False
    


read_file('/home/yjdwbj/wifi-apple-mix.pcap')



