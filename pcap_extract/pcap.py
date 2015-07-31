import os
import binascii,struct
from binascii import hexlify,unhexlify
import time
PCAP_HEAD = '!IHHIIII'
#DATA_HEAD = '!IIII'
ETHERNET_DATA = '!6B6BH'
IP_HEAD='!BBHHHBBHII'  #len,dscp,data_len,ident,flags,livetime,protype,srcip,dstip
TCP_HEAD ='!HHIIBBHHH'
UDP_HEAD ='!HHHH'
TCP_OPT ='%dB'
PCAP_HEAD_LEN = 24



def read_file(fname):
    stream = {}
    with open(fname) as f:
        if not is_pcaphead(f.read(PCAP_HEAD_LEN)):
            print "Valid pcap file"
            return
        else:
            n = 0
            while 1:
                #print "Packet Seq", n+1
                rdata = processing_in_memory(f)
                if not rdata:
                    continue
                src_ip,dst_ip,tcp_p = rdata
                    
                ud = {src_ip:tcp_p.src_port,dst_ip:tcp_p.dst_port}
                k = id(ud)
                if tcp_p.flags == 0x2: # syn
                    stream[k] = {}
                elif tcp_p.flags == 0x12: # syn,ack
                    continue
                elif tcp_p.flags == 0x10 or tcp_p.flags == 0x18: # ack,psh
                    if stream.has_key(k) and tcp_p.segment:
                        #print "has keys",stream.keys(),ud
                        stream[k][tcp_p.seq] = tcp_p.segment

                elif tcp_p.flags == 0x11: # fin,ack
                    # reassembled packets
                    #print "fin ack, key",k,ud
                    print "has keys",stream.keys
                    ct = 'Content-Type: image/'
                    ctlen = len(ct)
                    if stream.has_key(k):
                        if tcp_p.segment:
                            stream[k][tcp_p.seq] = tcp_p.segment
                        http_packet = ''.join(stream[k].values())
                        if not cmp('HTTP',http_packet[:4]):
                            pagelist = http_packet.split('\r\n')
                            imgtype = [ x for x in pagelist if not cmp(ct,x[:ctlen])]
                            print "image type",imgtype
                            if imgtype:
                                ext = imgtype[0][ctlen:]
                                with open('/home/yjdwbj/python-examples/image_dir/%s.%s' % (str(time.time()),ext),'wb') as im:
                                    im.write(pagelist[-1])
                                del pagelist[:]
                                    
                            #print pagelist
                        stream.pop(k)
                        #else:
                        #    print "reassembled packets",hexlify(http_packet)
                n = n+1
            

def processing_in_memory(infile):
    data_head = infile.read(16)
    if not data_head:
        print "no more packets,exiting ...."
        exit()
    #print "data head",hexlify(data_head)
    seconds,unseconds = struct.unpack('!II',data_head[:8])
    packet_len,raw_len = struct.unpack('II',data_head[8:])
    packet_buf = infile.read(raw_len)
    frame_type= struct.unpack('!H',packet_buf[12:14])[0]
    #print "link Type",link_packet[-1]
    if frame_type != 0x800:
        return 
    if frame_type == 0x806:
        #infile.read(raw_len - 16)
        print "this is ARP"
        print "file pos 0x%04x" % infile.tell()
        print "---------------------------------------------------------------"
        return

    if frame_type == 0x86dd:
        print "this is IPV6"
        print "file pos 0x%04x" % infile.tell()
        print "---------------------------------------------------------------"
        return

    verlen,dsf,iplen,ident,ff,tlive,ip_pro_type,chksum,src_ip,dst_ip= struct.unpack(IP_HEAD,packet_buf[14:34])
    ip_headsize = ((iplen > 4 )&0xF)*4
    #print "ip version " + proto_v[0]
    #print "ip head size %d" % ip_headsize
    #print "ip packet " , ip_packet
    if ip_pro_type == 6:
        tcp_packet = tcp_packet_parse(packet_buf[34:])
        return (src_ip,dst_ip,tcp_packet)
        #print "tcp head size",tcp_headsize
        #print "tcp packet" , tcp_packet
    elif ip_pro_type == 17:
        """ UDP protocol"""
        udp_packet = struct.unpack(UDP_HEAD,packet_buf[34:42])
        #print "udp packet head",udp_packet 
        return None
    #print "file pos 0x%04x" % infile.tell()
    #print "---------------------------------------------------------------"
    

class Packet():
    pass

def get_http_packet():
    pass


def tcp_packet_parse(buf):
    tcp = Packet()
    tcp.segment = None
    tcp.src_port,tcp.dst_port,tcp.seq,tcp.ack_seq,tcp.t_l,tcp.flags,tcp.w_size,tcp.chksum,tcp.urgen_p = \
            struct.unpack(TCP_HEAD,buf[:20])
    bl = len(buf)
    if bl > 20:
        tl = ((tcp.t_l >> 4 )& 0xF )*4
        if tl > 20: # have tcp options 
            tcp.options = struct.unpack('!%dB' % (tl-20),buf[20:tl])
        if bl > tl: # have segment data
            tcp.segment = buf[tl:]
    return  tcp



    

        
    

def is_pcaphead(ghead):
    magic_num,major,minor,timezone,timestamp,max_package_len,link_type = struct.unpack(PCAP_HEAD,ghead)
    if magic_num == 0xD4C3B2A1 or magic_num == 0xA1B2C3D4:
        return True
    else:
        return False
  


read_file('/home/yjdwbj/wifi-apple-mix.pcap')



