#!/usr/bin/env python
import os
import argparse
import binascii,struct
from binascii import hexlify,unhexlify
import time
import hashlib
import collections
PCAP_HEAD = '!IHHIIII'
#DATA_HEAD = '!IIII'
ETHERNET_DATA = '!6B6BH'
IP_HEAD='!BBHHHBBHII'  #len,dscp,data_len,ident,flags,livetime,protype,srcip,dstip
TCP_HEAD ='!HHIIBBHHH'
UDP_HEAD ='!HHHH'
TCP_OPT ='%dB'
PCAP_HEAD_LEN = 24


class PeerClass():
    def __init__(self,syn):
        self.syn = syn
        self.con = {}
        self.fin = None

def read_file(f):
    stream = {}
    if not is_pcaphead(f.read(PCAP_HEAD_LEN)):
        print "Valid pcap file"
        return
    else:
        n = 0
        last_pkt = None
        synpkt =None
        while 1:
            #print "Packet Seq", n+1
            tcp_p = processing_in_memory(f)
            if not tcp_p:
                continue
            #print 'dst port',tcp_p.dst_port,'src port',tcp_p.src_port
            if tcp_p.dst_port == 443 or tcp_p.src_port == 443:
                continue
                
            ud = {tcp_p.src_ip:tcp_p.src_port,tcp_p.dst_ip:tcp_p.dst_port}
            k = hashlib.md5(str(ud)).hexdigest()
            if tcp_p.flags == 0x2: # syn
                #stream[k] = {'request':{},'response':{}}
                #newstream = PeerClass(tcp_p)
                stream[k] = {}
                synpkt = tcp_p
                stream[k][tcp_p.seq] = tcp_p
            elif tcp_p.flags == 0x12: # syn,ack
                #stream[k].con[tcp_p.seq] = tcp_p
                if stream.has_key(k):
                    stream[k][tcp_p.seq] = tcp_p
                continue
            elif tcp_p.flags == 0x10 or tcp_p.flags == 0x18: # ack,psh or ack
                if stream.has_key(k):
                    stream[k][tcp_p.seq] = tcp_p
#                if stream.has_key(k) and tcp_p.segment:
#                    #print "has keys",stream.keys(),ud
#                    if not cmp(tcp_p.segment[:4],'POST') or not cmp(tcp_p.segment[:3],'GET'):
#                        #print "Request",tcp_p.segment
#                        stream[k]['request'][tcp_p.seq] = tcp_p.segment 
#                    else:
#                        stream[k]['response'][tcp_p.seq] = tcp_p.segment 
#                        #save_image(stream,tcp_p,k)
            elif tcp_p.flags == 0x11: # fin,ack
                #save_image(stream,tcp_p,k)
                if stream.has_key(k):
                    stream[k][tcp_p.seq] = tcp_p
                    proc_stream(stream[k],synpkt)
                # reassembled packets
                #print "fin ack, key",k,ud

def split_src_dst(src,dst,syn,pkt):
    if pkt.segment:
        if pkt.src_port == syn.src_port and pkt.src_ip == syn.src_ip:
            src.append(pkt.segment)
        else:
            dst.append(pkt.segment)


def proc_stream(stream_dict,synpkt):
    if not synpkt:
        return
    src = []
    dst = []
    [split_src_dst(src,dst,synpkt,x)  for x in stream_dict.values()]
    requests  = []
    peerA = ''.join(src)
    peerB = ''.join(dst)
    if peerB.count('HTTP') > 1:
        if peerA.count('GET') > 1:
           [save_image1('GET%s' % x,'HTTP%s' % y) for x  in peerA.split('GET') for y in peerB.split('HTTP/1.1 200 OK')]
        elif peerA.count('POST') >1:
           [save_image1('HOST%s' % x,'HTTP%s' % y) for x  in peerA.split('POST') for y in peerB.split('HTTP/1.1 200 OK')]
        elif peerA.count('GET') == 1 and peerA.count('POST') == 1:
            if peerA[:3] == 'GET':
                save_image2(peerA[:peerA.index('POST')],peerB[:peerB[4:].index('HTTP/1.1 200 OK')+15])
                save_image1(peerA[peerA.index('POST'):],peerB[peerB[4:].index('HTTP')+4:])
            else:
                save_image1(peerA[:peerA.index('GET')],peerB[:peerB[4:].index('HTTP')+4])
                save_image1(peerA[peerA.index('GET'):],peerB[:peerB[4:].index('HTTP')+4:])
    else:
        save_image1(peerA,peerB)


    #if peerA[:3] == 'GET' or peerA[:4] == 'POST':
    

def save_image1(request,response):
    ct = 'Content-Type: image/'
    ctlen = len(ct)
    pagelist = response.split('\r\n')
    imgtype = [ x for x in pagelist if not cmp(ct,x[:ctlen])]
    if imgtype:
        ext = imgtype[0][ctlen:]
        if ext == 'png':
            data = response[response.index('PNG')-1:]
            with open('%s/%s.%s' % (outdir,hashlib.sha1(request).hexdigest(),ext),'wb') as im:
                im.write(data)


def save_image(stream,tcp_p,k):
    if not stream.has_key(k):
        return
    ct = 'Content-Type: image/'
    ctlen = len(ct)
    od = collections.OrderedDict(sorted(stream[k]['response'].items()))
    http_packet = ''.join(od.values())
    pagelist = http_packet.split('\r\n')
    #print pagelist
    #printgg "Request",req_pkt.split('\r\n')
    #pagelist = http_packet.split('\r\n')
    req_uri = ''.join(stream[k]['request'].values()).split('\r\n')[0]
    imgtype = [ x for x in pagelist if not cmp(ct,x[:ctlen])]
    if imgtype:
        ext = imgtype[0][ctlen:]
        with open('%s/%s.%s' % (outdir,hashlib.sha1(req_uri).hexdigest(),ext),'wb') as im:
            im.write(pagelist[-1])
        del pagelist[:]
                
        #print pagelist
    #stream.pop(k)
        #else:
        #    print "reassembled packets",hexlify(http_packet)
            

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
        tcp_packet.src_ip = src_ip
        tcp_packet.dst_ip = dst_ip
        return tcp_packet

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
  



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description ='extract image from pcap')
    parser.add_argument('-f',metavar='in-file',type=argparse.FileType('rb'),dest='infile')
    parser.add_argument('-o',action="store",type=str,dest="outdir")
    args = parser.parse_args()
    if not args.infile:
        print args
        exit()
    outdir = os.path.abspath('.')
    if args.outdir:
        outdir = os.path.abspath(args.outdir)
        if not os.path.exists(outdir):
            os.mkdir(outdir)

    try:
        read_file(args.infile)
    except IOError:
        print parser.parse_args('-h')

#read_file('/home/yjdwbj/wifi-apple-mix.pcap')



