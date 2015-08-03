#!/usr/bin/env python
#-*- coding:utf-8 -*-
import os
import argparse
import binascii,struct
from binascii import hexlify,unhexlify
import time
import hashlib
import collections
import re
PCAP_HEAD = '!IHHIIII'
#DATA_HEAD = '!IIII'
ETHERNET_DATA = '!6B6BH'
IP_HEAD='!BBHHHBBHII'  #len,dscp,data_len,ident,flags,livetime,protype,srcip,dstip
TCP_HEAD ='!HHIIBBHHH'
UDP_HEAD ='!HHHH'
TCP_OPT ='%dB'
PCAP_HEAD_LEN = 24

def read_file(f):
    stream = {}
    if not is_pcaphead(f.read(PCAP_HEAD_LEN)):
        print "Valid pcap file"
        return
    else:
        n = 0
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
                if stream.has_key(k):
                    stream[k][tcp_p.seq] = tcp_p
                continue
            elif tcp_p.flags == 0x4: #rst
                continue
            elif tcp_p.flags == 0x10 or tcp_p.flags == 0x18: # ack,psh or ack
                if stream.has_key(k):
                    stream[k][tcp_p.seq] = tcp_p
            elif tcp_p.flags == 0x11: # fin,ack
                if stream.has_key(k):
                    stream[k][tcp_p.seq] = tcp_p
                    proc_stream(stream[k],synpkt)
                    stream.pop(k)

def split_src_dst(src,dst,syn,pkt):
    """区分源与目地"""
    if pkt.segment:
        if pkt.src_port == syn.src_port and pkt.src_ip == syn.src_ip:
            src.append(pkt.segment)
        else:
            dst.append(pkt.segment)


def proc_stream(stream_dict,synpkt):
    src = []
    dst = []
    [split_src_dst(src,dst,synpkt,x)  for x in collections.OrderedDict(sorted(stream_dict.items())).values()]
    
    allrequest= re.split(r'(GET |POST )*',''.join(src))
    allreq  = [ x for x in allrequest if len(x) > 5]
    n = ''.join(dst)
    allres  =[x for x in  n.split('HTTP/1.1 200 OK\r\n') if x]
    responses = [ x for x in allres if len(x) >0]
    [save_image(x) for x in responses] 
    """现在还无法把 request 与response包一一对应起来"""

def save_image1(request,response):
    """现在通过文件内容md5hash 值做为文件名，提取所标识为  'Content-Type: image/?' 的HTTP包"""
    ct = 'Content-Type: image/'
    ctlen = len(ct)
    rlist = request.split('\r\n')
    #print rlist
    urilast = rlist[0].split(' ')[0].split('/')[-1] # /abc/test.jpg HTTP/1.1\r\n
    dlist = response.split('\r\n\r\n')
    pagelist = dlist[0].split('\r\n')
    imgtype = [ x for x in pagelist if not cmp(ct,x[:ctlen])]
    if imgtype:
        imgname = None
        t = imgtype[0]
        ext = imgtype[0].split('/')[-1]
        if ext not in urilast:
            imgname  = urilast+'.'+ext
        else:
            imgname = urilast
        with open('%s/%s' % (outdir,imgname),'wb') as im:
            im.write(dlist[-1])


def save_image(response):
    ct = 'Content-Type: image/'
    ctlen = len(ct)
    dlist = response.split('\r\n\r\n')
    pagelist = dlist[0].split('\r\n')
    imgtype = [ x for x in pagelist if not cmp(ct,x[:ctlen])]
    if imgtype:
        t = imgtype[0]
        ext = imgtype[0].split('/')[-1]
        md5name = hashlib.md5(dlist[-1]).hexdigest()
        imgname = md5name+'.'+ext
        with open('%s/%s' % (outdir,imgname),'wb') as im:
            im.write(dlist[-1])
            

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
        """现在只处理IP包"""
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



