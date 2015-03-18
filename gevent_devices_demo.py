#!/opt/stackless-279/bin/python2
#coding=utf-8
from gevent import monkey;monkey.patch_all()
from gevent import socket
from gevent.event import AsyncResult
import gevent
#import socket
import binascii
import random
import struct
import string
import threading
import time
import hmac
import hashlib
import uuid
import sys
import pickle
import select
import argparse
import signal


from epoll_global import *

reload(sys)
sys.setdefaultencoding("utf-8")


def stun_struct_refresh_request():
    buf = []
    stun_init_command_str(STUN_METHOD_REFRESH,buf)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    return buf
########## handle response packets ##############


#### 模拟小机登录

def device_struct_allocate(uid):
    buf = []
    stun_init_command_str(STUN_METHOD_ALLOCATE,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,uid)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdata'))
    stun_add_fingerprint(buf)
    return buf


def send_data_to_app(srcsock,dstsock,sequence):
    buf = []
    stun_init_command_str(STUN_METHOD_DATA,buf)
    buf[3] = '%08x' % srcsock
    buf[4] = '%08x' % dstsock
    buf[-1] = sequence
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdatatestdata'))
    stun_add_fingerprint(buf)
    return buf

def send_data_work(q,evt):
    while True:
        evt.wait()

        q.put(50)


def device_login(host,uuid):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    try:
        sock.connect(host)
    except socket.timeout:
        errlog.log('socket %d connect server timeout' % sock.fileno())
        return
    buf = ''.join(device_struct_allocate(uuid))
    nbyte = sock.send(binascii.unhexlify(buf))
    mysock = 0xFFFFFFFF
    myconn = []
    mynum = 0
    global rtime
    a = AsyncResult()
    rtbuf = ''.join(stun_struct_refresh_request())
    while True:
        data = sock.recv(SOCK_BUFSIZE)
        a.set(0)
        if not data:
            break
        hbuf = binascii.hexlify(data)
        slog.log(','.join(['sock','%d' % sock.fileno(),'recv %d' % (len(hbuf)/2) ]))
        hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH*2])
        rdict = parser_stun_package(hbuf[STUN_HEADER_LENGTH*2:-8])
        if not rdict:
            slog.log(','.join(['sock','%d' % sock.fileno(),'server packet is wrong,rdict is empty']))
            break # 出错了
        if hattr.method == STUN_METHOD_SEND or hattr.method == STUN_METHOD_INFO:
            pass
        else:
            if not stun_is_success_response_str(hattr.method):
                slog.log(','.join(['sock','%d' % sock.fileno(),'server error responses',\
                        'method',hattr.method]))
                continue

        hattr.method = stun_get_type(hattr.method)
        if hattr.method == STUN_METHOD_ALLOCATE:
            gevent.spawn(refresh_time,sock,a,binascii.unhexlify(rtbuf),slog).join(timeout=0.2)
            #stackless.tasklet(refresh_time)(sock,a,binascii.unhexlify(p),slog)
            if rdict.has_key(STUN_ATTRIBUTE_STATE):
                stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                mysock = int(stat[:8],16)
        elif hattr.method == STUN_METHOD_INFO:
            if rdict.has_key(STUN_ATTRIBUTE_STATE):
                stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                myconn = int(stat[:8],16)
        elif hattr.method == STUN_METHOD_SEND:
            #if rdict.has_key(STUN_ATTRIBUTE_DATA):
            #    print rdict[STUN_ATTRIBUTE_DATA][-1],time.time()
            
            dstsock = int(hattr.srcsock,16)
            if mysock != 0xFFFFFFFF and dstsock != 0xFFFFFFFF:
                if hattr.sequence[:2] == '03':
                    buf = send_data_to_app(mysock,dstsock,'02%s' % hattr.sequence[2:])
                #下面是我方主动发数据
                elif hattr.sequence[:2] == '02':
                    rnum = int(hattr.sequence[2:],16)
                    if mynum == rnum:
                        mynum +=1
                    else:
                        errlog.log('losing packet number of %d',mynum)

                    buf = send_data_to_app(mysock,dstsock,'03%06x' % mynum)
                try:
                    nbyte = sock.send(binascii.unhexlify(''.join(buf)))
                except:
                     break

                #slog.log(','.join(['sock','%d' % sock.fileno(),'send %d' % nbyte]))
    slog.log(','.join(['sock','%d' % sock.fileno(),'close']))
    sock.close()


def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        for n in tlist:
            time.sleep(0.1)
            n.join()
        sys.exit(0)

def make_argument_parser():
    parser = argparse.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
            )
    parser.add_argument
    parser.add_argument('-H',action='store',dest='srv_host',type=str,\
            help=u'服务器地址, 端口默认是:3478 ,例如: -H 192.168.9:3478')
    #parser.add_argument('-p',action='store',default=3478,dest='port',type=int,\
    #                    help=u'服务器端口号，默认是: 3478')
    parser.add_argument('-f',action='store',dest='uuidfile',type=file,\
                        help=u'UUID的文件，例如： -f file.bin')
    parser.add_argument('--version',action='version',version=__version__)
    return parser



ehost = [] # 外部地址
phost = [] # 对端地址
nclient = 1
#uuidbin = None
uuidbin = None

tlist = []
global rtime
rtime = 0
appname = 'devices_demo'
slog  = StatLog(appname)
errlog = ErrLog(appname)
#log.addHandler(logging.StreamHandler())


__version__ = '0.0.1'
if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)
    host = ()
    if ':' in args.srv_host:
        s = args.srv_host.split(':')
        try:
            p = int(s[-1])
        except:
            print u'端口格式无法识别'
            exit(1)
        host = (s[0],p)
    else:
        host = (args.srv_host,3478)
        

    uuidfile = args.uuidfile
    n =0

    spalist = []
    uulist = []
    while True:
        try:
            uulist.append(pickle.load(args.uuidfile))
        except EOFError:
            break

    #slog.log(','.join(['Start UUID',uid]))
    #gp = [gevent.spawn(device_login,host,uid) for uid in uulist]
    gp = [threading.Thread(target=device_login,args=(host,uid)) for uid in uulist]
    for item in gp:
        item.run()
        item.join()


