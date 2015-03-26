#!/opt/pypy-2.5.0-src/pypy-c
#coding=utf-8
#!/opt/stackless-279/bin/python
import socket
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
from multiprocessing import Queue


from sockbasic import *

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
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('mnbvcxzz'))
    stun_add_fingerprint(buf)
    return buf

#class Devices(threading.Thread):
class Devices:
    pass
def refresh_time(sock,timer_queue,errlog,refresh_buf):
       n = time.time() + 30
       while True:
           try:
               num = timer_queue.get_nowait()
               n = time.time()+30
           except:
               time.sleep(1)
               if time.time() > n:
                   try:
                       sock.send(refresh_buf)
                   except IOError:
                      errlog.log(','.join(['sock','%d'% sock.fileno(),' closed,occur error,send packets %d ' % mynum]))

def DevicesFunc(host,uuid):
    devclass = Devices()
    #threading.Thread.__init__(devclass)
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
    sock.settimeout(SOCK_TIMEOUT)
    mysock = 0xFFFFFFFF
    dstsock = 0xFFFFFFFF
    mynum = 0
    refresh_buf = binascii.unhexlify(''.join(stun_struct_refresh_request()))
    timer_queue = Queue()
    fileno = sock.fileno()
    try:
        sock.connect(host)
    except socket.timeout:
        errlog.log('sock %d timeout' % sock.fileno())
        return 
    buf = device_struct_allocate(uuid)
    if write_sock(sock,buf,errlog):
        return
    sendtrigger = 1
    myrecv = ''
    while True:
        try:
            data = sock.recv(SOCK_BUFSIZE)
        except IOError:
            errlog.log('sock %d,recv occur erro' % fileno)
            break
        timer_queue.put(0)
        if not data:
            errlog.log('sock %d,recv not data' % fileno)
            if write_sock(sock,buf,errlog):
                break
            continue
        hbuf = binascii.hexlify(data)
        hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            errlog.log('sock %d,recv wrong head' % fileno)
            continue

        if  stun_get_type(hattr.method) == STUN_METHOD_SEND:
            time.sleep(1)
            if hattr.srcsock == 0xFFFFFFFF:
                errlog.log('sock %d,recv forward packet not srcsock' % fileno)
                continue
            dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                time.sleep(1)
                buf = send_data_to_app(mysock,dstsock,'02%s' % hattr.sequence[2:])
                slog.log("sock %d,recv app send num hex(%s)" % (fileno,hattr.sequence[2:]))
            #下面是我方主动发数据
            elif hattr.sequence[:2] == '02':
                rnum = int(hattr.sequence[2:],16)
                if mynum > 0xFFFFFF:
                    mynum = 0
                    errlog.log('socket %d,packet counter is over 0xFFFFFF once' % fileno)
                elif mynum == rnum:
                    mynum +=1
                    slog.log("sock %d,recv my confirm num %d is ok,data %s" % (fileno,rnum,hbuf))
                else:
                    errlog.log('sock %d,losing packet,recv  number  %d, my counter %d' % (fileno,rnum,mynum))
                buf = send_data_to_app(mysock,dstsock,'03%06x' % mynum)
            if write_sock(sock,buf,errlog):
                break

#            if sendtrigger:
#                time.sleep(1)
#                buf = send_data_to_app(mysock,dstsock,'03%06x' % mynum)
#                if write_sock(sock,buf,errlog):
#                    break
#                sendtrigger = 0
            continue
        p = parser_stun_package(hbuf[STUN_HEADER_LENGTH:-8])
        if not p:
            slog.log(','.join(['sock','%d' % fileno,'server packet is wrong,rdict is empty']))
            break # 出错了


        if not stun_is_success_response_str(hattr.method):
                slog.log(','.join(['sock','%d' % fileno,'server error responses',\
                        'method',hattr.method]))
                continue

        hattr.method = stun_get_type(hattr.method)
        rdict = p[0]
        if hattr.method == STUN_METHOD_ALLOCATE:
            pt = threading.Thread(target=refresh_time,args=(sock,timer_queue,errlog,refresh_buf))
            pt.start()
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                mysock = int(stat[:8],16)
            except KeyError:
                pass
        elif hattr.method == STUN_METHOD_INFO:
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                buf = send_data_to_app(mysock,int(stat[:8],16),'03%06x' % mynum)
                
                if write_sock(sock,buf,errlog):
                    break
            except KeyError:
                errlog.log("sock %d,recv not state" % fileno)


    errlog.log(','.join(['sock','%d' % fileno,'close,forward packets %d' % mynum]))
    sock.close()


def write_sock(sock,buf,errlog):
    if buf:
        try:
            nbyte = sock.send(binascii.unhexlify(''.join(buf)))
            return False
        except IOError:
            errlog.log('socket %d close,' % sock.fileno())
            return True
        except TypeError:
            errlog.log('send buf is wrong format %s' % buf)
            return False
        
    
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
    appname = "thread_devices"
    slog  = StatLog(appname)
    errlog = ErrLog(appname)
    for uid in uulist:
        it = threading.Thread(target=DevicesFunc,args=(host,uid))
        it.start()
        time.sleep(0.3)


