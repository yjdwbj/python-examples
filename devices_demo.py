#!/bin/python2
#coding=utf-8
import socket
import binascii
import logging
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

from logging import handlers

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


def send_data_to_app(srcsock,dstsock):
    buf = []
    stun_init_command_str(STUN_METHOD_DATA,buf)
    buf[3] = '%08x' % srcsock
    buf[4] = '%08x' % dstsock
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdatatestdata'))
    stun_add_fingerprint(buf)
    return buf

class ThreadRefreshTime(threading.Thread):
    def __init__(self,sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self._stopevent = threading.Event()
        self._sleepperiod = 1.0
        self.rtime = ''.join(stun_struct_refresh_request())
        log.info(','.join([self.name,'String','sock %d' % self.sock.fileno()]))

    def run(self):
        global rtime
        lock = threading.Lock()
        while self.sock:
            time.sleep(1)
            lock.acquire()
            rtime += 1
            lock.release()
            if rtime == REFRESH_TIME:
                rtime =0
            
                try:
                    nbyte = self.sock.send(binascii.unhexlify(self.rtime))
                    log.info(','.join(['sock','%d' %self.sock.fileno(),'refresh','send %d' % nbyte]))
                except:
                    log.info(','.join([self.name,'Exiting']))
                    self._stopevent.set()

    def join(self,timeout=None):
        log.info(','.join([self.name,'Exiting','sock %d' % self.sock.fileno()]))
        self.sock.close()
        self._stopevent.set()
        threading.Thread.join(self,timeout)
        



def device_login(host,uuid):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    lock = threading.Lock()
    try:
        sock.connect(host)
    except:
        print 'format_exception():'
        log.info(','.join(['sock %d' % sock.fileno(),'connect timeout']))
        return 
    buf = ''.join(device_struct_allocate(uuid))
    nbyte = sock.send(binascii.unhexlify(buf))
    log.info(','.join(['sock','%d' % sock.fileno(),'send %d'%nbyte]))
    mysock = 0xFFFFFFFF
    myconn = []
    global rtime
    while True:
        try:
            data = sock.recv(SOCK_BUFSIZE)
        except:
            break
        lock.acquire()
        rtime = 0
        lock.release()
        if not data:
            break
        else:
            hbuf = binascii.hexlify(data)
            log.info(','.join(['sock','%d' % sock.fileno(),'recv %d' % (len(hbuf)/2) ]))
            hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH*2])
            rdict = parser_stun_package(hbuf[STUN_HEADER_LENGTH*2:-8])
            if not rdict:
                log.info(','.join(['sock','%d' % sock.fileno(),'server packet is wrong,rdict is empty']))
                break # 出错了
            if hattr.method == STUN_METHOD_SEND or hattr.method == STUN_METHOD_INFO:
                pass
            else:
                if not stun_is_success_response_str(hattr.method):
                    log.info(','.join(['sock','%d' % sock.fileno(),'server error responses',\
                            'method',hattr.method]))
                    continue

            hattr.method = stun_get_type(hattr.method)
            if hattr.method == STUN_METHOD_ALLOCATE:
                t = ThreadRefreshTime(sock)
                t.setDaemon(True)
                t.start()
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
                
                log.info(','.join(['sock','%d' % sock.fileno(),'recv forward packet']))
                dstsock = int(hattr.srcsock,16)
                if mysock != 0xFFFFFFFF and dstsock != 0xFFFFFFFF:
                    buf = send_data_to_app(mysock,dstsock)
                    try:
                        nbyte = sock.send(binascii.unhexlify(''.join(buf)))
                    except:
                        break
                    log.info(','.join(['sock','%d' % sock.fileno(),'send %d' % nbyte]))
    log.info(','.join(['sock','%d' % sock.fileno(),'close']))
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
log  = logging.getLogger('dev_demo')
appname = 'devices_demo'
log.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
file_handler = handlers.RotatingFileHandler('%s.log' % appname,maxBytes=LOG_SIZE,backupCount=LOG_COUNT,encoding=None)

file_handler.setFormatter(formatter)
log.addHandler(file_handler)
#log.addHandler(logging.StreamHandler())


__version__ = '0.0.1'
if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)
    host = ()
    print args.uuidfile
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
    while True:
        time.sleep(0.3)
        try:
            uid = pickle.load(args.uuidfile)
            log.info(','.join(['Start UUID',uid]))
            t = threading.Thread(target=device_login,args=(host,uid))
            t.setDaemon(True)
            t.start()
            tlist.append(t)
        except EOFError:
            break

    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C')
    signal.pause()

