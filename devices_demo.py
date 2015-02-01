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

from epoll_global import *
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


def send_initial_packet(sock,host):
    try:
        sock.connect(host)
    except:
        print "threading connect host"

class ThreadConnectApp(threading.Thread):
    def __init__(self):
        global gport
        threading.Thread.__init__(self)
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.bind(('',gport))
        self.sock.setblocking(0)
        self.sock.listen(1)

    def run(self):
        sock = self.sock
        # connect nath server
        epoll = select.epoll()
        epoll.register(sock.fileno(),select.EPOLLIN)
        print "local",sock.getsockname()
        try:
            while True:
                events = epoll.poll(1)
                for fileno,event in events:
                    if fileno == sock.fileno():
                        try:
                            conn,addr = sock.accept()
                        except:
                            continue
                        clients[conn.fileno()] = conn
                        epoll.register(conn.fileno(),select.EPOLLIN)
                    elif event & select.EPOLLIN:
                        data = clients[fileno].recv(2048)
                        print "read",data
                        epoll.modify(fileno,select.EPOLLOUT)
                    elif event & select.EPOLLOUT:
                        clients[fileno].send("tetssss")
                        epoll.modify(fileno,select.EPOLLIN)
                    elif event & select.EPOLLHUP:
                        epoll.unregister(fileno)
                        clients[fileno].close()
                        clients.pop(fileno)
        finally:
            epoll.unregister(sock.fileno())
            epoll.close()
            sock.close()

class ThreadConnectNatSrv(threading.Thread):
    def __init__(self,addr):
        global gport
        threading.Thread.__init__(self)
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.bind(('',0))
        self.port = gport = self.sock.getsockname()[1]
        self.sock.connect(addr)

    def run(self):
        global gport
        sock=self.sock
        sock.send(binascii.unhexlify(''.join(device_struct_allocate())))
        while True:
            data = sock.recv(2048)
            if not data:
                break
            else:
                rhex = binascii.hexlify(data)
                res_mth = "%04x" % stun_get_method_str(int(rhex[:4],16))
                if res_mth == STUN_METHOD_ALLOCATE:
                    t = ThreadRefreshTime(sock)
                    t.start()
                elif res_mth == STUN_METHOD_CONNECT:
                    res = stun_handle_response(rhex)
                    if res.has_key(STUN_ATTRIBUTE_MESSAGE_ERROR_CODE):
                        print res[STUN_ATTRIBUTE_MESSAGE_ERROR_CODE][-1]
                    if res.has_key(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS):
                        phost = res[STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS][-2:]
                        cbuf = stun_connect_address(res) 
                        hhh = socket.inet_ntoa(binascii.unhexlify("%x" % (phost[1] ^ STUN_MAGIC_COOKIE)))
                        ppp = phost[0] ^  (STUN_MAGIC_COOKIE >> 16)
                        sock.send(binascii.unhexlify(''.join(cbuf)))
                        tsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        tsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                        print "gport is",gport
                        tsock.bind(('',gport))
                        tsock.setblocking(0)
                        tsock.connect((hhh,ppp))
                        tsock.close()
                        print "send server"

def send_data_to_app(srcsock,dstsock):
    buf = []
    stun_init_command_str(STUN_METHOD_DATA,buf)
    buf[3] = '%08x' % srcsock
    buf[4] = '%08x' % dstsock
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('wwwwwww'))
    stun_add_fingerprint(buf)
    return buf

class ThreadRefreshTime(threading.Thread):
    def __init__(self,sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self._stopevent = threading.Event()
        self._sleepperiod = 1.0
        self.rtime = ''.join(stun_struct_refresh_request())
        self.st = 5
        self.tt = time.time()+self.st

    def run(self):
        while self.sock and not self._stopevent.isSet():
            self._stopevent.wait(1)
            if time.time() > self.tt:
                self.tt = time.time()+self.st
                try:
                    self.sock.send(binascii.unhexlify(self.rtime))
                    log.info(','.join(['sock','%d' %self.sock.fileno(),'send']))
                except:
                    self._stopevent.set()

    def join(self,timeout=None):
        print 'Exit threading',self.name
        self.sock.close()
        self._stopevent.set()
        threading.Thread.join(self,timeout)
        



def device_login(host,uuid):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try:
        sock.connect(host)
    except Exception,err:
        print 'format_exception():'
    buf = ''.join(device_struct_allocate(uuid))

    log.info(','.join(['sock','%d' % sock.fileno(),'send']))
    sock.send(binascii.unhexlify(buf))
    mysock = 0
    myconn = []
    global tlist
    tlist = []
    while True:
        data = sock.recv(2048)
        if not data:
            break
        else:
            hbuf = binascii.hexlify(data)
            log.info(','.join(['sock','%d' % sock.fileno(),'recv']))
            hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH*2])
            rdict = parser_stun_package(hbuf[STUN_HEADER_LENGTH*2:-8])
            if not rdict:
                print "server packet is wrong"
                break # 出错了
            if hattr.method == STUN_METHOD_SEND or hattr.method == STUN_METHOD_INFO:
                pass
            else:
                if not stun_is_success_response_str(hattr.method):
                    print "error response",hattr.method
                    continue

            hattr.method = stun_get_type(hattr.method)
            if hattr.method == STUN_METHOD_ALLOCATE:
                t = ThreadRefreshTime(sock)
                t.setDaemon(True)
                t.start()
                tlist.append(t)
                if rdict.has_key(STUN_ATTRIBUTE_STATE):
                    stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                    mysock = int(stat[:8],16)
            elif hattr.method == STUN_METHOD_INFO:
                if rdict.has_key(STUN_ATTRIBUTE_STATE):
                    stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                    myconn = int(stat[:8],16)
            elif hattr.method == STUN_METHOD_SEND:
                print "recv forward packet"
                #if rdict.has_key(STUN_ATTRIBUTE_DATA):
                #    print rdict[STUN_ATTRIBUTE_DATA][-1],time.time()
                dstsock = int(hattr.srcsock,16)
                buf = send_data_to_app(mysock,dstsock)
                log.info(','.join(['sock','%d' % sock.fileno(),'send']))
                try:
                    sock.send(binascii.unhexlify(''.join(buf)))
                except:
                    break
    log.info(','.join(['sock','%d' % sock.fileno(),'close']))
    sock.close()
    print u'退出线程'



def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        global tlist
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
tlist = []
nclient = 1
#uuidbin = None
uuidbin = None
def devid_damon():
    #global uuidbin
    #uuidbin = open('uuid.bin','w')
    #device_allocate_login('120.24.235.68',3478)
    #device_login(('192.168.8.9',3478),uuid)
    #devices_services('120.24.235.68',3478)
    global gport
    #srvt = ThreadConnectNatSrv(('120.24.235.68',3478))
    #srvt.start()
    #appt = ThreadConnectApp()
    #appt.start()
    #uuidbin.close()
       

global tlist
log  = logging.getLogger('dev_demo')
appname = 'devices_demo'
log.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
file_handler = handlers.RotatingFileHandler('%s.log' % appname,maxBytes=LOG_SIZE,backupCount=LOG_COUNT,encoding=None)

file_handler.setFormatter(formatter)
log.addHandler(file_handler)
log.addHandler(logging.StreamHandler())


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
    tlist = []
    while True:
        if n == 15:
            n = 0
            time.sleep(1)
        try:
            uid = pickle.load(args.uuidfile)
            log.info(','.join(['Start UUID',uid]))
            t = threading.Thread(target=device_login,args=(host,uid))
            t.start()
        except EOFError:
            break
        n +=1

    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C')
    signal.pause()

