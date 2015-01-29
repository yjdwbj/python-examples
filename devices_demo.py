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
import pdb
import traceback

from epoll_global import *


#### Refresh Request ######


def stun_struct_refresh_request():
    buf = []
    stun_init_command_str(STUN_METHOD_REFRESH,buf)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    return buf
########## handle response packets ##############


def stun_handle_response(response):
    ss = struct.Struct(STUN_STRUCT_FMT)
    hexpos = struct.calcsize(STUN_STRUCT_FMT)*2
    rdict = {}
    reqhead = recv_header = ss.unpack(binascii.unhexlify(response[:hexpos]))
    rdict['tid'] = binascii.hexlify(reqhead[-1])
    #send_header = ss.unpack(binascii.a2b_hex(''.join(last_request[:4])))
    res_mth = "%04x" % stun_get_method_str(recv_header[0])
    rdict['rmethod'] = res_mth
    #print "This method is",res_mth,"send method is",send_header[0]
    iserr = False
    if stun_is_success_response_str(recv_header[0]) == False:
        print "Not success response"
        iserr = True

    hexpos = 40
    blen = len(response)
    while hexpos < blen:
        n = get_first_attr(response[hexpos:],rdict)
        if n == 0:
            print "Unkown Attribute"
            print "resposes left",response[hexpos:]
            return rdict
        else:
            hexpos += n
    if iserr and rdict.has_key(STUN_ATTRIBUTE_MESSAGE_ERROR_CODE):
        print "Occur error ",binascii.unhexlify(rdict[STUN_ATTRIBUTE_MESSAGE_ERROR_CODE][-1])
    return rdict

#### 模拟小机登录

def device_struct_allocate():
    buf = []
    stun_init_command_str(STUN_METHOD_ALLOCATE,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,'e68cd4167aea4f85a7242031252be15874657374a860a02f')
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdata'))
    stun_add_fingerprint(buf)
    print buf
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
        clients = {}
        responses = {}
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
                print "not data"
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

    def run(self):
        while self.sock:
            buf = stun_struct_refresh_request()
            sdata = binascii.a2b_hex(''.join(buf))
            try:
                self.sock.send(sdata)
            except:
                print "socket has closed"
                return
            time.sleep(30)


def device_login(host):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try:
        sock.connect(host)
    except Exception,err:
        print 'format_exception():'
    buf = ''.join(device_struct_allocate())
    sock.send(binascii.unhexlify(buf))
    mysock = 0
    myconn = []
    while True:
        data = sock.recv(2048)
        if not data:
            break
        else:
            hbuf = binascii.hexlify(data)
            print 'recv buf is',hbuf
            #hdict = get_packet_head_dict(hbuf[:STUN_HEADER_LENGTH*2])
            hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH*2])
            rdict = parser_stun_package(hbuf[STUN_HEADER_LENGTH*2:-8])
            if not rdict:
                print "server packet is wrong"
                break # 出错了
            if hattr.method != STUN_METHOD_SEND:
                if not stun_is_success_response_str(hattr.method):
                    print "error response",hattr.method
                    continue
            hattr.method = stun_get_type(hattr.method)
            print "method",hattr.method
            if hattr.method == STUN_METHOD_ALLOCATE:
                print 'start refresh time'
                t = ThreadRefreshTime(sock)
                t.start()
                if rdict.has_key(STUN_ATTRIBUTE_STATE):
                    stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                    mysock = int(stat[:8],16)
            elif hattr.method == STUN_METHOD_INFO:
                if rdict.has_key(STUN_ATTRIBUTE_STATE):
                    stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                    myconn = int(stat[:8],16)
            elif hattr.method == STUN_METHOD_SEND:
                print "recv forward packet"
                if rdict.has_key[STUN_ATTRIBUTE_DATA]:
                    print rdict[STUN_ATTRIBUTE_DATA][-1]
                dstsock = int(hattr.srcsock,16)
                buf = send_data_to_app(mysock,dstsock)
                print "replay forward buf",buf
                sock.send(binascii.unhexlify(''.join(buf)))


    print 'sock will close'
    sock.close()





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
    device_login(('192.168.8.9',3478))
    #devices_services('120.24.235.68',3478)
    global gport
    #srvt = ThreadConnectNatSrv(('120.24.235.68',3478))
    #srvt.start()
    #appt = ThreadConnectApp()
    #appt.start()
    #uuidbin.close()


def test_radom_uuid():
    global uuidbin
    if len(sys.argv) < 2:
        print "请在后写一个数量"
    try:
        nclient = sys.argv[1]
    except:
        return
    nclient = int(nclient)
    uuidbin = open('uuid.bin','w')
    n = 5
    for i  in xrange(nclient):
        print i,"client now start"
        try:
            t = threading.Thread(target=device_allocate_login,args=('192.168.8.9',3478))
            t.start()
        except IOError:
            print "too many files opened"
        if n == 0:
            time.sleep(1)
            n=15
        n -=1
    uuidbin.close()


if __name__ == '__main__':
    devid_damon()

