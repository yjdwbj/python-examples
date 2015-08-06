#!/opt/stackless-279/bin/python
#-*- coding: utf-8 -*-
#!/opt/pypy-2.5.0-src/pypy-c
#####################################################################
# lcy
#                                                                   #
#                                                                   #
#
#
####################################################################
import time
import struct
import uuid
import sys
import os
import unittest
import argparse
import errno
import pickle
from itertools import *
from collections import OrderedDict
from binascii import unhexlify,hexlify
from datetime import datetime
import hashlib
from sockbasic import *
from random import randint
#import gevent
#from gevent import monkey,socket
#from gevent.pool import Pool
#from gevent.queue import Queue,Empty
import multiprocessing
from ftplib import FTP

#from multiprocessing import Queue
#from multiprocessing.queues import Empty
#monkey.patch_socket(dns=False,aggressive=False)
#monkey.patch_time()
#monkey.patch_os()
#monkey.patch_thread()
#monkey.patch_ssl()
##monkey.patch_all(socket=True,dns=False,time=True,select=False,thread=True,os=True,ssl=False,httplib=False,subprocess=False,aggressive=True)
import threading

#FTP_HOST='192.168.25.105'
FTP_HOST='ftp.jieli.net'

def logger_worker(queue,logger):
    #n = time.time() + 120
    while 1:
        #if time.time() > n:
        #    break
        for x in xrange(300):
            try:
                msg = queue.get_nowait()
                logger.log(msg)
                #n = time.time() + 120
            except Empty:
                break
        gevent.sleep(0)

def upload_ftp(host,uname,pwd,fname):
    ftp = FTP(host)
    ftp.login(uname,pwd)
    ftp.storbinary('STOR %s' % fname,open(fname,'rb'),2048)
    ftp.quit()

def down_ftp(host,uname,pwd,fname):
    ftp = FTP(host)
    ftp.login(uname,pwd)
    ftp.retrbinary('RETR %s' % fname,open(fname,'wb').write)
    ftp.delete(fname)
    ftp.quit()

def get_md5_digest(fname):
    digest = None
    try:
        with open(fname) as f:
            digest = hashlib.md5(f.read()).hexdigest()
    except IOError:
        return None
    return digest

def cmp_md5_digest(fname,digest):
    b = False
    try:
        with open(fname) as f:
            b = cmp(hashlib.md5(f.read()).hexdigest(),digest)
    except IOError:
        return True
    return b
        


class DevicesFunc():
    global host
    def __init__(self,uid):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        #self.sock.setsockopt(socket.SOL_SOCKET,socket.TCP_NODELAY,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.srcsock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.mynum = 0
        self.add_queue = Queue()
        self.rm_queue = Queue()
        self.retry_t = None
        self.fileno = self.sock.fileno()
        self.host = host
        self.uid = uid
        self.recv = ''
        self.sbuf = ''
        self.retry = 50
        self.ftpuser = ''
        self.ftpwd = ''
        self.start()

    def start(self):
        while 1:
            n = time.time()
            rt = randint(5,120)
            try:
                self.sock.connect(self.host)
            except socket.timeout:
                #qdict.err.put('sock connect timeout %d time %f,sleep %d retry' % (self.fileno,time.time() -n,rt))
                #gevent.sleep(rt)
                continue
            except socket.error:
                #qdict.err.put('sock connect error %d time %f,sleep %d retry' % (self.fileno,time.time() -n,rt))
                #gevent.sleep(rt)
                continue
            else:
                break
        
        self.sbuf = self.device_struct_allocate()
        print hexlify(self.sbuf)
        exit()
        if self.write_sock():
            devreconn.put_nowait(self.uid)
            return

        while 1:
            try:
                data = self.sock.recv(SOCK_BUFSIZE)
            except IOError:
                if n:
                    n -=1
                    gevent.sleep(0.1)
                    continue
                else:
                    qdict.err.put('sock %d,recv occur erro' % self.fileno)
                    break
            if not data:
                qdict.err.put('sock %d,recv not data ' % self.fileno)
                break
            self.recv += hexlify(data)
            del data
            if self.process_handle_first():
                break
            gevent.sleep(0)
        qdict.err.put(','.join(['sock','%d'% self.fileno,' closed,occur error, send packets %d ' % self.mynum]))
        self.sock.close()
        devreconn.put_nowait(self.uid)

    def process_handle_first(self):
        l = self.recv.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            qdict.err.put('sock %d, recv no HEAD_MAGIC packet %s' % (self.fileno,self.recv))
            return
        plen = len(self.recv)
        if l > 1:
            #qdict.err.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            #qdict.state.put("sock %d,recv multi buf,len %d, buf: %s" % (self.fileno,plen,self.recv))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            mulist = split_requests_buf(self.recv)
            pos = sum([len(v) for v in mulist])
            self.recv = self.recv[pos:]
            [self.process_loop(n) for n in  mulist]
            del mulist[:]
            del mulist
            #gevent.sleep(0.1)
        else: # 找到一个标识，还不知在什么位置
            pos = self.recv.index(HEAD_MAGIC)
            self.recv = self.recv[pos:]
            nlen = int(self.recv[8:12],16) *2
            if len(self.recv) < nlen:
                qdict.err.put("sock %d, recv packet not complete, %s" % (self.fileno,self.recv))
                return
            onepack = self.recv[:nlen]
            self.recv = self.recv[nlen:]
            ret = self.process_loop(onepack)
            del onepack
            return ret


    def process_loop(self,hbuf):
        if check_packet_vaild(hbuf): # 校验包头
           qdict.err.put(','.join(['sock','%d'% self.fileno,'check_packet_vaild',hbuf]))
           qdict.err.put(hbuf)
           return False


        hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            qdict.err.put('sock %d,recv wrong head,buf: %s' % (self.fileno,hbuf[:STUN_HEADER_LENGTH]))
            return False
    
        #retmethod = stun_get_type(hattr.method)
        if  not cmp(stun_get_type(hattr.method),STUN_METHOD_SEND):
        #if  not cmp(retmethod,STUN_METHOD_SEND) or not cmp(retmethod,STUN_METHOD_DATA):
            if hattr.srcsock == 0xFFFFFFFF:
                qdict.err.put('sock %d,recv forward packet not srcsock,buf %s' % (self.fileno,hbuf))
                return False
            dstsock = hattr.srcsock
            self.dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                #qdict.recv.put("recv: %s,sock %d,recv from app number of hex(%s); buf: %s" % (str(self.sock.getsockname()),self.fileno,hattr.sequence[2:],hbuf))
                p  = parser_stun_package(hbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
                if p is None:
                    print "appfunc parser_stun_package is None",hbuf
                    return False
                rdict = p[0]
                del p
                d = unhexlify(rdict[STUN_ATTRIBUTE_DATA])
                if d.index('ftp'):
                    glist = d.split(':')
                    down_ftp(FTP_HOST,glist[2],glist[3],glist[4])
                    self.ftpuser = glist[2]
                    self.ftpwd = glist[3]
                    if not cmp_md5_digest(glist[4],glist[5]):
                        print glist[5]
                    else:
                        print "digest error"
                
                self.sbuf = self.send_data_to_app('02%s' % hattr.sequence[2:8])
                #qdict.send.put("send: sock %d,send confirm packet to app;data: %s" % (self.fileno,self.sbuf))
            #下面是我方主动发数据
            elif hattr.sequence[:2] == '02':
                rnum = int(hattr.sequence[2:],16)
                if self.mynum > 0xFFFFFF:
                    self.mynum = 0
                    qdict.err.put('socket %d,packet counter is over 0xFFFFFF once' % self.fileno)
                elif self.mynum == rnum:
                    self.mynum +=1
                    #qdict.confirm.put("confirm: %s,sock %d,recv my confirm num %d is ok;data: %s" % (str(self.sock.getsockname()),self.fileno,rnum,hbuf))
                    self.rm_queue.put(0)
                else:
                    #qdict.lost.put('lost: sock %d,losing packet,recv  number  %d, my counter %d;data %s' % (self.fileno,rnum,self.mynum,hbuf))
                    self.rm_queue.put(0)
                    #return False

                self.sbuf = self.send_data_to_app('03%06x' % self.mynum)
                #qdict.send.put("send: sock %d,%s ,to app  sock %d,packet number %d;data: %s" % (self.fileno,str(self.sock.getsockname()),\
                        #self.dstsock,rnum,self.sbuf))
                self.add_queue.put(0)
            for m in STUN_HEAD_KEY:
                hattr.__dict__.pop(m,None)
            return  self.write_sock()

        p = parser_stun_package(hbuf[STUN_HEADER_LENGTH:-8])
        if not p:
            print "devfunc parser_stun_package is None",rbuf
            qdict.state.put(','.join(['sock','%d' % self.fileno,'server packet is wrong,rdict is empty']))
            return False # 出错了
    
    
        if not stun_is_success_response_str(hattr.method):
                qdict.err.put(','.join(['sock','%d' % self.fileno,'server error sbuf',\
                        'method,',hattr.method,hbuf]))
                return False
    
        hattr.method = stun_get_type(hattr.method)
        rdict = p[0]
        del p
        if hattr.method == STUN_METHOD_ALLOCATE:
            #qdict.state.put('sock %d, login' % self.fileno)
            """
            登录成功
            """
            #qdict.state.put('sock %d,uuid %s login' % (self.fileno,self.uid))
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                self.srcsock = int(stat[:8],16)
            except KeyError:
                qdict.err.put('sock %d,login not my sock fileno,retry login' % self.fileno)
                self.sbuf = self.device_struct_allocate()
                rdict.clear()
                del rdict
                for m in STUN_HEAD_KEY:
                    hattr.__dict__.pop(m,None)
                return self.write_sock()
        elif hattr.method == STUN_METHOD_INFO:
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
            except KeyError:
                qdict.err.put("sock %d,recv not state,%s,rdict %s" % (self.fileno,str(self.sock.getsockname()),hbuf))
            else:
                self.dstsock = int(stat[:8],16)
                self.sbuf = self.send_data_to_app('03%06x' % self.mynum)
                #qdict.send.put("send: sock %d,start send packet to app;data: %s" % (self.fileno,self.sbuf))
                if not self.retry_t:
                    self.retry_t  = threading.Thread(target=self.retransmit_packet)
                    self.retry_t.start()
                self.add_queue.put(0)
                rdict.clear()
                del rdict
                for m in STUN_HEAD_KEY:
                    hattr.__dict__.pop(m,None)
                return self.write_sock()
        rdict.clear()
        del rdict
        for m in STUN_HEAD_KEY:
            hattr.__dict__.pop(m,None)
        del hattr
        return False
    
    def retransmit_packet(self):
        while 1:
            gevent.sleep(0.01)
            try:
                p = self.add_queue.get_nowait()
                n = time.time() + randint(30,self.retry)
            except Empty:
                pass
            else:
                while 1:
                    gevent.sleep(0.01)
                    try:
                        rm = self.rm_queue.get_nowait()
                        break
                    except Empty:
                        pass

                    if time.time() > n:
                        if self.write_sock():
                            #devreconn.put_nowait(self.uid)
                            return
                        #qdict.retransmit.put('sock %d ,retransmit_packet ;data:%s' % (self.fileno,self.sbuf))
                        n = time.time() + randint(30,self.retry)
                        """break inside loop"""
                        #except:
                        #    qdict.err.put('sock %d ,retransmit_packet error' % self.fileno)
    
    
    def write_sock(self):
        if self.sbuf:
            try:
                nbyte = self.sock.send(unhexlify(self.sbuf))
                #gevent.sleep(0.01)
            except IOError:
                qdict.err.put('socket %d has closed' % self.fileno)
                return True
            except TypeError:
                qdict.err.put('send buf is wrong format %s' % self.sbuf)
                return True
        return False

    def device_struct_allocate(self):
        #buf = []
        #stun_init_command_str(STUN_METHOD_ALLOCATE,buf)
        od = stun_init_command_head(STUN_METHOD_ALLOCATE)
        stun_attr_append_str(od,STUN_ATTRIBUTE_UUID,self.uid)
        #filed = UCLIENT_SESSION_LIFETIME
        #stun_attr_append_str(od,STUN_ATTRIBUTE_LIFETIME,filed)
        stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,'testdata')
        stun_add_fingerprint(od)
        return ''.join(get_list_from_od(od))
    
    
    def send_data_to_app(self,sequence):
        #stun_init_command_str(STUN_METHOD_DATA,buf)
        od = stun_init_command_head(STUN_METHOD_DATA)
        #buf[3] = '%08x' % self.srcsock
        #buf[4] = '%08x' % self.dstsock
        #buf[-1] = sequence
        od['srcsock']=  self.srcsock
        od['dstsock']= self.dstsock
        od['sequence']=sequence
        #stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,hexlify('%d' % time.time()))
        if (sequence >> 24) == 0x3:
            upfname = 'app_data.bin'
            upload_ftp(FTP_HOST,self.ftpuser,self.ftpwd,upfname)
            digest = get_md5_digest(upfname)
            stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,'%.05f:ftp:%s:%s:%s:%s' % (time.time(),self.ftpuser,self.ftpwd,upfname,digest))
        stun_add_fingerprint(od)
        for n in STUN_HEAD_KEY:
            if not od.has_key(n):
                print 'app packet head miss key %s' % n
        lst = get_list_from_od(od)
        b = ''.join(lst)
        del lst[:]
        del lst
        n = int(b[8:12],16)
        if n*2 != len(b):
            print "len is wrong some msg lost",b
        return b





class APPfunc():
    global host
    def __init__(self,uid):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        #self.sock.setsockopt(socket.SOL_SOCKET,socket.TCP_NODELAY,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.mynum = 0
        self.add_queue = Queue()
        self.rm_queue = Queue()
        self.retry_t = None
        self.fileno = self.sock.fileno()
        self.srcsock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.sbuf = []
        self.recv = ''
        self.user = uid
        self.pwd = uid
        self.uid= uid
        self.addr = host
        self.retry = 50
        self.start()

    def start(self):
        while 1:
            n = time.time()
            #rt = randint(5,120)
            try:
                self.sock.connect(self.addr)
            except socket.timeout:
                #qdict.err.put('sock connect timeout %d time %f,sleep %d retry' % (self.fileno,time.time() -n,rt))
                #gevent.sleep(rt)
                continue
            except socket.error:
                #qdict.err.put('sock connect error %d time %f,sleep %s retry' % (self.fileno,time.time() -n,rt))
                #gevent.sleep(rt)
                continue
            else:
                break
        
        self.sbuf = self.stun_register_request()
        if self.write_sock():
            appreconn.put_nowait(self.uid)
            return
        while 1:
            try:
                data = self.sock.recv(SOCK_BUFSIZE)
            except IOError:
                if n:
                    n -=1
                    gevent.sleep(0.1)
                    continue
                else:
                    qdict.err.put('sock %d, recv IOerror' % self.fileno)
                    break
            if not data:
                qdict.err.put('sock %d, recv not data' % self.fileno)
                break
            self.recv += binascii.b2a_hex(data)
            del data
            if self.process_handle_first():
                break
            gevent.sleep(0)
        #qdict.err.put(','.join(['sock','%d'% self.fileno,' closed,occur error,send packets %d ' % self.mynum]))
        self.sock.close()
        appreconn.put_nowait(self.uid)


    def process_handle_first(self):
        l = self.recv.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            qdict.err.put('sock %d, recv no HEAD_MAGIC packet %s' % (self.fileno,self.recv))
            return False
        plen = len(self.recv)
        if l > 1:
            #qdict.err.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            #qdict.state.put("sock %d,recv multi buf,len %d, buf: %s" % (self.fileno,plen,self.recv))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            mulist = split_requests_buf(self.recv)
            pos = sum([len(v) for v in mulist])
            self.recv = self.recv[pos:]
            [self.process_loop(n) for n in  mulist]
            del mulist[:]
            del mulist
            #gevent.sleep(0.1)
        else: # 找到一个标识，还不知在什么位置
            pos = self.recv.index(HEAD_MAGIC)
            self.recv = self.recv[pos:]
            nlen = int(self.recv[8:12],16) *2
            if len(self.recv) < nlen:
                qdict.err.put("sock %d, recv packet not complete, %s" % (self.fileno,self.recv))
                return False
            onepack = self.recv[:nlen]
            self.recv = self.recv[nlen:]
            ret = self.process_loop(onepack)
            del onepack
            return ret


    def process_loop(self,rbuf):
        if check_packet_vaild(rbuf): # 校验包头
            qdict.err.put(','.join(['sock','%d'% self.fileno,'check_packet_vaild',rbuf]))
            qdict.err.put(rbuf)
            return False
    
        hattr = get_packet_head_class(rbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            qdict.err.put('sock %d,recv wrong head , %s' % (self.fileno,rbuf))
            return False
     
        if not cmp(stun_get_type(hattr.method),STUN_METHOD_DATA): # 小机回应
            if hattr.srcsock == 0xFFFFFFFF:
                qdict.err.put('sock %d, recv forward packet not srcsock,buf %s' % (self.fileno,rbuf))
                return False
            self.dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                #qdict.recv.put("recv: %s,sock %d,recv from  dev  number of  hex(%s); buf: %s" % (str(self.sock.getsockname()),self.fileno,hattr.sequence[2:],rbuf))
                p  = parser_stun_package(rbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
                if p is None:
                    print "appfunc parser_stun_package is None",rbuf
                    return False
                rdict = p[0]
                del p
                d = unhexlify(rdict[STUN_ATTRIBUTE_DATA])
                if d.index('ftp'):
                    glist = d.split(':')
                    down_ftp(FTP_HOST,self.user,self.ftpwd,glist[4])
                    if not cmp_md5_digest(glist[4],glist[5]):
                        print glist[5]
                    else:
                        print "digest is error"
                
                self.sbuf = self.stun_send_data_to_devid('02%s' % hattr.sequence[2:8])
                #qdict.send.put("send: sock %d,send confirm packet to dev,data %s" % (self.fileno,self.sbuf))
            elif hattr.sequence[:2] == '02':
                n = int(hattr.sequence[2:],16)
                if n > 0xFFFFFF:
                    self.mynum = 0
                    qdict.err.put('packet counter over 0xFFFFFF once')
                elif n == self.mynum: 
                    self.mynum+=1
                    #qdict.confirm.put("confirm: %s,sock %d,recv dev confirm num %d ok;data: %s" % (str(self.sock.getsockname()),self.fileno,n,rbuf))
                    self.rm_queue.put(0)
                else:
                    #qdict.lost.put('lost: sock %d,lost packet,recv num %d,my counter %d; data: %s' %(self.fileno,n,self.mynum,rbuf))
                    """收到的包序错了，直接返回"""
                    self.rm_queue.put(0)
                    #return False
                self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                self.add_queue.put(0)
                #qdict.send.put("send: sock %d,send packet of %d to dev;data %s" % (self.fileno,n,self.sbuf))
            for m in STUN_HEAD_KEY:
                hattr.__dict__.pop(m,None)
            del hattr
            return self.write_sock()

    
        if not stun_is_success_response_str(hattr.method):
            if cmp(hattr.method[-2:],STUN_METHOD_REGISTER[-2:]):
                qdict.err.put(','.join(['sock','%d'% self.fileno,'recv server error',\
                        'method',hattr.method,rbuf]))
                return False
            else:
                self.sbuf = self.stun_login_request()
                return self.write_sock()
    
        hattr.method = stun_get_type(hattr.method)
        p  = parser_stun_package(rbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
        if p is None:
            print "appfunc parser_stun_package is None",rbuf
            return False
        rdict = p[0]
        del p
        if not cmp(hattr.method,STUN_METHOD_BINDING):
            stat = rdict[STUN_ATTRIBUTE_STATE]
            self.ftpwd = unhexlify(rdict[STUN_ATTRIBUTE_MESSAGE_INTEGRITY])
            self.srcsock = int(stat[:8],16)
            # 下面绑定一些UUID
            #if len(self.ulist) > 1:
            #    self.sbuf = stun_bind_uuids(''.join(self.ulist))
            #else:
            #qdict.state.put('sock %d,uname %s login' % (self.fileno,self.user))
            self.sbuf= self.stun_bind_single_uuid()
        elif hattr.method == STUN_METHOD_REGISTER:
            self.sbuf = self.stun_login_request()
        elif hattr.method  == STUN_METHOD_REFRESH:
            del rdict
            for m in STUN_HEAD_KEY:
                hattr.__dict__.pop(m,None)
            del hattr
            return False
        elif hattr.method == STUN_METHOD_CHANNEL_BIND:
            # 绑定小机命令o

            # 开启重传线程
            if not self.retry_t:
                self.retry_t  = threading.Thread(target=self.retransmit_packet)
                self.retry_t.start()
            try:
                self.dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                if self.dstsock != 0xFFFFFFFF:
                   self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                   #qdict.send.put('sock %d,start send packet to dev %d;buf %s' % (self.fileno,self.dstsock,self.sbuf))
                   self.add_queue.put(0) 
                else:
                    return False
            except KeyError:
                qdict.err.put('sock %d,recv server bind not RUUID ,buf %s' % (self.fileno,rbuf))
     
     
        elif hattr.method == STUN_METHOD_INFO:
            if not self.retry_t:
                self.retry_t  = threading.Thread(target=self.retransmit_packet)
                self.retry_t.start()
            try:
                self.dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                #qdict.send.put('sock %d,start send packet to dev %d;buf: %s' % (self.fileno,self.dstsock,self.sbuf))
                self.add_queue.put(0) 
            except KeyError:
                self.dstsock = int(rdict[STUN_ATTRIBUTE_STATE][:8],16)  # 这里是对应的sock的下线了
                qdict.err.put('sock %d,recv server info not RUUID,may be dev logout ,buf %s' % (self.fileno,rbuf))
                if self.dstsock:
                    self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                else:
                    return False
     
     
        elif hattr.method == STUN_METHOD_PULL:
            pass
        elif hattr.method == STUN_METHOD_MODIFY:
            pass
        elif hattr.method == STUN_METHOD_DELETE:
            pass
        else:
            pass
        rdict.clear()
        del rdict
        for m in STUN_HEAD_KEY:
            hattr.__dict__.pop(m,None)
        del hattr
        return  self.write_sock()
    
    
    def write_sock(self):
        if self.sbuf:
            try:
                nbyte = self.sock.send(unhexlify(self.sbuf))
                #gevent.sleep(0.01)
                #qdict.state.put(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))
                #print ''.join(buf)
            except IOError:
                qdict.err.put(','.join(['sock','%d'% self.fileno,'closed']))
                return True
            
        return False
            #except TypeError:
            #    qdict.err.put('sock %d,send buf is wrong format %s' % (self.fileno,self.sbuf))

    def retransmit_packet(self):
        while 1:
            gevent.sleep(0.01)
            try:
                p = self.add_queue.get_nowait()
                n = time.time() + self.retry
            except Empty:
                pass
            else:
                while 1:
                    gevent.sleep(0.01)
                    try:
                        n = self.rm_queue.get_nowait()
                    except Empty:
                        pass
                    else:
                        break
                    if time.time() > n:
                        if self.write_sock():
                            #appreconn.put_nowait(self.uid)
                            return
                        #qdict.retransmit.put('sock %d ,retransmit_packet ;data: %s' % (self.fileno,self.sbuf))
                        n = time.time() + self.retry
                        """break inside loop"""
                        #except:
                        #    qdict.err.put('sock %d ,retransmit_packet error' % self.fileno)


    def stun_bind_single_uuid(self):
        #buf = []
        #stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
        od = stun_init_command_head(STUN_METHOD_CHANNEL_BIND)
        stun_attr_append_str(od,STUN_ATTRIBUTE_UUID,self.uid.lower())
        stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,self.uid.lower())
        stun_add_fingerprint(od)
        return ''.join(get_list_from_od(od))
    
    def stun_register_request(self):
        #buf = []
        #stun_init_command_str(STUN_METHOD_REGISTER,buf)
        od = stun_init_command_head(STUN_METHOD_REGISTER)
        stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,hexlify(self.user))
        nmac = hashlib.sha256()
        nmac.update(self.pwd)
        stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,nmac.hexdigest())
        stun_add_fingerprint(od)
        return ''.join(get_list_from_od(od))
    
    def stun_login_request(self):
        #buf = []
        #stun_init_command_str(STUN_METHOD_BINDING,buf)
        od = stun_init_command_head(STUN_METHOD_BINDING)
        stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,hexlify(self.user))
        obj = hashlib.sha256()
        obj.update(self.pwd)
        stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,obj.hexdigest())
        #filed = "%08x" % UCLIENT_SESSION_LIFETIME
        stun_attr_append_str(od,STUN_ATTRIBUTE_LIFETIME,0x23)
        del filed
        stun_add_fingerprint(od)
        return ''.join(get_list_from_od(od))

    
    def stun_send_data_to_devid(self,sequence):
        #buf = []
        #stun_init_command_str(STUN_METHOD_SEND,buf)
        od = stun_init_command_head(STUN_METHOD_SEND)
        od['srcsock']='%08x' % self.srcsock
        od['dstsock']='%08x' % self.dstsock
        od['sequence']= sequence
        if not cmp(sequence[:2],'03'):
            upfname = 'disk_data.bin'
            upload_ftp(FTP_HOST,self.user,self.ftpwd,upfname)
            digest = get_md5_digest(upfname)
            stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,hexlify('%.05f:ftp:%s:%s:%s:%s' % (time.time(),self.user,self.ftpwd,upfname,digest)))
        stun_add_fingerprint(od)
        for n in STUN_HEAD_KEY:
            if not od.has_key(n):
                print 'app packet head miss key %s' % n

        return ''.join(get_list_from_od(od))

    
def make_argument_parser():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter
        )
    subparsers = parser.add_subparsers(help='commands')
    # A list commands
    app_parser = subparsers.add_parser(
            'app',help=u'手机端APP模拟器')
    app_parser.add_argument('-f',action='store',dest='uuidfile',type=file,\
                help=u'UUID 文件，例如： -f file.bin')
    app_parser.add_argument('-H',action='store',dest='srv_host',type=str,\
                help=u'服务器地址, 例如: -H 192.168.8.9:3478')
    app_parser.add_argument('-u',action='store',default=100,dest='u_count',type=int,\
                help=u'随机生成用户个数，例如生成100 用户名： -c 100 . 默认数是100') 
    app_parser.add_argument('-b',action='store',default=10, dest='b_count',type=int,\
                help=u'每个用户绑定UUID的个数，如果此数大于文件里的数量，使用文件里的数值.默认:10 .例如： -c 10') 
    app_parser.set_defaults(func=AppDemo)

    dev_parser = subparsers.add_parser(
                'dev',help=u'小机端模拟器')
    dev_parser.add_argument('-H',action='store',dest='srv_host',type=str,\
            help=u'服务器地址, 端口默认是:3478 ,例如: -H 192.168.8.9:3478')
    dev_parser.add_argument('-f',action='store',dest='uuidfile',type=file,\
                        help=u'UUID的文件，例如： -f file.bin')
    dev_parser.set_defaults(func=DevDemo)
    
    return parser

__version__ = '0.1.0'

def read_uuid_file(fd):
    ulist = []
    while 1:
        try:
            ulist.append(pickle.load(fd))
        except EOFError:
            break
    return ulist



def loopconnect(obj,q):
    while 1:
        gevent.sleep(0.01)
        try:
            p = q.get_nowait()
        except Empty:
            continue
        else:
            if obj == DevicesFunc:
                qdict.err.put('device uid %s reconnection server' % p)
            else:
                qdict.err.put('app uid %s reconnection server' % p)
            gevent.spawn(obj,p)

def chunks(l,n):
    for i in xrange(0,len(l),n):
        yield l[i:i+n]

def subprocess(func,l):
    pool = Pool(len(l))
    for uid in l:
        pool.spawn(func,uid)
    pool.join()

def AppDemo(args):
    global host
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)

    l = args.srv_host.split(':')
    if len(l) == 1 or l[-1] == '':
        host = (args.srv_host,3478)
    else:
        host = (args.srv_host[:d],int(args.srv_host[d:]))
    appworker = threading.Thread(target=loopconnect,args=(APPfunc,appreconn))
    appworker.start()
    ulist = read_uuid_file(args.uuidfile)
    bind = args.b_count if args.b_count < len(ulist) else len(ulist)
    tbuf = ulist
    bind = 1
    usize = len(ulist)
    """
    psize  = multiprocessing.cpu_count()
    if psize > 2:
        subsize = usize / psize
        sublist = chunks(ulist,subsize)
        for sl in sublist:
            multiprocessing.Process(target=subprocess,args=(APPfunc,sl)).start()
    else:
        subprocess(APPfunc,ulist)
    """
    subprocess(APPfunc,ulist)
    #pool.map(APPfunc,ulist)
    #gevent.joinall([gevent.spawn(APPfunc,host,uid) for uid in ulist])

def DevDemo(args):
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)

    global host
    l = args.srv_host.split(':')
    if len(l) == 1 or l[-1] == '':
        host = (args.srv_host,3478)
    else:
        host = (args.srv_host[:d],int(args.srv_host[d:]))
    devworker = threading.Thread(target=loopconnect,args=(DevicesFunc,devreconn))
    devworker.start()
    ulist = read_uuid_file(args.uuidfile)
    usize = len(ulist)
    """
    psize  = multiprocessing.cpu_count()
    if psize > 2:
        subsize = usize / psize
        sublist = chunks(ulist,subsize)
        for sl in sublist:
            multiprocessing.Process(target=subprocess,args=(DevicesFunc,sl)).start()
    else:
        subprocess(DevicesFunc,ulist)
    """
    subprocess(DevicesFunc,ulist)
    #gevent.joinall([gevent.spawn(DevicesFunc,host,uid) for uid in uulist])
    

class A:
    pass

appreconn = Queue()
devreconn = Queue()
global host
if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    name = str(vars(args)['func']).split(' ')[1]
    """
    拆分日志到多个文件中
    """
    qdict = A()
    logdict = A()

    #tt = ['err','state','recv','send','confirm','retransmit','lost']
    tt = ['err','state']
    [setattr(qdict,k,Queue()) for k in tt]
    [setattr(logdict,k,StatLog('_'.join([name,k]))) for k in tt]
    tlist = [threading.Thread(target=logger_worker,args=(q,l)) for (q,l) in izip(qdict.__dict__.values(),logdict.__dict__.values())]
    [n.start() for n in tlist]
    args.func(args)
    [n.join() for n in tlist]





