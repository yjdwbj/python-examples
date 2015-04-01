#!/opt/pypy-2.5.0-src/pypy-c
#-*- coding: utf-8 -*-
#!/opt/pypy-2.5.0-src/pypy-c
#####################################################################
# lcy
#                                                                   #
#                                                                   #
#
#
####################################################################
import socket
import time
import struct
import threading
import uuid
import sys
import os
import gc
import unittest
import argparse
import errno
import pickle
from Queue import Queue
from binascii import unhexlify,hexlify
from datetime import datetime
import hashlib
from sockbasic import *
import asyncore

from select import epoll,EPOLLET,EPOLLIN,EPOLLOUT,EPOLLHUP,EPOLLERR

class WorkerThread(threading.Thread):
    def __init__(self,queue,logger):
        threading.Thread.__init__(self)
        self.queue = queue 
        self.log = logger

    def run(self):
        while True:
            msg = self.queue.get()
            self.log.log(msg)
            time.sleep(0.01)


devqueue = Queue()
appqueue = Queue()

class DevThread():
    EV_IN = EPOLLIN | EPOLLET
    EV_OUT = EPOLLOUT  | EPOLLET
    EV_DISCONNECTED =(EPOLLHUP | EPOLLERR)
    def __init__(self,host,errqueue,statqueue,pqueue):
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.epoll = epoll()
        self.clients = {}
        self.uids = {}
        self.recv = {}
        self.sbuf = {}
        self.numbers = {}
        self.srcsock = {}
        self.dstsock = {}
        self.queue = pqueue
        self.host = host
        self.run()
    
    def run(self):
        while True:
            pa = devqueue.get()
            self.create_new_socket(pa)
            events = self.epoll.poll(1)
            for fileno,event in events:
                print event,fileno
                if event & self.EV_IN:
                    self.handle_read(fileno)
                    self.epoll.modify(fileno,self.EV_OUT)
                elif event & self.EV_OUT:
                    self.clients[fileno].send(unhexlify(''.join(self.sbuf[fileno])))
                    self.epoll.modify(fileno,self.EV_IN)
                elif event & self.EV_DISCONNECTED:
                    pass

    def create_new_socket(self,uid):

        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)

        sock.connect(self.host)
        sock.setblocking(0)
        fd = sock.fileno()
        self.uids[fd] = uid
        self.clients[fd] = sock
        self.recv[fd] = ''
        self.sbuf[fd] = ''
        self.numbers[fd] = 0
        self.srcsock[fd] = 0xFFFFFFFF
        self.dstsock[fd] = 0xFFFFFFFF
        sock.send(unhexlify(''.join(self.device_struct_allocate(fd))))
        self.epoll.register(fd,self.EV_IN)

    def handle_read(self,fileno):
        data = self.clients[fileno].recv(SOCK_BUFSIZE)
        self.recv[fileno] +=  hexlify(data)
        self.process_handle_first(fileno)

    def process_handle_first(self,fileno):
        pbuf = self.recv[fileno]
        l = pbuf.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            self.errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (fileno,pbuf))
            return
        plen = len(pbuf)
        if l > 1:
            #self.errqueue.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            self.statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (fileno,plen,pbuf))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            pos = sum([len(v) for v in split_requests_buf(pbuf)])
            self.recv[fileno] = pbuf[pos:]
            [self.process_loop(n) for n in  split_requests_buf(pbuf)]
        else: # 找到一个标识，还不知在什么位置
            pos = pbuf.index(HEAD_MAGIC)
            self.recv[fileno]  = pbuf[pos:]
            nlen = int(pbuf[8:12],16) *2
            if len(pbuf) < nlen:
                self.errqueue.put("sock %d, recv packet not complete, %s" % (fileno,pbuf))
                return
            onepack = pbuf[:nlen]
            self.recv[fileno] = pbuf[nlen:]
            self.process_loop(onepack,fileno)

    def device_struct_allocate(self,fileno):
        buf = []
        stun_init_command_str(STUN_METHOD_ALLOCATE,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,self.uids[fileno])
        filed = "%08x" % UCLIENT_SESSION_LIFETIME
        stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdata'))
        stun_add_fingerprint(buf)
        return buf
    
    
    def send_data_to_app(self,sequence,fileno):
        buf = []
        stun_init_command_str(STUN_METHOD_DATA,buf)
        buf[3] = '%08x' % self.srcsock[fileno]
        buf[4] = '%08x' % self.dstsock[fileno]
        buf[-1] = sequence
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('mnbvcxzz'))
        stun_add_fingerprint(buf)
        return buf

    def process_loop(self,hbuf,fileno):
        gc.collect()
        if check_packet_vaild(hbuf): # 校验包头
           self.errqueue.put(','.join(['sock','%d'% fileno,'check_packet_vaild',hbuf]))
           self.errqueue.put(hbuf)
           return False


        hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            self.errqueue.put('sock %d,recv wrong head' % fileno)
            return False
    
        if  stun_get_type(hattr.method) == STUN_METHOD_SEND:
            if hattr.srcsock == 0xFFFFFFFF:
                self.errqueue.put('sock %d,recv forward packet not srcsock,buf %s' % (fileno,hbuf))
                return False
            self.dstsock[fileno] = hattr.srcsock
            if hattr.sequence[:2] == '03':
                time.sleep(1)
                self.sbuf = self.send_data_to_app('02%s' % hattr.sequence[2:],fileno)
                self.statqueue.put("sock %d,recv app send me num hex(%s), buf %s" % (fileno,hattr.sequence[2:],hbuf))
            #下面是我方主动发数据
            elif hattr.sequence[:2] == '02':
                rnum = int(hattr.sequence[2:],16)
                if self.numbers[fileno] > 0xFFFFFF:
                    self.numbers[fileno] = 0
                    self.errqueue.put('socket %d,packet counter is over 0xFFFFFF once' % fileno)
                elif self.numbers[fileno] == rnum:
                    self.numbers[fileno] +=1
                    self.statqueue.put("sock %d,recv my confirm num %d is ok,data %s" % (fileno,rnum,hbuf))
                else:
                    self.errqueue.put('sock %d,losing packet,recv  number  %d, my counter %d' % (fileno,rnum,self.numbers[fileno]))
                self.sbuf = self.send_data_to_app('03%06x' % self.numbers[fileno],fileno)
            #return  self.handle_write()
            self.epoll.modify(fileno,self.EV_OUT)
            return
        p = parser_stun_package(hbuf[STUN_HEADER_LENGTH:-8])
        if not p:
            self.statqueue.put(','.join(['sock','%d' % fileno,'server packet is wrong,rdict is empty']))
            return False # 出错了
    
    
        if not stun_is_success_response_str(hattr.method):
                self.errqueue.put(','.join(['sock','%d' % fileno,'server error responses',\
                        'method',hattr.method]))
                return False
    
        hattr.method = stun_get_type(hattr.method)
        rdict = p[0]
        if hattr.method == STUN_METHOD_ALLOCATE:
            self.statqueue.put('sock %d, login' % fileno)
            #pt = threading.Thread(target=refresh_time,args=(self.sock,self.timer_queue,errlog,self.refresh_buf))
            #pt.start()
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                self.srcsock[fileno] = int(stat[:8],16)
            except KeyError:
                pass
        elif hattr.method == STUN_METHOD_INFO:
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                self.dstsock[fileno] = int(stat[:8],16)
                self.sbuf = self.send_data_to_app('03%06x' % self.numbers[fileno])
                self.epoll.modify(fileno,self.EV_OUT)
                #return self.handle_write()
                return
            except KeyError:
                self.errqueue.put("sock %d,recv not state" % fileno)
        return False
    
    
    
    def socket_write(self):
        if self.sbuf:
            try:
                nbyte = self.sock.send(binascii.unhexlify(''.join(self.sbuf)))
                return False
            except IOError:
                self.errqueue.put('socket %d close,' % self.fileno)
                return True
            except TypeError:
                self.errqueue.put('send buf is wrong format %s' % self.sbuf)
                return False




class AppThread():
    EV_IN = EPOLLIN | EPOLLET
    EV_OUT = EPOLLOUT  | EPOLLET
    EV_DISCONNECTED =(EPOLLHUP | EPOLLERR)
    def __init__(self,host,errqueue,statqueue):
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.epoll = epoll()
        self.clients = {}
        self.uids = {}
        self.recv = {}
        self.sbuf = {}
        self.numbers = {}
        self.srcsock = {}
        self.dstsock = {}
        self.host = host
        self.users = {}
        self.pwds = {}
        self.run()
    
    def run(self):
        while True:
            pa = appqueue.get()
            self.create_new_socket(pa)
            events = self.epoll.poll(1)
            for fileno,event in events:
                print event,fileno
                if event & self.EV_IN:
                    self.handle_read(fileno)
                    self.epoll.modify(fileno,self.EV_OUT)
                elif event & self.EV_OUT:
                    self.clients[fileno].send(unhexlify(''.join(self.sbuf[fileno])))
                    self.epoll.modify(fileno,self.EV_IN)
                elif event & self.EV_DISCONNECTED:
                    pass

    def create_new_socket(self,pa):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)

        sock.connect(self.host)
        sock.setblocking(0)
        fd = sock.fileno()
        self.users[fd] = pa
        self.pwds[fd] = pa
        self.uids[fd] = pa
        self.clients[fd] = sock
        self.recv[fd] = ''
        self.numbers[fd] = 0
        self.srcsock[fd] = 0xFFFFFFFF
        self.dstsock[fd] = 0xFFFFFFFF
        #sock.send(unhexlify(''.join(self.device_struct_allocate(fd))))
        self.sbuf[fd] = self.stun_register_request(fd)
        #sock.send(unhexlify(''.join(self.stun_register_request(fd))))
        self.epoll.register(fd,self.EV_OUT)


    def handle_read(self,fileno):
        data =  self.clients[fileno].recv(SOCK_BUFSIZE)
        self.recv[fileno] += hexlify(data)
        self.process_handle_first(fileno)

    def process_handle_first(self,fileno):
        pbuf = self.recv[fileno]
        l = pbuf.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            self.errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (fileno,pbuf))
            return
        plen = len(pbuf)
        if l > 1:
            #self.errqueue.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            self.statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (fileno,plen,pbuf))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            pos = sum([len(v) for v in split_requests_buf(pbuf)])
            self.recv[fileno] = pbuf[pos:]
            [self.process_loop(n) for n in  split_requests_buf(pbuf)]
        else: # 找到一个标识，还不知在什么位置
            pos = pbuf.index(HEAD_MAGIC)
            self.recv[fileno]  = pbuf[pos:]
            nlen = int(pbuf[8:12],16) *2
            if len(pbuf) < nlen:
                self.errqueue.put("sock %d, recv packet not complete, %s" % (fileno,pbuf))
                return
            onepack = pbuf[:nlen]
            self.recv[fileno] = pbuf[nlen:]
            self.process_loop(onepack,fileno)

    def process_loop(self,rbuf,fileno):
        if check_packet_vaild(rbuf): # 校验包头
            self.errqueue.put(','.join(['sock','%d'% fileno,'check_packet_vaild',rbuf]))
            self.errqueue.put(rbuf)
            return False
    
        hattr = get_packet_head_class(rbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            self.errqueue.put('sock %d,recv wrong head' % fileno)
            return False
     
        if stun_get_type(hattr.method) == STUN_METHOD_DATA: # 小机回应
            if hattr.srcsock == 0xFFFFFFFF:
                self.errqueue.put('sock %d, recv forward packet not srcsock,buf %s' % (fileno,rbuf))
                return False
            self.dstsock[fileno] = hattr.srcsock
            if hattr.sequence[:2] == '03':
                self.statqueue.put("recv dev send to me,sock %d, num hex(%s), data: %s" % (fileno,hattr.sequence[2:],rbuf))
                time.sleep(1)
                self.sbuf[fileno] = self.stun_send_data_to_devid('02%s' % hattr.sequence[2:],fileno)
            elif hattr.sequence[:2] == '02':
                n = int(hattr.sequence[2:],16)
                if n > 0xFFFFFF:
                    self.numbers[fileno] = 0
                    self.errqueue.put('packet counter over 0xFFFFFF once')
                elif n == self.numbers[fileno]: 
                    self.numbers[fileno]+=1
                    self.statqueue.put("sock %d,recv dev confirm num %d ok,data %s" % (fileno,n,rbuf))
                else:
                    self.errqueue.put('sock %d,lost packet,recv num %d,my counter %d' %(fileno,n,self.numbers[fileno]),fileno)
                self.sbuf[fileno] = self.stun_send_data_to_devid('03%06x' % self.numbers[fileno])
                self.statqueue.put("sock %d,send packet of %d to dev,data %s" % (fileno,n,''.join(self.sbuf[fileno])))

            return self.epoll.modify(fileno,self.EV_OUT)
    
        if not stun_is_success_response_str(hattr.method):
            if cmp(hattr.method[-2:],STUN_METHOD_REGISTER[-2:]):
                self.errqueue.put(','.join(['sock','%d'% fileno,'recv server error',\
                        'method',hattr.method,rbuf]))
                return False
            else:
                self.sbuf[fileno] = self.stun_login_request(fileno)
                return self.epoll.modify(fileno,self.EV_OUT)
    
        hattr.method = stun_get_type(hattr.method)
        p  = parser_stun_package(rbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
        if p is None:
            return False
        rdict = p[0]
        if not cmp(hattr.method,STUN_METHOD_BINDING):
            #p = threading.Thread(target=refresh_time,args=(self.sock,self.timer_queue,self.errlog,self.refresh_buf))
            #p.start()
            stat = rdict[STUN_ATTRIBUTE_STATE]
            self.srcsock[fileno]= int(stat[:8],16)
            # 下面绑定一些UUID
            #if len(self.ulist) > 1:
            #    self.sbuf[fileno] = stun_bind_uuids(''.join(self.ulist))
            #else:
            self.sbuf[fileno]= self.stun_bind_single_uuid(fileno)
        elif hattr.method == STUN_METHOD_REGISTER:
            self.sbuf[fileno] = self.stun_login_request(fileno)
        elif hattr.method  == STUN_METHOD_REFRESH:
            return False
        elif hattr.method == STUN_METHOD_CHANNEL_BIND:
            # 绑定小机命令o
            try:
                dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.dstsock[fileno] = dstsock
                if dstsock != 0xFFFFFFFF:
                   self.sbuf[fileno] = self.stun_send_data_to_devid('03%06x' % self.numbers[fileno],fileno)
                   self.statqueue.put('sock %d,start send packet to dev %d,buf %s' % (fileno,dstsock,''.join(self.sbuf[fileno])))
                else:
                    return False
            except KeyError:
                self.errqueue.put('sock %d,recv server packet not RUUID ,buf %s' % (fileno,rbuf))
     
#            elif rdict.has_key(STUN_ATTRIBUTE_MRUUID):
#                mlist = split_mruuid(rdict[STUN_ATTRIBUTE_MRUUID])
#                for n in mlist:
#                    time.sleep(0.2)
#                    dstsock = int(n[-8:],16)
#                    if dstsock != 0xFFFFFFFF:
#                        pass
#                        #send_forward_buf(sock,mysock,dstsock)
#                return False
     
        elif hattr.method == STUN_METHOD_INFO:
            try:
                self.dstsock[fileno] =  int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.sbuf[fileno] = self.stun_send_data_to_devid('03%06x' % self.numbers[fileno],fileno)
                self.statqueue.put('sock %d,send packet to dev %d,buf %s' % (fileno,self.dstsock[fileno],rbuf))
            except KeyError:
                self.errqueue.put("sock %d,recv no STATE" % fileno)
                print rdict
        elif hattr.method == STUN_METHOD_PULL:
            pass
        elif hattr.method == STUN_METHOD_MODIFY:
            pass
        elif hattr.method == STUN_METHOD_DELETE:
            pass
        else:
            pass
        return  self.epoll.modify(fileno,self.EV_OUT)


    def stun_bind_single_uuid(self,fileno):
        buf = []
        stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
        #jluid = '19357888AA07418584391D0ADB61E7902653716613920FBF'
        #jluid = 'e68cd4167aea4f85a7242031252be15874657374a860a02f'
        stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,self.uids[fileno].lower())
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,self.uids[fileno].lower())
        stun_add_fingerprint(buf)
        return buf
    
    def stun_register_request(self,fileno):
        buf = []
        stun_init_command_str(STUN_METHOD_REGISTER,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(self.users[fileno]))
        nmac = hashlib.sha256()
        nmac.update(self.pwds[fileno])
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,nmac.hexdigest())
        stun_add_fingerprint(buf)
        return buf
    
    def stun_login_request(self,fileno):
        buf = []
        stun_init_command_str(STUN_METHOD_BINDING,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(self.users[fileno]))
        obj = hashlib.sha256()
        obj.update(self.pwds[fileno])
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,obj.hexdigest())
        #filed = "%08x" % UCLIENT_SESSION_LIFETIME
        filed = "%08x" % 30
        stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
        stun_add_fingerprint(buf)
        #print "login buf is",buf
        return buf
    
    def stun_send_data_to_devid(self,sequence,fileno):
        buf = []
        stun_init_command_str(STUN_METHOD_SEND,buf)
        buf[3] = '%08x' % self.srcsock[fileno]
        buf[4] = '%08x' % self.dstsock[fileno]
        buf[-1] = sequence
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('abcdefgh'))
        stun_add_fingerprint(buf)
        return buf

    
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
    while True:
        try:
            ulist.append(pickle.load(fd))
        except EOFError:
            break
    return ulist



def AppDemo(args):
    port = args.srv_host if args.srv_host else 3478
    errqueue = Queue()
    statqueue = Queue()
    errlog = ErrLog('AppDemo')
    statlog = StatLog('AppDemo')
    errworker = WorkerThread(errqueue,errlog,)
    errworker.start()
    statworker = WorkerThread(statqueue,statlog)
    statworker.start()
    uulist = []
    host = ()
    try:
        d = args.srv_host.index(':')
        host = (args.srv_host[:d],int(args.srv_host[d:]))
    except:
        host = (args.srv_host,3478)
    ulist = read_uuid_file(args.uuidfile)
    bind = args.b_count if args.b_count < len(ulist) else len(ulist)
    tbuf = ulist
    #mqueue = Manager().Queue()
    #mqueue = stl.channel()
    #et = Process(target=EpollHandler,args=(errqueue,statqueue,mqueue))
    #et.daemon = True
    #et.start()
    ap = threading.Thread(target=AppThread,args=(host,errqueue,statqueue))
    ap.daemon = True
    ap.start()
    for i in xrange(args.u_count):
       cuts = [bind]
       muuid = [tbuf[i:j] for i,j in zip([0]+cuts,cuts+[None])]
       if len(muuid) == 2:
           #stackless.tasklet(stun_setLogin)(host,muuid[0],uname,uname)
           #mulpool.apply_async(stun_setLogin,args=(host,muuid[0],uname,uname))
           #glist.append(gevent.spawn(stun_setLogin,host,muuid[0],uname,uname))
           uname = muuid[0][0]
           appqueue.put(uname)
           tbuf = muuid[-1] if len(muuid[-1]) > bind else muuid[-1]+ulist
    ap.join()

def DevDemo(args):
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)


    errqueue = Queue()
    statqueue = Queue()
    errlog = ErrLog('DevDemo')
    statlog = StatLog('DevDemo')
    errworker = WorkerThread(errqueue,errlog,)
    errworker.start()
    statworker = WorkerThread(statqueue,statlog)
    statworker.start()

    host = ()
    try:
        d = args.srv_host.index(':')
        host = (args.srv_host[:d],int(args.srv_host[d:]))
    except:
        host = (args.srv_host,3478)
    uulist = read_uuid_file(args.uuidfile)
    pqueue = Queue()
    mainThread = threading.Thread(target=DevThread,args=(host,errqueue,statqueue,pqueue))
    mainThread.daemon = True
    mainThread.start()
    for uid in uulist:
        devqueue.put_nowait(uid)
        print uid
        #apps = DevSocket(host,uid,errqueue,statqueue)
    mainThread.join()
    

if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    args.func(args)



