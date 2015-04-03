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
import uuid
import sys
import os
import gc
import unittest
import argparse
import errno
import pickle
from binascii import unhexlify,hexlify
from datetime import datetime
import hashlib
from sockbasic import *
#import eventlet
import socket
from multiprocessing import Queue
import threading


def logger_worker(queue,logger):
    while True:
        time.sleep(0.01)
        try:
            msg = queue.get_nowait()
            logger.log(msg)
        except:
            pass

class DevicesFunc():
    def __init__(self,host,uid):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.srcsock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.mynum = 0
        self.refresh_buf = binascii.unhexlify(''.join(stun_struct_refresh_request()))
        self.timer_queue = Queue()
        self.fileno = self.sock.fileno()
        self.host = host
        self.uid = uid
        self.fileno = self.sock.fileno()
        self.recv = ''
        self.sbuf = ''
        self.start()

    def start(self):
        n = time.time()
        try:
            self.sock.connect(self.host)
        except socket.timeout:
            errqueue.put('sock %d timeout %f' % (self.fileno,time.time()-n))
            return
        except socket.error:
            errqueue.put('sock %d socket.error %f' % (self.fileno,time.time()-n))
            return
        self.sbuf = self.device_struct_allocate()
        if self.write_sock():
            return
        while True:
            try:
                data = self.sock.recv(SOCK_BUFSIZE)
            except IOError:
                errqueue.put('sock %d,recv occur erro' % self.fileno)
                break
            self.timer_queue.put(0)
            if not data:
                errqueue.put('sock %d,recv not data' % self.fileno)
                break
            self.recv += binascii.hexlify(data)
            self.process_handle_first()
            time.sleep(0.01)
        errqueue.put(','.join(['sock','%d'% self.fileno,' closed,occur error,send packets %d ' % self.mynum]))
        self.sock.close()

    def process_handle_first(self):
        l = self.recv.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (self.fileno,self.recv))
            return
        plen = len(self.recv)
        if l > 1:
            #errqueue.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (self.fileno,plen,self.recv))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            pos = sum([len(v) for v in split_requests_buf(self.recv)])
            self.recv = self.recv[pos:]
            [self.process_loop(n) for n in  split_requests_buf(self.recv)]
        else: # 找到一个标识，还不知在什么位置
            pos = self.recv.index(HEAD_MAGIC)
            self.recv = self.recv[pos:]
            nlen = int(self.recv[8:12],16) *2
            if len(self.recv) < nlen:
                errqueue.put("sock %d, recv packet not complete, %s" % (self.fileno,self.recv))
                return
            onepack = self.recv[:nlen]
            self.recv = self.recv[nlen:]
            self.process_loop(onepack)


    def process_loop(self,hbuf):
        gc.collect()
        if check_packet_vaild(hbuf): # 校验包头
           errqueue.put(','.join(['sock','%d'% self.fileno,'check_packet_vaild',hbuf]))
           errqueue.put(hbuf)
           return False


        hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            errqueue.put('sock %d,recv wrong head' % self.fileno)
            return False
    
        if  stun_get_type(hattr.method) == STUN_METHOD_SEND:
            if hattr.srcsock == 0xFFFFFFFF:
                errqueue.put('sock %d,recv forward packet not srcsock,buf %s' % (self.fileno,hbuf))
                return False
            dstsock = hattr.srcsock
            self.dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                time.sleep(0.01)
                self.sbuf = self.send_data_to_app('02%s' % hattr.sequence[2:])
                statqueue.put("sock %d,recv app send me num hex(%s), buf %s" % (self.fileno,hattr.sequence[2:],hbuf))
            #下面是我方主动发数据
            elif hattr.sequence[:2] == '02':
                rnum = int(hattr.sequence[2:],16)
                if self.mynum > 0xFFFFFF:
                    self.mynum = 0
                    errqueue.put('socket %d,packet counter is over 0xFFFFFF once' % self.fileno)
                elif self.mynum == rnum:
                    self.mynum +=1
                    statqueue.put("sock %d,recv my confirm num %d is ok,data %s" % (self.fileno,rnum,hbuf))
                else:
                    errqueue.put('sock %d,losing packet,recv  number  %d, my counter %d' % (self.fileno,rnum,self.mynum))
                self.sbuf = self.send_data_to_app('03%06x' % self.mynum)
            return  self.write_sock()
        p = parser_stun_package(hbuf[STUN_HEADER_LENGTH:-8])
        if not p:
            statqueue.put(','.join(['sock','%d' % self.fileno,'server packet is wrong,rdict is empty']))
            return False # 出错了
    
    
        if not stun_is_success_response_str(hattr.method):
                errqueue.put(','.join(['sock','%d' % self.fileno,'server error responses',\
                        'method',hattr.method]))
                return False
    
        hattr.method = stun_get_type(hattr.method)
        rdict = p[0]
        if hattr.method == STUN_METHOD_ALLOCATE:
            #statqueue.put('sock %d, login' % self.fileno)
            statqueue.put('sock %d,uuid %s login' % (self.fileno,self.uid))
            pt = threading.Thread(target=self.retransmit_packet)
            pt.start()
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                self.srcsock = int(stat[:8],16)
            except KeyError:
                pass
        elif hattr.method == STUN_METHOD_INFO:
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                self.dstsock = int(stat[:8],16)
                self.sbuf = self.send_data_to_app('03%06x' % self.mynum)
                return self.write_sock()
            except KeyError:
                errqueue.put("sock %d,recv not state" % self.fileno)
        return False
    
    def retransmit_packet(self):
        n = time.time() + 30
        while True:
            time.sleep(0.01)
            try:
                num = self.timer_queue.get_nowait()
                n = time.time()+30
            except:
                if time.time() > n:
                    try:
                        self.responses = self.stun_send_data_to_devid('03%06x' % self.mynum)
                        self.write_sock()
                        statqueue.put('sock %d ,retransmit_packet %s' % (self.fileno,''.join(self.responses)))
                    except:
                        errqueue.put('sock %d ,retransmit_packet error' % self.fileno)
    
    
    def write_sock(self):
        if self.sbuf:
            try:
                nbyte = self.sock.send(binascii.unhexlify(''.join(self.sbuf)))
                return False
            except IOError:
                errqueue.put('socket %d close,' % self.file)
                return True
            except TypeError:
                errqueue.put('send buf is wrong format %s' % self.sbuf)
                return False

    def device_struct_allocate(self):
        buf = []
        stun_init_command_str(STUN_METHOD_ALLOCATE,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,self.uid)
        filed = "%08x" % UCLIENT_SESSION_LIFETIME
        stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdata'))
        stun_add_fingerprint(buf)
        return buf
    
    
    def send_data_to_app(self,sequence):
        buf = []
        stun_init_command_str(STUN_METHOD_DATA,buf)
        buf[3] = '%08x' % self.srcsock
        buf[4] = '%08x' % self.dstsock
        buf[-1] = sequence
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('mnbvcxzz'))
        stun_add_fingerprint(buf)
        return buf





class APPfunc():
    def __init__(self,addr,uid):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.mynum = 0
        self.timer_queue = Queue()
        self.refresh_buf = binascii.unhexlify(''.join(stun_struct_refresh_request()))
        self.fileno = self.sock.fileno()
        self.srcsock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.responses = []
        self.recv = ''
        self.user = uid
        self.pwd = uid
        self.uid= uid
        self.addr = addr
        self.start()

    def start(self):
        n = time.time()
        try:
            self.sock.connect(self.addr)
        except socket.timeout:
            errqueue.put('sock timeout %d time %f' % (self.fileno,time.time() -n))
            return
        except socket.error:
            errqueue.put('sock error %d time %f' % (self.fileno,time.time() -n))
            return
    
        self.responses = self.stun_register_request()
        if self.socket_write():
            return
        while True:
            try:
                data = self.sock.recv(SOCK_BUFSIZE)
            except IOError:
                break
            self.timer_queue.put(0) 
            if not data:
                errqueue.put('sock %d, recv not data' % self.fileno)
                break
            self.recv += binascii.b2a_hex(data)
            self.process_handle_first()
            time.sleep(0.01)
        errqueue.put(','.join(['sock','%d'% self.fileno,' closed,occur error,send packets %d ' % self.mynum]))
        self.sock.close()

    def process_handle_first(self):
        l = self.recv.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (self.fileno,self.recv))
            return
        plen = len(self.recv)
        if l > 1:
            #errqueue.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (self.fileno,plen,self.recv))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            pos = sum([len(v) for v in split_requests_buf(self.recv)])
            self.recv = self.recv[pos:]
            [self.process_loop(n) for n in  split_requests_buf(self.recv)]
        else: # 找到一个标识，还不知在什么位置
            pos = self.recv.index(HEAD_MAGIC)
            self.recv = self.recv[pos:]
            nlen = int(self.recv[8:12],16) *2
            if len(self.recv) < nlen:
                errqueue.put("sock %d, recv packet not complete, %s" % (self.fileno,self.recv))
                return
            onepack = self.recv[:nlen]
            self.recv = self.recv[nlen:]
            self.process_loop(onepack)


    def process_loop(self,rbuf):
        gc.collect()
        if check_packet_vaild(rbuf): # 校验包头
            errqueue.put(','.join(['sock','%d'% self.fileno,'check_packet_vaild',rbuf]))
            errqueue.put(rbuf)
            return False
    
        hattr = get_packet_head_class(rbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            errqueue.put('sock %d,recv wrong head' % self.fileno)
            return False
     
        if stun_get_type(hattr.method) == STUN_METHOD_DATA: # 小机回应
            if hattr.srcsock == 0xFFFFFFFF:
                errqueue.put('sock %d, recv forward packet not srcsock,buf %s' % (self.fileno,rbuf))
                return False
            self.dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                statqueue.put("recv dev send to me,sock %d, num hex(%s), data: %s" % (self.fileno,hattr.sequence[2:],rbuf))
                self.responses = self.stun_send_data_to_devid('02%s' % hattr.sequence[2:])
            elif hattr.sequence[:2] == '02':
                n = int(hattr.sequence[2:],16)
                if n > 0xFFFFFF:
                    self.mynum = 0
                    errqueue.put('packet counter over 0xFFFFFF once')
                elif n == self.mynum: 
                    self.mynum+=1
                    statqueue.put("sock %d,recv dev confirm num %d ok,data %s" % (self.fileno,n,rbuf))
                else:
                    errqueue.put('sock %d,lost packet,recv num %d,my counter %d' %(self.fileno,n,self.mynum))
                self.responses = self.stun_send_data_to_devid('03%06x' % self.mynum)
                statqueue.put("sock %d,send packet of %d to dev,data %s" % (self.fileno,n,''.join(self.responses)))

            return self.socket_write()
    
        if not stun_is_success_response_str(hattr.method):
            if cmp(hattr.method[-2:],STUN_METHOD_REGISTER[-2:]):
                errqueue.put(','.join(['sock','%d'% self.fileno,'recv server error',\
                        'method',hattr.method,rbuf]))
                return False
            else:
                self.responses = self.stun_login_request()
                return self.socket_write()
    
        hattr.method = stun_get_type(hattr.method)
        p  = parser_stun_package(rbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
        if p is None:
            return False
        rdict = p[0]
        if not cmp(hattr.method,STUN_METHOD_BINDING):
            p = threading.Thread(target=self.retransmit_packet)
            p.start()
            stat = rdict[STUN_ATTRIBUTE_STATE]
            self.srcsock = int(stat[:8],16)
            # 下面绑定一些UUID
            #if len(self.ulist) > 1:
            #    self.responses = stun_bind_uuids(''.join(self.ulist))
            #else:
            statqueue.put('sock %d,uname %s login' % (self.fileno,self.user))
            self.responses= self.stun_bind_single_uuid()
        elif hattr.method == STUN_METHOD_REGISTER:
            self.responses = stun_login_request(self.user,self.pwd)
        elif hattr.method  == STUN_METHOD_REFRESH:
            return False
        elif hattr.method == STUN_METHOD_CHANNEL_BIND:
            # 绑定小机命令o
            try:
                self.dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                if self.dstsock != 0xFFFFFFFF:
                   self.responses = self.stun_send_data_to_devid('03%06x' % self.mynum)
                   statqueue.put('sock %d,start send packet to dev %d,buf %s' % (self.fileno,self.dstsock,''.join(self.responses)))
                else:
                    return False
            except KeyError:
                errqueue.put('sock %d,recv server packet not RUUID ,buf %s' % (self.fileno,rbuf))
     
#            elif rdict.has_key(STUN_ATTRIBUTE_MRUUID):
#                mlist = split_mruuid(rdict[STUN_ATTRIBUTE_MRUUID])
#                for n in mlist:
#                    time.sleep(0.2)
#                    dstsock = int(n[-8:],16)
#                    if dstsock != 0xFFFFFFFF:
#                        pass
#                        #send_forward_buf(sock,srcsock,dstsock)
#                return False
     
        elif hattr.method == STUN_METHOD_INFO:
            try:
                self.dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.responses = self.stun_send_data_to_devid('03%06x' % self.mynum)
                statqueue.put('sock %d,send packet to dev %d,buf %s' % (self.fileno,self.dstsock,rbuf))
            except KeyError:
                errqueue.put("sock %d,recv no RUUID" % self.fileno)
        elif hattr.method == STUN_METHOD_PULL:
            pass
        elif hattr.method == STUN_METHOD_MODIFY:
            pass
        elif hattr.method == STUN_METHOD_DELETE:
            pass
        else:
            pass
        return  self.socket_write()
    
    
    def socket_write(self):
        if self.responses:
            try:
                nbyte = self.sock.send(binascii.unhexlify(''.join(self.responses)))
                #statqueue.put(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))
                #print ''.join(buf)
            except IOError:
                errqueue.put(','.join(['sock','%d'% self.fileno,'closed']))
                return True
            except TypeError:
                errqueue.put('send buf is wrong format %s' % self.responses)
        return False

    def retransmit_packet(self):
        n = time.time() + 10
        while True:
            time.sleep(0.01)
            try:
                num = self.timer_queue.get_nowait()
                n = time.time()+30
            except:
                if time.time() > n:
                    try:
                        self.responses = self.stun_send_data_to_devid('03%06x' % self.mynum)
                        self.socket_write()
                        statqueue.put('sock %d ,retransmit_packet %s' % (self.fileno,''.join(self.responses)))
                    except:
                        errqueue.put('sock %d ,retransmit_packet error' % self.fileno)




    def stun_bind_single_uuid(self):
        buf = []
        stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,self.uid.lower())
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,self.uid.lower())
        stun_add_fingerprint(buf)
        return buf
    
    def stun_register_request(self):
        buf = []
        stun_init_command_str(STUN_METHOD_REGISTER,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(self.user))
        nmac = hashlib.sha256()
        nmac.update(self.pwd)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,nmac.hexdigest())
        stun_add_fingerprint(buf)
        return buf
    
    def stun_login_request(self):
        buf = []
        stun_init_command_str(STUN_METHOD_BINDING,buf)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(self.user))
        obj = hashlib.sha256()
        obj.update(self.pwd)
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,obj.hexdigest())
        #filed = "%08x" % UCLIENT_SESSION_LIFETIME
        filed = "%08x" % 30
        stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
        stun_add_fingerprint(buf)
        #print "login buf is",buf
        return buf
    
    def stun_send_data_to_devid(self,sequence):
        buf = []
        stun_init_command_str(STUN_METHOD_SEND,buf)
        buf[3] = '%08x' % self.srcsock
        buf[4] = '%08x' % self.dstsock
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
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)
    errlog = ErrLog('AppDemo')
    statlog = StatLog('AppDemo')
    errworker = threading.Thread(target=logger_worker,args=(errqueue,errlog))
    #errworker.daemon = True
    errworker.start()
    statworker = threading.Thread(target=logger_worker,args=(statqueue,statlog))
    #statworker.daemon = True
    statworker.start()
    host = ()
    try:
        d = args.srv_host.index(':')
        host = (args.srv_host[:d],int(args.srv_host[d:]))
    except:
        host = (args.srv_host,3478)
    ulist = read_uuid_file(args.uuidfile)
    bind = args.b_count if args.b_count < len(ulist) else len(ulist)
    tbuf = ulist
    bind = 1
    ucount = len(ulist)
    for uid in ulist:
        pt = threading.Thread(target=APPfunc,args=(host,uid))
        #pt.daemon = True
        pt.start()
        time.sleep(0.3)

def DevDemo(args):
    args = make_argument_parser().parse_args()
    if not args.srv_host or not args.uuidfile:
        print make_argument_parser().parse_args(['-h'])
        exit(1)

    errlog = ErrLog('DevDemo')
    statlog = StatLog('DevDemo')

    errworker = threading.Thread(target=logger_worker,args=(errqueue,errlog))
    #errworker.daemon = True
    errworker.start()
    statworker = threading.Thread(target=logger_worker,args=(statqueue,statlog))
    #statworker.daemon = True
    statworker.start()

    host = ()
    try:
        d = args.srv_host.index(':')
        host = (args.srv_host[:d],int(args.srv_host[d:]))
    except:
        host = (args.srv_host,3478)
    uulist = read_uuid_file(args.uuidfile)
    for uid in uulist:
        pt = threading.Thread(target=DevicesFunc,args=(host,uid))
        #pt.daemon = True
        pt.start()
        time.sleep(0.3)
    

errqueue = Queue()
statqueue = Queue()
if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    args.func(args)
#    while True:
#        try:
#            pass
#        except (SystemExit,KeyboardInterrupt):
#            print "Server exit"
#            break




