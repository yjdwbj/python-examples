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



class DevSocket(asyncore.dispatcher):
    def __init__(self,host,uid,errqueue,statqueue):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        self.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        self.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.fd = self.fileno()    
        self.mynum = 0
        self.srcsock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.uid = uid
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.sbuf = ''
        self.host = host
        self.recv = ''
        self.connect(self.host)
#        except socket.timeout:
#            self.errqueue.put('sock %d timeout %f' % (self.fileno,time.time()-n))
#            return None
#        except socket.error:
#            self.errqueue.put('sock %d socket.error %f' % (self.fileno,time.time()-n))
#            return None
#        stl.tasklet(self.run)()
#  
        self.sbuf = self.device_struct_allocate()
        self.handle_write()


    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()
    
    def handle_write(self):
        time.sleep(0.5)
        sent = self.send(unhexlify(''.join(self.sbuf)))

    def writable(self):
        return True

    def handle_read(self):
        data = self.sock.recv(SOCK_BUFSIZE)
        self.recv +=  hexlify(data)
        self.process_handle_first()

    def process_handle_first(self):
         l = self.recv.count(HEAD_MAGIC) #没有找到JL关键字
         if not l:
             self.errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (self.fileno,self.recv))
             return
         plen = len(self.recv)
         if l > 1:
             #self.errqueue.put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
             self.statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (self.fileno,plen,self.recv))
             #hbuf = hbuf[l:] # 从找到标识头开始处理
             pos = sum([len(v) for v in split_requests_buf(self.recv)])
             self.recv = self.recv[pos:]
             [self.process_loop(n) for n in  split_requests_buf(self.recv)]
         else: # 找到一个标识，还不知在什么位置
             pos = self.recv.index(HEAD_MAGIC)
             self.recv = self.recv[pos:]
             nlen = int(self.recv[8:12],16) *2
             if len(self.recv) < nlen:
                 self.errqueue.put("sock %d, recv packet not complete, %s" % (self.fileno,self.recv))
                 return
             onepack = self.recv[:nlen]
             self.recv = self.recv[nlen:]
             self.process_loop(onepack)

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

    def process_loop(self,hbuf):
        gc.collect()
        if check_packet_vaild(hbuf): # 校验包头
           self.errqueue.put(','.join(['sock','%d'% self.fileno,'check_packet_vaild',hbuf]))
           self.errqueue.put(hbuf)
           return False


        hattr = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            self.errqueue.put('sock %d,recv wrong head' % self.fileno)
            return False
    
        if  stun_get_type(hattr.method) == STUN_METHOD_SEND:
            time.sleep(1)
            if hattr.srcsock == 0xFFFFFFFF:
                self.errqueue.put('sock %d,recv forward packet not srcsock,buf %s' % (self.fileno,hbuf))
                return False
            dstsock = hattr.srcsock
            self.dstsock = dstsock
            if hattr.sequence[:2] == '03':
                time.sleep(1)
                self.sbuf = self.send_data_to_app('02%s' % hattr.sequence[2:])
                self.statqueue.put("sock %d,recv app send me num hex(%s), buf %s" % (self.fileno,hattr.sequence[2:],hbuf))
            #下面是我方主动发数据
            elif hattr.sequence[:2] == '02':
                rnum = int(hattr.sequence[2:],16)
                if self.mynum > 0xFFFFFF:
                    self.mynum = 0
                    self.errqueue.put('socket %d,packet counter is over 0xFFFFFF once' % self.fileno)
                elif self.mynum == rnum:
                    self.mynum +=1
                    self.statqueue.put("sock %d,recv my confirm num %d is ok,data %s" % (self.fileno,rnum,hbuf))
                else:
                    self.errqueue.put('sock %d,losing packet,recv  number  %d, my counter %d' % (self.fileno,rnum,self.mynum))
                self.sbuf = self.send_data_to_app('03%06x' % self.mynum)
            return  self.handle_write()
        p = parser_stun_package(hbuf[STUN_HEADER_LENGTH:-8])
        if not p:
            self.statqueue.put(','.join(['sock','%d' % self.fileno,'server packet is wrong,rdict is empty']))
            return False # 出错了
    
    
        if not stun_is_success_response_str(hattr.method):
                self.errqueue.put(','.join(['sock','%d' % self.fileno,'server error responses',\
                        'method',hattr.method]))
                return False
    
        hattr.method = stun_get_type(hattr.method)
        rdict = p[0]
        if hattr.method == STUN_METHOD_ALLOCATE:
            self.statqueue.put('sock %d, login' % self.fileno)
            #pt = threading.Thread(target=refresh_time,args=(self.sock,self.timer_queue,errlog,self.refresh_buf))
            #pt.start()
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
                return self.handle_write()
            except KeyError:
                self.errqueue.put("sock %d,recv not state" % self.fileno)
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




class AppSocket(asyncore.dispatcher):
    def __init__(self,host,sublst,user,pwd,errqueue,statqueue):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        self.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        self.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.fd = self.fileno()    
        self.mynum = 0
        self.srcsock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.jluid = sublst[0]
        self.user = user
        self.pwd = pwd
        self.host = host
        self.recv =''
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.connect(self.host)
        self.sbuf = self.stun_register_request()
        self.handle_write()

    def handle_read(self):
        data =  self.recv(SOCK_BUFSIZE)
        self.recv += hexlify(data)
        self.process_handle_first()

    def process_handle_first(self):
        l = self.recv.count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            self.errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (self.fd,self.recv))
            return
        plen = len(self.recv)
        if l > 1:
            #self.errqueue.put('sock %d,recv unkown msg %s' % (fd,self.requests[:l])
            self.statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (self.fd,plen,self.recv))
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            pos = sum([len(v) for v in split_requests_buf(self.recv)])
            self.recv = self.recv[pos:]
            [self.process_loop(n) for n in  split_requests_buf(self.recv)]
        else: # 找到一个标识，还不知在什么位置
            pos = self.recv.index(HEAD_MAGIC)
            self.recv = self.recv[pos:]
            nlen = int(self.recv[8:12],16) *2
            if len(self.recv) < nlen:
                self.errqueue.put("sock %d, recv packet not complete, %s" % (self.fd,self.recv))
                return
            onepack = self.recv[:nlen]
            self.recv = self.recv[nlen:]
            self.process_loop(onepack)

    def process_loop(self,rbuf):
        if check_packet_vaild(rbuf): # 校验包头
            self.errqueue.put(','.join(['sock','%d'% self.fd,'check_packet_vaild',rbuf]))
            self.errqueue.put(rbuf)
            return False
    
        hattr = get_packet_head_class(rbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            self.errqueue.put('sock %d,recv wrong head' % self.fd)
            return False
     
        if stun_get_type(hattr.method) == STUN_METHOD_DATA: # 小机回应
            if hattr.srcsock == 0xFFFFFFFF:
                self.errqueue.put('sock %d, recv forward packet not srcsock,buf %s' % (self.fd,rbuf))
                return False
            self.dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                self.statqueue.put("recv dev send to me,sock %d, num hex(%s), data: %s" % (self.fd,hattr.sequence[2:],rbuf))
                time.sleep(1)
                self.sbuf = self.stun_send_data_to_devid('02%s' % hattr.sequence[2:])
            elif hattr.sequence[:2] == '02':
                n = int(hattr.sequence[2:],16)
                if n > 0xFFFFFF:
                    self.mynum = 0
                    self.errqueue.put('packet counter over 0xFFFFFF once')
                elif n == self.mynum: 
                    self.mynum+=1
                    self.statqueue.put("sock %d,recv dev confirm num %d ok,data %s" % (self.fd,n,rbuf))
                else:
                    self.errqueue.put('sock %d,lost packet,recv num %d,my counter %d' %(self.fd,n,self.mynum))
                self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                self.statqueue.put("sock %d,send packet of %d to dev,data %s" % (self.fd,n,''.join(self.sbuf)))

            return self.handle_write()
    
        if not stun_is_success_response_str(hattr.method):
            if cmp(hattr.method[-2:],STUN_METHOD_REGISTER[-2:]):
                self.errqueue.put(','.join(['sock','%d'% self.fd,'recv server error',\
                        'method',hattr.method,rbuf]))
                return False
            else:
                self.sbuf = self.stun_login_request()
                return self.handle_write()
    
        hattr.method = stun_get_type(hattr.method)
        p  = parser_stun_package(rbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
        if p is None:
            return False
        rdict = p[0]
        if not cmp(hattr.method,STUN_METHOD_BINDING):
            #p = threading.Thread(target=refresh_time,args=(self.sock,self.timer_queue,self.errlog,self.refresh_buf))
            #p.start()
            stat = rdict[STUN_ATTRIBUTE_STATE]
            self.srcsock= int(stat[:8],16)
            # 下面绑定一些UUID
            #if len(self.ulist) > 1:
            #    self.sbuf = stun_bind_uuids(''.join(self.ulist))
            #else:
            self.sbuf= self.stun_bind_single_uuid()
        elif hattr.method == STUN_METHOD_REGISTER:
            self.sbuf = self.stun_login_request()
        elif hattr.method  == STUN_METHOD_REFRESH:
            return False
        elif hattr.method == STUN_METHOD_CHANNEL_BIND:
            # 绑定小机命令o
            try:
                dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.dstsock = dstsock
                if dstsock != 0xFFFFFFFF:
                   self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                   self.statqueue.put('sock %d,start send packet to dev %d,buf %s' % (self.fd,dstsock,''.join(self.sbuf)))
                else:
                    return False
            except KeyError:
                self.errqueue.put('sock %d,recv server packet not RUUID ,buf %s' % (self.fd,rbuf))
     
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
                self.dstsock =  int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.sbuf = self.stun_send_data_to_devid('03%06x' % self.mynum)
                self.statqueue.put('sock %d,send packet to dev %d,buf %s' % (self.fd,self.dstsock,rbuf))
            except KeyError:
                self.errqueue.put("sock %d,recv no STATE" % self.fd)
                print rdict
        elif hattr.method == STUN_METHOD_PULL:
            pass
        elif hattr.method == STUN_METHOD_MODIFY:
            pass
        elif hattr.method == STUN_METHOD_DELETE:
            pass
        else:
            pass
        return  self.handle_write()

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()
    
    def handle_write(self):
        time.sleep(0.5)
        sent = self.send(unhexlify(''.join(self.sbuf)))

    def writable(self):
        return True

    def stun_bind_single_uuid(self):
        buf = []
        stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
        #jluid = '19357888AA07418584391D0ADB61E7902653716613920FBF'
        #jluid = 'e68cd4167aea4f85a7242031252be15874657374a860a02f'
        stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,self.jluid.lower())
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,self.jluid.lower())
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
    for i in xrange(args.u_count):
       cuts = [bind]
       muuid = [tbuf[i:j] for i,j in zip([0]+cuts,cuts+[None])]
       if len(muuid) == 2:
           #stackless.tasklet(stun_setLogin)(host,muuid[0],uname,uname)
           #mulpool.apply_async(stun_setLogin,args=(host,muuid[0],uname,uname))
           #glist.append(gevent.spawn(stun_setLogin,host,muuid[0],uname,uname))
           uname = muuid[0][0]
           ap = AppSocket(host,muuid[0],uname,uname,errqueue,statqueue)
           tbuf = muuid[-1] if len(muuid[-1]) > bind else muuid[-1]+ulist
    asyncore.loop(timeout=1,use_poll=True)

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
    for uid in uulist:
        apps = DevSocket(host,uid,errqueue,statqueue)
        print "added uid",uid
    asyncore.loop(timeout=100,use_poll=True)
    

if __name__ == '__main__':
    args = make_argument_parser().parse_args()
    args.func(args)



