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
import gc

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
def refresh_time(sock,timer_queue,errqueue,refresh_buf):
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
                      errqueue.put(','.join(['sock','%d'% sock.fileno(),' closed,refresh_time']))
class DevicesFunc():
    def __init__(self,host,uuid,errqueue,statqueue):
        #threading.Thread.__init__(devclass)
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.sock.settimeout(None)
        self.mysock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.mynum = 0
        self.refresh_buf = binascii.unhexlify(''.join(stun_struct_refresh_request()))
        self.timer_queue = Queue()
        self.fileno = self.sock.fileno()
        self.host = host
        self.uuid = uuid
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.fileno = self.sock.fileno()
        self.recv = ''
        self.sbuf = ''
        self.start()

    def start(self):
        n = time.time()
        try:
            self.sock.connect(self.host)
        except socket.timeout:
            self.errqueue.put('sock %d timeout %f' % (sock.fileno,time.time()-n))
            return
        except socket.error:
            self.errqueue.put('sock %d socket.error %f' % (sock.fileno,time.time()-n))
            return
        self.sbuf = device_struct_allocate(self.uuid)
        if self.write_sock():
            return
        while True:
            try:
                data = self.sock.recv(SOCK_BUFSIZE)
            except IOError:
                self.errqueue.put('sock %d,recv occur erro' % self.fileno)
                break
            self.timer_queue.put(0)
            if not data:
                self.errqueue.put('sock %d,recv not data' % self.fileno)
                break
            self.recv += binascii.hexlify(data)
            self.process_handle_first()
        self.errqueue.put(','.join(['sock','%d'% self.fileno,' closed,occur error,send packets %d ' % self.mynum]))
        self.sock.close()

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
            if hattr.srcsock == 0xFFFFFFFF:
                self.errqueue.put('sock %d,recv forward packet not srcsock,buf %s' % (self.fileno,hbuf))
                return False
            dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                time.sleep(1)
                self.sbuf = send_data_to_app(self.mysock,dstsock,'02%s' % hattr.sequence[2:])
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
                self.sbuf = send_data_to_app(self.mysock,dstsock,'03%06x' % self.mynum)
            return  self.write_sock()
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
                self.mysock = int(stat[:8],16)
            except KeyError:
                pass
        elif hattr.method == STUN_METHOD_INFO:
            try:
                stat = rdict[STUN_ATTRIBUTE_STATE]
                self.sbuf = send_data_to_app(self.mysock,int(stat[:8],16),'03%06x' % self.mynum)
                return self.write_sock()
            except KeyError:
                self.errqueue.put("sock %d,recv not state" % self.fileno)
        return False
    
    
    
    def write_sock(self):
        if self.sbuf:
            try:
                nbyte = self.sock.send(binascii.unhexlify(''.join(self.sbuf)))
                return False
            except IOError:
                self.errqueue.put('socket %d close,' % self.file)
                return True
            except TypeError:
                self.errqueue.put('send buf is wrong format %s' % self.sbuf)
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

    #statqueue.put(','.join(['Start UUID',uid]))
    #gp = [gevent.spawn(device_login,host,uid) for uid in uulist]
    appname = "thread_devices"
    errqueue = Queue()
    statqueue = Queue()
    errlog = ErrLog('devices_err')
    statlog = StatLog('devices_stat')
    errworker = WorkerThread(errqueue,errlog,)
    errworker.start()
    statworker = WorkerThread(statqueue,statlog)
    statworker.start()

    for uid in uulist:
        it = threading.Thread(target=DevicesFunc,args=(host,uid,errqueue,statqueue))
        it.start()
        time.sleep(0.3)


