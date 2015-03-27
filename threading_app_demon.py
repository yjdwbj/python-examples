#!/opt/pypy-2.5.0-src/pypy-c
#coding=utf-8
#!/opt/stackless-279/bin/python
import socket
import binascii
import logging
import random
import struct
import zlib
import string
import time
import hmac
import hashlib
import uuid,pickle
import argparse
import signal
import sys,os
from multiprocessing import Queue
import threading
from sockbasic import *
import gc

reload(sys)
sys.setdefaultencoding("utf-8")


def stun_register_request(uname,pwd):
    buf = []
    stun_init_command_str(STUN_METHOD_REGISTER,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    nmac = hashlib.sha256()
    nmac.update(pwd)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,nmac.hexdigest())
    stun_add_fingerprint(buf)
    return buf

def stun_login_request(uname,pwd):
    buf = []
    stun_init_command_str(STUN_METHOD_BINDING,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    obj = hashlib.sha256()
    obj.update(pwd)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,obj.hexdigest())
    #filed = "%08x" % UCLIENT_SESSION_LIFETIME
    filed = "%08x" % 30
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    #print "login buf is",buf
    return buf


def stun_bind_uuids(jluids):
    buf = []
    stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
    #u1 = '19357888AA07418584391D0ADB61E7902653716613920FBF'
    #jluid = 'e68cd4167aea4f85a7242031252be15874657374a860a02f'
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_MUUID,''.join([u1.lower(),jluid]))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MUUID,jluids)
    stun_add_fingerprint(buf)
    return buf

def stun_bind_single_uuid(jluid):
    buf = []
    stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
    #jluid = '19357888AA07418584391D0ADB61E7902653716613920FBF'
    #jluid = 'e68cd4167aea4f85a7242031252be15874657374a860a02f'
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,jluid.lower())
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,jluid.lower())
    stun_add_fingerprint(buf)
    return buf

def stun_modify_bind(jluid):
    buf = []
    stun_init_command_str(STUN_METHOD_MODIFY,buf)
    #jluid = '19357888AA07418584391D0ADB61E7902653716613920FBF'
    #jluid = 'e68cd4167aea4f85a7242031252be15874657374a860a02f'
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,jluid.lower())
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,jluid.lower())
    stun_add_fingerprint(buf)
    return buf

def stun_remove_bind(jluid):
    buf = []
    stun_init_command_str(STUN_METHOD_DELETE,buf)
    #jluid = '19357888AA07418584391D0ADB61E7902653716613920FBF'
    #jluid = 'e68cd4167aea4f85a7242031252be15874657374a860a02f'
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,jluid.lower())
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,jluid.lower())
    stun_add_fingerprint(buf)
    return buf

def stun_send_data_to_devid(srcsock,dstsock,sequence):
    buf = []
    stun_init_command_str(STUN_METHOD_SEND,buf)
    buf[3] = '%08x' % srcsock
    buf[4] = '%08x' % dstsock
    buf[-1] = sequence
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('abcdefgh'))
    stun_add_fingerprint(buf)
    return buf


def stun_connect_peer_with_uuid(uuid,uname,pwd):
    buf = []
    stun_init_command_str(STUN_METHOD_CONNECT,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,uuid)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    obj = hashlib.sha256()
    obj.update(pwd)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,obj.hexdigest())
    stun_add_fingerprint(buf)
    return buf


def stun_struct_refresh_request():
    buf = []
    stun_init_command_str(STUN_METHOD_REFRESH,buf)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    return buf

def stun_pull_user_binds(uname):
    buf = []
    stun_init_command_str(STUN_METHOD_PULL,buf)
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    stun_add_fingerprint(buf)
    return buf
    



def test_bind_ten_random_devid():
    n = 10
    u = ''
    while n > 0:
        u = ''.join([u,gen_random_jluuid()])
        n -=1
    print 'ten uuids',u
    return u

class APPCLASS:
    pass

#class APP(threading.Thread):
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

#def APPfunc(addr,ulist,user,pwd):
class APPfunc():
    def __init__(self,addr,sublst,user,pwd,errqueue,statqueue):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        self.sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,10)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
        self.sock.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,120)
        self.sock.settimeout(SOCK_TIMEOUT)
        self.mynum = 0
        self.timer_queue = Queue()
        self.refresh_buf = binascii.unhexlify(''.join(stun_struct_refresh_request()))
        self.fileno = self.sock.fileno()
        self.mysock = 0xFFFFFFFF
        self.dstsock = 0xFFFFFFFF
        self.responses = []
        self.recv = ''
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.user = user
        self.pwd = pwd
        self.ulist = sublst
        self.addr = addr
        self.start()

    def start(self):
        nums = 100
        while nums > 0:
            n = time.time()
            try:
                self.sock.connect(self.addr)
                break
            except socket.timeout:
                self.errqueue.put('sock timeout %d time %f' % (self.fileno,time.time() -n))
                time.sleep(5)
                continue
            except socket.error:
                self.errqueue.put('sock error %d time %f,sleep 5.0 try again' % (self.fileno,time.time() -n))
                time.sleep(5.0)
                continue
        if not nums:
            return
        
    
        self.responses = stun_register_request(self.user,self.pwd)
        if self.socket_write():
            return
        while True:
            try:
                data = self.sock.recv(SOCK_BUFSIZE)
            except IOError:
                break
            self.timer_queue.put(0) 
            if not data:
                self.errqueue.put('sock %d, recv not data' % self.fileno)
                break
            self.recv += binascii.b2a_hex(data)
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


    def process_loop(self,rbuf):
        gc.collect()
        if check_packet_vaild(rbuf): # 校验包头
            self.errqueue.put(','.join(['sock','%d'% self.fileno,'check_packet_vaild',rbuf]))
            self.errqueue.put(rbuf)
            return False
    
        hattr = get_packet_head_class(rbuf[:STUN_HEADER_LENGTH])
        if not hattr:
            self.errqueue.put('sock %d,recv wrong head' % self.fileno)
            return False
     
        if stun_get_type(hattr.method) == STUN_METHOD_DATA: # 小机回应
            if hattr.srcsock == 0xFFFFFFFF:
                self.errqueue.put('sock %d, recv forward packet not srcsock,buf %s' % (self.fileno,rbuf))
                return False
            dstsock = hattr.srcsock
            if hattr.sequence[:2] == '03':
                self.statqueue.put("recv dev send to me,sock %d, num hex(%s), data: %s" % (self.fileno,hattr.sequence[2:],rbuf))
                time.sleep(1)
                self.responses = stun_send_data_to_devid(self.mysock,dstsock,'02%s' % hattr.sequence[2:])
            elif hattr.sequence[:2] == '02':
                n = int(hattr.sequence[2:],16)
                if n > 0xFFFFFF:
                    self.mynum = 0
                    self.errqueue.put('packet counter over 0xFFFFFF once')
                elif n == self.mynum: 
                    self.mynum+=1
                    self.statqueue.put("sock %d,recv dev confirm num %d ok,data %s" % (self.fileno,n,rbuf))
                else:
                    self.errqueue.put('sock %d,lost packet,recv num %d,my counter %d' %(self.fileno,n,self.mynum))
                self.responses = stun_send_data_to_devid(self.mysock,dstsock,'03%06x' % self.mynum)
                self.statqueue.put("sock %d,send packet of %d to dev,data %s" % (self.fileno,n,''.join(self.responses)))

            return self.socket_write()
    
        if not stun_is_success_response_str(hattr.method):
            if cmp(hattr.method[-2:],STUN_METHOD_REGISTER[-2:]):
                self.errqueue.put(','.join(['sock','%d'% self.fileno,'recv server error',\
                        'method',hattr.method,rbuf]))
                return False
            else:
                self.responses = stun_login_request(self.user,self.pwd)
                return self.socket_write()
    
        hattr.method = stun_get_type(hattr.method)
        p  = parser_stun_package(rbuf[STUN_HEADER_LENGTH:-8]) # 去头去尾
        if p is None:
            return False
        rdict = p[0]
        if not cmp(hattr.method,STUN_METHOD_BINDING):
            #p = threading.Thread(target=refresh_time,args=(self.sock,self.timer_queue,self.errlog,self.refresh_buf))
            #p.start()
            stat = rdict[STUN_ATTRIBUTE_STATE]
            self.mysock = int(stat[:8],16)
            # 下面绑定一些UUID
            #if len(self.ulist) > 1:
            #    self.responses = stun_bind_uuids(''.join(self.ulist))
            #else:
            self.responses= stun_bind_single_uuid(self.ulist[0])
        elif hattr.method == STUN_METHOD_REGISTER:
            self.responses = stun_login_request(self.user,self.pwd)
        elif hattr.method  == STUN_METHOD_REFRESH:
            return False
        elif hattr.method == STUN_METHOD_CHANNEL_BIND:
            # 绑定小机命令o
            try:
                dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                if dstsock != 0xFFFFFFFF:
                   self.responses = stun_send_data_to_devid(self.mysock,dstsock,'03%06x' % self.mynum)
                   self.statqueue.put('sock %d,start send packet to dev %d,buf %s' % (self.fileno,dstsock,''.join(self.responses)))
                else:
                    return False
            except KeyError:
                self.errqueue.put('sock %d,recv server packet not RUUID ,buf %s' % (self.fileno,rbuf))
     
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
                dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-8:],16)
                self.responses = stun_send_data_to_devid(self.mysock,dstsock,'03%06x' % self.mynum)
                self.statqueue.put('sock %d,send packet to dev %d,buf %s' % (self.fileno,dstsock,rbuf))
            except KeyError:
                self.errqueue.put("sock %d,recv no RUUID" % self.fileno)
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
                self.errqueue.put(','.join(['sock','%d'% self.fileno,'closed']))
                return True
            except TypeError:
                self.errqueue.put('send buf is wrong format %s' % self.responses)
        return False


def send_forward_buf(sock,srcsock,dstsock):
    buf = stun_send_data_to_devid(srcsock,dstsock)
    nbyte = sock.send(binascii.unhexlify(''.join(buf)))
    statqueue.put(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))


def make_argument_parser():
    parser = argparse.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
            )
    parser.add_argument
    parser.add_argument('-f',action='store',dest='uuidfile',type=file,\
                help=u'UUID 文件，例如： -f file.bin')
    parser.add_argument('-H',action='store',dest='srv_host',type=str,\
                help=u'服务器地址, 例如: -H 192.168.8.9:3478')
    parser.add_argument('-u',action='store',default=100,dest='u_count',type=int,\
                help=u'随机生成用户个数，例如生成100 用户名： -c 100 . 默认数是100') 
    parser.add_argument('-b',action='store',default=10, dest='b_count',type=int,\
                help=u'每个用户绑定UUID的个数，如果此数大于文件里的数量，使用文件里的数值.默认:10 .例如： -c 10') 
    parser.add_argument('--version',action='version',version=__version__)
    return parser

def signal_handler(signal,frame):
    for n in tlist:
        time.sleep(0.1)
        n.join()
    sys.exit(0)

__version__ = '0.0.1'


ehost = [] # 外部地址
phost = [] # 对端地址

global rtime
rtime = 0
appname = 'app_demon'
tlist = []


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
           p = 3478
       host = (s[0],p)
   else:
       host = (args.srv_host,3478)


   ulist = []
   while True:
       try:
           ulist.append(pickle.load(args.uuidfile))
       except:
           break
   if ulist == []:
       print u'文件里没有UUID'
       exit(1)
   acclist = []
   bind = args.b_count if args.b_count < len(ulist) else len(ulist)
   errqueue = Queue()
   statqueue = Queue()
   errlog = ErrLog('app_demon_err')
   statlog = StatLog('app_demon_stat')
   errworker = WorkerThread(errqueue,errlog,)
   errworker.start()
   statworker = WorkerThread(statqueue,statlog)
   statworker.start()

   tbuf = ulist
   tt = 0 
   glist = []
   for i in xrange(args.u_count):
       #uname  = str(uuid.uuid4()).replace('-','')
       #n = random.randint(0,15)
       zi = []
       #for y in xrange(n):
       #    zi.append(chr(random.randint(97,122)))
       #uname = ''.join([z,''.join(zi)])
       cuts = [bind]
       muuid = [tbuf[i:j] for i,j in zip([0]+cuts,cuts+[None])]
       if len(muuid) == 2:
           #stackless.tasklet(stun_setLogin)(host,muuid[0],uname,uname)
           #mulpool.apply_async(stun_setLogin,args=(host,muuid[0],uname,uname))
           #glist.append(gevent.spawn(stun_setLogin,host,muuid[0],uname,uname))
           uname = muuid[0][0]
           pt = threading.Thread(target=APPfunc,args=(host,muuid[0],uname,uname,errqueue,statqueue))
           pt.start()
           glist.append(pt)
           tbuf = muuid[-1] if len(muuid[-1]) > bind else muuid[-1]+ulist
       time.sleep(0.3)
   #gevent.joinall(glist)
   #stackless.run()


   


           
           
