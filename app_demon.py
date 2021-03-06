#!/bin/python2
#coding=utf-8
import socket
import binascii
import logging
import random
import struct
import zlib
import string
import threading
import time
import hmac
import hashlib
import uuid,pickle
import argparse
from epoll_global import *
import logging
from logging import handlers
import signal
import select
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

class ThreadRefreshTime(threading.Thread):
    def __init__(self,sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self.rtime = binascii.unhexlify(''.join(stun_struct_refresh_request()))
        log.info(','.join([self.name,'Starting refresh','sock %d' % sock.fileno()]))
        self._stopevent =threading.Event()

    def run(self):
        global rtime 
        while self.sock:
            time.sleep(1)
            lock.acquire()
            rtime += 1
            lock.release()
            if rtime == REFRESH_TIME:
                rtime = 0
                try:
                    nbyte = self.sock.send(self.rtime)
                    log.info(','.join(['sock','%d'%self.sock.fileno(),'refresh send: %d' % nbyte]))
                except:
                    log.info(','.join([self.name,'Exiting']))
                    break

    def stop(self):
        log.info(','.join([self.name,'Exiting','sock %d' % self.sock.fileno()]))
        self.sock.close()


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
    stun_add_fingerprint(buf)
    return buf

def stun_send_data_to_devid(srcsock,dstsock):
    buf = []
    stun_init_command_str(STUN_METHOD_SEND,buf)
    buf[3] = '%08x' % srcsock
    buf[4] = '%08x' % dstsock
    buf[-1] = '03000000'
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify('testdatatestdata'))
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

def stun_contract_allocate_request(buf):
    stun_init_command_str(STUN_METHOD_BINDING,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify("lcy"))
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)


def stun_struct_refresh_request():
    buf = []
    stun_init_command_str(STUN_METHOD_REFRESH,buf)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    return buf
########## handle response packets ##############
def handle_connect_devid(conn,uid,uname,pwd):
    global last_request
    buf = []
    response_result = []
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    buf = stun_connect_peer_with_uuid(uid,'test','1234')
    sdata = binascii.a2b_hex(''.join(buf))
    last_request = buf
    sock.connect(conn)
    sock.send(sdata)
    while True:
        data,addr = sock.recvfrom(2048)
        if not data:
            break
        else:
            myrecv = binascii.b2a_hex(data)
            print "data  new ",myrecv
            rdict = stun_handle_response(myrecv,response_result)
            if rdict.has_key(STUN_ATTRIBUTE_MESSAGE_ERROR_CODE):
                print "Message Error",rdict[STUN_ATTRIBUTE_MESSAGE_ERROR_CODE][-1]
                break
    sock.close()




def connect_devid_from_file(host,port):
    ufile = open('uuid.bin','r')
    while True:
        try:
            rid = pickle.load(ufile)
            t = threading.Thread(target=handle_connect_devid,args=((host,port),binascii.hexlify(rid),'lcy','test'))
            t.start()
        except EOFError:
            break
    ufile.close()

def test_bind_ten_random_devid():
    n = 10
    u = ''
    while n > 0:
        u = ''.join([u,gen_random_jluuid()])
        n -=1
    print 'ten uuids',u
    return u


def stun_setLogin((addr),ulist,user,pwd):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    buf = stun_register_request(user,pwd)
    sdata = binascii.a2b_hex(''.join(buf))
    sock.bind(('',0))
    try:
        sock.connect(addr)
    except:
        log.info(','.join(['sock %d' % sock.fileno(),'connect timeout']))
        return
    sock.send(sdata)
    log.info(','.join(['sock','%d'%sock.fileno(),'send']))
    fileno = sock.fileno()
    mysock = 0
    buf = ''
    global rtime
    lock = threading.Lock()
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
            myrecv = binascii.b2a_hex(data)
            log.info(','.join(['sock','%d'%sock.fileno(),'recv: %d' % (len(myrecv)/2)]))
            if check_packet_vaild(myrecv): # 校验包头
                log.info(','.join(['sock','%d'% fileno,'recv unkown packet']))
                break

            hattr = get_packet_head_class(myrecv[:STUN_HEADER_LENGTH*2])

            rdict = parser_stun_package(myrecv[STUN_HEADER_LENGTH*2:-8]) # 去头去尾
            if hattr.method == STUN_METHOD_DATA or hattr.method == STUN_METHOD_INFO:
                pass
            else:
                if not stun_is_success_response_str(hattr.method):
                    log.info(','.join(['sock','%d'% fileno,'recv server error',\
                            'method',hattr.method]))
                    if rdict.has_key(STUN_ATTRIBUTE_MESSAGE_ERROR_CODE):
                        print errDict.get(rdict[STUN_ATTRIBUTE_MESSAGE_ERROR_CODE][-1][:4])
                    break

            hattr.method = stun_get_type(hattr.method)
            if hattr.method  == STUN_METHOD_BINDING:
                refresh  = ThreadRefreshTime(sock)
                refresh.setDaemon(True)
                refresh.start()
                
                stat = rdict[STUN_ATTRIBUTE_STATE][-1]
                mysock = int(stat[:8],16)
                # 下面绑定一些UUID
                if len(ulist) > 1:
                    buf = stun_bind_uuids(''.join(ulist))
                else:
                    buf = stun_bind_single_uuid(ulist[0])
            elif hattr.method == STUN_METHOD_REGISTER:
                buf = stun_login_request(user,pwd)
            elif hattr.method  == STUN_METHOD_REFRESH:
                continue
            elif hattr.method == STUN_METHOD_CHANNEL_BIND:
                # 绑定小机命令o
                if rdict.has_key(STUN_ATTRIBUTE_RUUID):
                    dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-1][-8:],16)
                    if dstsock != 0xFFFFFFFF:
                        buf = stun_send_data_to_devid(mysock,dstsock)
                    else:
                        continue

                elif rdict.has_key(STUN_ATTRIBUTE_MRUUID):
                    mlist = split_mruuid(rdict[STUN_ATTRIBUTE_MRUUID])
                    for n in mlist:
                        time.sleep(0.2)
                        dstsock = int(n[-8:],16)
                        if dstsock != 0xFFFFFFFF:
                            send_forward_buf(sock,mysock,dstsock)
                    continue

            elif hattr.method == STUN_METHOD_DATA:
                #print "recv device peer data",time.time()
                dstsock = int(hattr.srcsock,16)
                buf = stun_send_data_to_devid(mysock,dstsock)
                log.info(','.join(['sock','%d'% fileno,'recv forward buf']))
            elif hattr.method == STUN_METHOD_INFO:
                log.info(','.join(['sock','%d'% fileno,'recv server info']))
                if rdict.has_key(STUN_ATTRIBUTE_RUUID):
                    dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-1][-8:],16)
                    buf = stun_send_data_to_devid(mysock,dstsock)
            else:
                print "Command error"
            if buf:
                try:
                    nbyte = sock.send(binascii.unhexlify(''.join(buf)))
                    buf = []
                    log.info(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))
                except:
                    break
    log.info(','.join(['sock','%d'% fileno,'already closed']))
    sock.close()

def send_forward_buf(sock,srcsock,dstsock):
    buf = stun_send_data_to_devid(srcsock,dstsock)
    print "send forward buf"
    nbyte = sock.send(binascii.unhexlify(''.join(buf)))
    log.info(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))


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
log = logging.getLogger(appname)
log.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
file_handler = handlers.RotatingFileHandler('%s.log' % appname,maxBytes=LOG_SIZE,backupCount=LOG_COUNT,encoding=None)

file_handler.setFormatter(formatter)
log.addHandler(file_handler)
#log.addHandler(logging.StreamHandler())
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
   log.info(','.join([appname,'Start']))
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
   log.info(','.join(['UUID counts','%d' % len(ulist),'(per user)bind count %d' % bind]))

   tbuf = ulist
   tt = 0 
   for i in xrange(args.u_count):
       time.sleep(0.3)
       z = str(uuid.uuid4()).replace('-','')
       n = random.randint(0,15)
       zi = []
       for y in xrange(n):
           zi.append(chr(random.randint(97,122)))
       uname = ''.join([z,''.join(zi)])
       cuts = [bind]
       muuid = [tbuf[i:j] for i,j in zip([0]+cuts,cuts+[None])]

       if len(muuid) == 2:
           # start threading
           t = threading.Thread(target =stun_setLogin,args=(host,muuid[0],uname,uname))
           t.setDaemon(True)
           t.start()
           tlist.append(t)
           log.info(','.join(['user:%s' % uname,'pwd:%s' % uname,'Starting %s' % t.name]))
           tbuf = muuid[-1] if len(muuid[-1]) > bind else muuid[-1]+ulist

   signal.signal(signal.SIGINT,signal_handler)
   print(u'Press Ctrl+c')
   signal.pause()

           
           
