#!/opt/stackless-279/bin/python
#coding=utf-8
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
from epoll_global import *
import signal
import sys
from multiprocessing import Queue
import threading

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
    stun_add_fingerprint(buf)
    return buf

def stun_send_data_to_devid(srcsock,dstsock,sequence):
    buf = []
    stun_init_command_str(STUN_METHOD_SEND,buf)
    buf[3] = '%08x' % srcsock
    buf[4] = '%08x' % dstsock
    buf[-1] = sequence
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
                    errlog.log(','.join(['sock','%d'% fileno,' closed,occur error,send packets %d ' % mynum]))

def APPfunc(addr,ulist,user,pwd):
#        threading.Thread.__init__(appclass)
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
    sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    sock.settimeout(SOCK_TIMEOUT)
    addr = addr
    ulist = ulist
    user = user
    pwd = pwd
    appname = 'app_demon'
    slog = StatLog(appname)
    errlog = ErrLog(appname)
    mynum = 0
    timer_queue = Queue()
    refresh_buf = binascii.unhexlify(''.join(stun_struct_refresh_request()))
    fileno = sock.fileno()
    mysock = 0xFFFFFFFF
    dstsock = 0xFFFFFFFF
    buf = []
    try:
        sock.connect(addr)
    except socket.timeout:
        errlog.log('sock i %d timeout' % fileno)
        return
    buf = stun_register_request(user,pwd)
    if socket_write(sock,buf,errlog):
        return
    while True:
        try:
            data = sock.recv(SOCK_BUFSIZE)
        except IOError:
            break
        timer_queue.put(0) 
        if not data:
            continue
        myrecv = binascii.b2a_hex(data)
        if check_packet_vaild(myrecv): # 校验包头
            errlog.log(','.join(['sock','%d'% fileno,'recv unkown packet']))
            errlog.log(myrecv)
            continue

        hattr = get_packet_head_class(myrecv[:STUN_HEADER_LENGTH*2])
 
        if stun_get_type(hattr.method) == STUN_METHOD_DATA: # 小机回应
            dstsock = int(hattr.srcsock,16)
            if hattr.sequence[:2] == '03':
                slog.log("recv dev send,sock %d, num hex(%s)" % (fileno,hattr.sequence[2:]))
                time.sleep(1)
                buf = stun_send_data_to_devid(mysock,dstsock,'02%s' % hattr.sequence[2:])
            elif hattr.sequence[:2] == '02':
                n = int(hattr.sequence[2:],16)
                slog.log("sock %d,recv confirm num %d ok" % (fileno,n))
                if n > 0xFFFFFF:
                    mynum = 0
                    errlog.log('packet counter over 0xFFFFFF once')
                elif n == mynum: 
                    mynum+=1
                    #errlog.log("packet number is %d" % mynum)
                else:
                    errlog.log('sock %d,lost packet,recv num %d,my counter %d' %(fileno,n,mynum))
                buf = stun_send_data_to_devid(mysock,dstsock,'03%06x' % mynum)
            if socket_write(sock,buf,errlog):
                break
            continue


        if not stun_is_success_response_str(hattr.method):
            errlog.log(','.join(['sock','%d'% fileno,'recv server error',\
                    'method',hattr.method]))
            continue
        hattr.method = stun_get_type(hattr.method)
        rdict = parser_stun_package(myrecv[STUN_HEADER_LENGTH*2:-8]) # 去头去尾
        if not cmp(hattr.method,STUN_METHOD_BINDING):
            p = threading.Thread(target=refresh_time,args=(sock,timer_queue,errlog,refresh_buf))
            p.start()
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
                   buf = stun_send_data_to_devid(mysock,dstsock,'03%06x' % mynum)
                else:
                    continue
 
            elif rdict.has_key(STUN_ATTRIBUTE_MRUUID):
                mlist = split_mruuid(rdict[STUN_ATTRIBUTE_MRUUID])
                for n in mlist:
                    time.sleep(0.2)
                    dstsock = int(n[-8:],16)
                    if dstsock != 0xFFFFFFFF:
                        pass
                        #send_forward_buf(sock,mysock,dstsock)
                continue
 
        elif hattr.method == STUN_METHOD_INFO:
            slog.log(','.join(['sock','%d'% fileno,'recv server info']))
            try:
                dstsock = int(rdict[STUN_ATTRIBUTE_RUUID][-1][-8:],16)
                buf = stun_send_data_to_devid(mysock,dstsock,'03%06x' % mynum)
            except KeyError:
                pass
        else:
            print "Command error"
        if socket_write(sock,buf,errlog):
            break


    errlog.log(','.join(['sock','%d'% fileno,' closed,occur error,send packets %d ' % mynum]))
    sock.close()

def socket_write(sock,buf,errlog):
    if buf:
        try:
            nbyte = sock.send(binascii.unhexlify(''.join(buf)))
            #slog.log(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))
        except IOError:
            errlog.log(','.join(['sock','%d'% sock.fileno(),'closed']))
            return True
        except TypeError:
            errlog.log('send buf is wrong format %s' % buf)
    return False


def send_forward_buf(sock,srcsock,dstsock):
    buf = stun_send_data_to_devid(srcsock,dstsock)
    nbyte = sock.send(binascii.unhexlify(''.join(buf)))
    slog.log(','.join(['sock','%d'%sock.fileno(),'send: %d' % nbyte]))


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
slog = StatLog(appname)
errlog = ErrLog(appname)
tlist = []

class nsp():
    pass

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
   slog.log(','.join([appname,'Start']))
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

   tbuf = ulist
   tt = 0 
   glist = []
   for i in xrange(args.u_count):
       z = str(uuid.uuid4()).replace('-','')
       n = random.randint(0,15)
       zi = []
       for y in xrange(n):
           zi.append(chr(random.randint(97,122)))
       uname = ''.join([z,''.join(zi)])
       cuts = [bind]
       muuid = [tbuf[i:j] for i,j in zip([0]+cuts,cuts+[None])]
       if len(muuid) == 2:
           #stackless.tasklet(stun_setLogin)(host,muuid[0],uname,uname)
           #mulpool.apply_async(stun_setLogin,args=(host,muuid[0],uname,uname))
           #glist.append(gevent.spawn(stun_setLogin,host,muuid[0],uname,uname))
           pt = threading.Thread(target=APPfunc,args=(host,muuid[0],uname,uname))
           glist.append(pt)
           pt.start()
           tbuf = muuid[-1] if len(muuid[-1]) > bind else muuid[-1]+ulist
       time.sleep(0.3)
   #gevent.joinall(glist)
   #stackless.run()


   


           
           
