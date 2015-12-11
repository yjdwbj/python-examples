#coding=utf-8
import binascii
import struct
import uuid
import time
import logging
import string,random
from logging import handlers
from itertools import *
from collections import OrderedDict
from multiprocessing  import Pool,Queue
from multiprocessing.queues import Empty
from select import epoll,EPOLLET,EPOLLIN,EPOLLOUT,EPOLLHUP,EPOLLERR
import socket

from binascii import hexlify,unhexlify,crc32
from datetime import datetime
import sys
import traceback
import ssl
from ssl import SSLEOFError

STUN_METHOD_APPLOGIN=0x1   # APP登录命令
STUN_METHOD_ALLOCATE=0x3   #小机登录命令
STUN_METHOD_REFRESH=0x4
STUN_METHOD_SEND=0x6  # APP 给小机发数据
STUN_METHOD_DATA=0x7  # 小机给APP发数据
STUN_METHOD_INFO=0x8  # 服务器发出的通知命令
STUN_METHOD_CHANNEL_BIND=0x9 # APP 绑定小机的命令
STUN_METHOD_MODIFY=0x10 #修改绑定信息
STUN_METHOD_DELETE=0x11 #删除绑定项
STUN_METHOD_PULL=0x12  # 从服务器上拉去数据
STUN_METHOD_SMS=0x14  # 请求短信验证码
STUN_METHOD_QUERY=0x13  #  从服务器查询用户

STUN_METHOD_PUSH=0x15 # 小机发出命令，可能要APNS 推送的。

STUN_METHOD_CONNECT=0xa
STUN_METHOD_CONNECTION_BIND=0xb
STUN_METHOD_CONNECTION_ATTEMPT=0xc

STUN_METHOD_CHECK_USER=0xe
STUN_METHOD_REGISTER=0xf # App 注册用户命令



# RFC 6062 #
STUN_ATTRIBUTE_MAPPED_ADDRESS=0x1
STUN_ATTRIBUTE_CHANGE_REQUEST=0x3
STUN_ATTRIBUTE_USERNAME=0x6
STUN_ATTRIBUTE_MESSAGE_INTEGRITY=0x8
STUN_ATTRIBUTE_MESSAGE_ERROR_CODE=0x9
STUN_ATTRIBUTE_CHANNEL_NUMBER=0xc
STUN_ATTRIBUTE_LIFETIME=0xd
STUN_ATTRIBUTE_BANDWIDTH=0x10
STUN_ATTRIBUTE_XOR_PEER_ADDRESS=0x12
STUN_ATTRIBUTE_DATA=0x13
STUN_ATTRIBUTE_PHONE_ENV=0x14
STUN_ATTRIBUTE_FINGERPRINT=0x8028
STUN_ATTRIBUTE_UUID=0x8001
STUN_ATTRIBUTE_RUUID=0x8002
STUN_ATTRIBUTE_STATE=0x8003
STUN_ATTRIBUTE_MUUID=0x8004
STUN_ATTRIBUTE_MRUUID=0x8005


#Lifetimes

CRC_MASK=0xFFFFFFFF
STUN_UUID_VENDOR='20sI'
STUN_UVC='16s4sI' # uuireturn check_packet_crc32(buf)
SOCK_BUFSIZE=4096
SOCK_TIMEOUT=7200
UUID_SIZE=struct.calcsize(STUN_UVC)
TUUID_SIZE=16
REFRESH_TIME=50
CRCMASK=0x5354554e
CRCPWD=0x6a686369
HEAD_MAGIC=struct.pack('!HH',0x4a4c,0x1)

UCLIENT_SESSION_LIFETIME=int(600)

STUN_ERROR_UNKNOWN_ATTR=0x401
STUN_ERROR_UNKNOWN_HEAD= 0x402
STUN_ERROR_UNKNOWN_PACKET=0x404
STUN_ERROR_UNKNOWN_METHOD=0x403
STUN_ERROR_USER_EXIST= 0x405
STUN_ERROR_AUTH= 0x406
STUN_ERROR_DEVOFFLINE= 0x407
STUN_ERROR_FORMAT=0x408
STUN_ERROR_OBJ_NOT_EXIST=0x410
STUN_ERROR_SRV_ERROR=0x411
STUN_ERROR_OVER_TIME=0x412
STUN_ERROR_CODE_ERROR=0x413
STUN_ERROR_OVER_CONUT=0x414
STUN_ERROR_LOGIN=0x415
STUN_ERROR_NONE=None

LOG_ERROR_UUID='UUID Format Error'
LOG_ERROR_AUTH='Guest Authentication error'
LOG_ERROR_METHOD='Unkown Method command'
LOG_ERROR_SOCK='Socket pipe was broke'
LOG_ERROR_REGISTER='Register user occur error'
LOG_ERROR_DB='Operator db occur error'
LOG_ERROR_PACKET='Unkown packet format'
LOG_ERROR_ATTR='Unkown packet Attribute'
LOG_ERROR_FILENO='Too many fileno opened'
LOG_ERROR_IILAGE_CLIENT='Iilega Client request'



STUN_ONLINE=0x1
STUN_OFFLINE=0x0

LOG_SIZE=536870912
LOG_COUNT=128
HEXSEQ='0123456789abcdef'

JL_PKT_HEAD ='!HHHIIHI' # magic,verion,length,srcsock,dstsock,method,sequence
STUN_HEADER_LENGTH=struct.calcsize(JL_PKT_HEAD)

#STUN_HEAD_CUTS=(4,8,12,20,28,32,40) # 固定长度的包头
STUN_HEAD_KEY=('magic','version','length','srcsock','dstsock','method','sequence') # 包头的格式的名称
mthlist=(STUN_METHOD_APPLOGIN,\
        STUN_METHOD_ALLOCATE,\
        STUN_METHOD_REFRESH,\
        STUN_METHOD_SEND,\
        STUN_METHOD_DATA,\
        STUN_METHOD_INFO,\
        STUN_METHOD_CHANNEL_BIND,\
        STUN_METHOD_MODIFY,\
        STUN_METHOD_DELETE,\
        STUN_METHOD_PULL,\
        STUN_METHOD_CONNECT,\
        STUN_METHOD_CONNECTION_BIND,\
        STUN_METHOD_CONNECTION_ATTEMPT,\
        STUN_METHOD_CHECK_USER,\
        STUN_METHOD_REGISTER,\
        STUN_METHOD_QUERY,\
        STUN_METHOD_SMS,\
        STUN_METHOD_PUSH
        )


__author__ = 'liuchunyang'

class DictClass:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)


def stun_is_success_response_str(mth):
    n = mth & 0xFFFF
    return ((n & 0x1100) == 0x1000)


def get_packet_head_class(buf): # 把包头解析成可以识的类属性
    hlist  =  list(struct.unpack(JL_PKT_HEAD,buf))
    if len(hlist) != len(STUN_HEAD_KEY):
        del hlist[:]
        del hlist
        return None

    d = dict(zip(STUN_HEAD_KEY,hlist))
    del hlist[:]
    del hlist
    
    cc = DictClass()
    #s= ('srcsock','dstsock')
    for k in d.keys():
        setattr(cc,k,d.get(k)) # 设置源地址，目地

    for n in STUN_HEAD_KEY:
        d.pop(n,None)
    del d
    m = (STUN_METHOD_SEND,STUN_METHOD_DATA)
    if stun_get_type(cc.method) not in mthlist: #命令类形不能识别
        return None
    else:
        return cc

def stun_make_success_response(method):
    #print "success response %04x" % ((stun_make_type(method) & 0xFEEF) | 0x0100)
    return ((stun_make_type(method) & 0xFEFF) | 0x1000)

def stun_make_error_response(method):
    return ((stun_make_type(method) & 0xFEFF) | 0x1100)

def stun_make_type(method):
    t  = method & 0xFFFF
    #t = (( t & 0x000F) | ((t  & 0x0070) << 1) | ((t & 0x0380) << 2) | ((t & 0x0C00) << 2))
    t = ( t & 0x00FF) | ((t  & 0x0700) << 1) | ((t & 0x3800) << 2)
    return t

def stun_get_type(method):
    tt = method & 0xFFFF
    #t = (tt & 0x000F)| ((tt & 0x00E0) >> 1)|((tt & 0x0E00)>>2)|((tt & 0x3000)>>2)
    t = (tt & 0x00FF)| ((tt & 0x0E00) >> 1)|((tt & 0xEE00)>>2)
    return t

def stun_attr_append_str(od,attr,add_value):
    od['lst'].append(pack16(attr)) 
    alen = len(add_value)
    od['lst'].append(pack16(alen))
    # 4Byte 对齐
    rem4 = (alen & 0x0003)& 0xf
    if rem4:
        alen = alen+4-rem4
    od['lst'].append(struct.pack('!%ds' % alen,add_value))
    #buf[2] ="%04x" % (len(''.join(buf)) / 2 )

def get_list_from_od(od):
    lst = list(chain(od.values()[:-1],od['lst']))
    for n in STUN_HEAD_KEY:
        od.pop(n,None)
    od.pop('lst',None)
    del od
    return lst

def stun_add_fingerprint(od):
    crc_str = ''.join(chain(od.values()[:-1],od['lst']))
    od['length'] = pack16(len(crc_str)+4) # 4Byte crc32
    crc_str = ''.join(chain(od.values()[:-1],od['lst'])) # 这一次不要忘记了:
    crcval = crc32(crc_str)
    del crc_str
    crcstr = struct.pack('!I', ((crcval  ^ CRCMASK) & 0xFFFFFFFF))
    #buf[-1] = crcstr.replace('-','')
    od['lst'].append(crcstr)

def pack16(t):
    return struct.pack('!H',t)

def unpack16(t):
    return struct.unpack('!H',t)[0]

def unpack32(t):
    return struct.unpack('!I',t)[0]

def pack32(t):
    return struct.pack('!I',t)

def stun_init_command_head(msg_type):
    d = OrderedDict()
    d['magic'] = pack16(0x4a4c)
    d['version'] = pack16(0x1)
    d['length']=pack16(0x14)
    d['srcsock']=pack32(0xFFFFFFFF)
    d['dstsock']=pack32(0xFFFFFFFF)
    d['method'] = pack16(msg_type)
    d['sequence'] = pack32(0)
    d['lst'] = []
    return d
    

def check_packet_crc32(buf): # 检查包的CRC
    if len(buf) < (STUN_HEADER_LENGTH + 4):
        return False
    #crc = struct.unpack('!HHI',binascii.unhexlify(buf[-16:]))
    rcrc =(crc32(buf[:-4]) ^ CRCMASK) & 0xFFFFFFFF
    return unpack32(buf[-4:]) == rcrc
    #return cmp(buf[-8:],'%08x' %  rcrc)

def check_packet_vaild(buf):
    if len(buf) < (STUN_HEADER_LENGTH + 4):
        return False
    return not ((buf[:4] == HEAD_MAGIC) and check_packet_crc32(buf))
    #return check_packet_crc32(buf)

def stun_error_response(res):
    od = stun_init_command_head(stun_make_error_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_ERROR_CODE,pack16(res.eattr))
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def get_jluuid_crc32(uhex):
    ucrc = crc32(uhex)
    return (ucrc ^ CRCPWD) & 0xFFFFFFFF

def check_uuid_format(uid):
    n = [ x for x in uid[:TUUID_SIZE*2] if x > 'f' or x < '0']
    return  len(n) > 0 or uid[1] < 24

def check_uuid_valid(uhex):
    #print "my crc",crcstr,'rcrc',uhex[-8:]
    return get_jluuid_crc32(uhex[:-4]) == uhex[-4:]

def check_jluuid(huid): # 自定义24B的UUID
    if ((crc32(huid[:-4]) ^ CRCPWD) & 0xFFFFFFFF) != unpack32(huid[-4:]):
        return STUN_ERROR_UNKNOWN_PACKET

    #if check_uuid_format(huid):
    #    return STUN_ERROR_UNKNOWN_PACKET
    return None

def check_dst_and_src(res):
    if res.dstsock == 0xFFFFFFFF or res.srcsock == 0xFFFFFFFF:
        res.eattr = STUN_ERROR_UNKNOWN_HEAD
        return True
    else:
        return False

def get_muluuid_fmt(num):
    n = 1
    p = []
    while n <= num:
        p.append(UUID_SIZE * n)
        n+=1
    return p

def split_jl_head(hbuf,fileno):
    return [(''.join([HEAD_MAGIC,n]),fileno) for n in hbuf.split(HEAD_MAGIC) if n]

#def split_requests_buf(hbuf):
#    nset = set([''.join([HEAD_MAGIC,n]) for n in hbuf.split(HEAD_MAGIC) if n])
#    nlist = list(nset)
#    del nset
#    #chl = int(nlist[-1][8:12],16) # 检查最后一个是否是完整的。
#    chl = unpack16(nlist[-1][4:6])
#    if len(nlist[-1]) != chl:
#        return nlist[:-1]
#    return nlist

def split_requests_buf(hbuf):
    buf = hbuf
    lst = []
    while 1:
        if not buf:
            break
        bl = len(buf)
        if bl < 6:
            break
        if HEAD_MAGIC != buf[:4]:
            break
        tl = struct.unpack('!H',buf[4:6])[0]
        if bl < tl:
            break
        lst.append(buf[:tl])
        buf = buf[tl:]
    return lst


def read_attr_block(buf):
    try:
        attr_name,attr_len = struct.unpack('!HH',buf[:4])
    #print "attr_len",attr_name,attr_len,hexlify(buf),' ',buf
        res =  (attr_name,attr_len,struct.unpack('!%ds' % attr_len,buf[4:4+attr_len])[0])
    except:
        return None
    else:
        return res


def parser_stun_package(buf):
    bl = len(buf)
    pos = 0
    mlist = {}
    while pos != bl:
        one_attr = read_attr_block(buf[pos:])
        if not one_attr:
            return None
        l = one_attr[1]
        rem4 = (l & 0x3) & 0xf
        if rem4:
            rem4 = l +4-rem4
            l = l+(rem4-l)
        pos = pos+l+4
        mlist[one_attr[0]] = one_attr[2]
    return mlist
    

def split_muuid(b):
    hlen = UUID_SIZE * 2
    return  [b[k:k+hlen] for k in xrange(0,len(b),hlen)]

def pwd_generator(size=8,chars=string.ascii_lowercase+string.digits):
    return ''.join(random.SystemRandom().choice(chars) for _ in xrange(size))

def split_mruuid(b):
    hlen = UUID_SIZE * 2+8
    return  [b[k:k+hlen] for k in xrange(0,len(b),hlen)]
    

def gen_random_jluuid(vendor):
    n = ''.join([str(uuid.uuid4()).replace('-',''),vendor])
    return ''.join([n,get_jluuid_crc32(n)])



def logger_worker(queue,logger):
    while 1:
        for n in xrange(60):
            try:
                msg = queue.get_nowait()
            except Empty:
                pass
            else:
                logger.log(msg)
        time.sleep(0.1)

def force_hex(sdata):
    hdata = sdata
    while 1:
        try:
            hdata = hdata.decode('hex')
        except TypeError:
            break
    return hdata




class ErrLog(logging.Logger):
    def __init__(self,aname):
        logging.Logger.__init__(self,aname)
        self.setLevel(logging.ERROR)
        fmt = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
        file_handler = handlers.RotatingFileHandler('err_%s_%s.log' % (aname,time.strftime('%Y%m%d%H%M%S')),maxBytes=LOG_SIZE,backupCount=LOG_COUNT)
        file_handler.setFormatter(fmt)
        self.addHandler(file_handler)

    def log(self,msg):
        self.error(msg)


class StatLog(logging.Logger):
    def __init__(self,aname):
        logging.Logger.__init__(self,aname)
        self.setLevel(logging.INFO)
        fmt = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
        file_handler = handlers.RotatingFileHandler('stat_%s_%s.log' % (aname,time.strftime('%Y%m%d%H%M%S')),maxBytes=LOG_SIZE,backupCount=LOG_COUNT)
        file_handler.setFormatter(fmt)
        self.addHandler(file_handler)
    def log(self,msg):
        self.info(msg)

class EpollReactor(object):
    EV_IN = EPOLLIN | EPOLLET
    EV_OUT = EPOLLOUT  | EPOLLET
    EV_DISCONNECTED =(EPOLLHUP | EPOLLERR)
    def __init__(self):
        self._poller = epoll(1024)

    def poll(self,timeout):
        return self._poller.poll(timeout)

    def register(self,fd,mode):
        return self._poller.register(fd,mode)

    def unregister(self,fd):
        return self._poller.unregister(fd)

    def modify(self,fd,mode):
        self._poller.modify(fd,mode)


class APNSConnection(object):
    apnsHost = 'gateway.push.apple.com'
    apnsSandboxHost = 'gateway.sandbox.push.apple.com'
    apnsPort = 2195
    def __init__(self,certificate =None):
        self.socket = None
        self.connectionContext = None
        self.certificate = certificate
        self.ssl_module = ssl
        self.context()
        self.connect(self.apnsSandboxHost,self.apnsPort)

    def context(self):
        if self.connectionContext != None:
            return self

        self.socket = socket.socket()
        self.connectionContext = self.ssl_module.wrap_socket(
                self.socket,
                ssl_version = self.ssl_module.PROTOCOL_SSLv23,
                certfile = self.certificate
                )
        return self

    def read(self,blockSize = 1024):
        return self.connectionContext.read(blockSize)

    def write(self,data = None):
        self.connectionContext.write(data)

    def connect(self,host,port):
        self.connectionContext.connect((host,port))

    def close(self):
        self.connectionContext.close()
        self.socket.close()
