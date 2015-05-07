#coding=utf-8
import binascii
import struct
import uuid
import time
import logging
from logging import handlers
from itertools import *
from collections import OrderedDict
from multiprocessing  import Pool,Queue
from multiprocessing.queues import Empty
from select import epoll,EPOLLET,EPOLLIN,EPOLLOUT,EPOLLHUP,EPOLLERR

from binascii import hexlify,unhexlify
from datetime import datetime
from sqlalchemy import *
from sqlalchemy.exc import *
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql,and_
from sqlalchemy.dialects import postgresql as pgsql
from sqlalchemy.pool import QueuePool


STUN_METHOD_BINDING='0001'   # APP登录命令
STUN_METHOD_ALLOCATE='0003'   #小机登录命令
STUN_METHOD_REFRESH='0004'
STUN_METHOD_SEND='0006'  # APP 给小机发数据
STUN_METHOD_DATA='0007'  # 小机给APP发数据
STUN_METHOD_INFO='0008'  # 服务器发出的通知命令
STUN_METHOD_CHANNEL_BIND='0009' # APP 绑定小机的命令
STUN_METHOD_MODIFY='0010' #修改绑定信息
STUN_METHOD_DELETE='0011' #删除绑定项
STUN_METHOD_PULL='0012'  # 从服务器上拉去数据

STUN_METHOD_CONNECT='000a'
STUN_METHOD_CONNECTION_BIND='000b'
STUN_METHOD_CONNECTION_ATTEMPT='000c'

STUN_METHOD_CHECK_USER='000e'
STUN_METHOD_REGISTER='000f' # App 注册用户命令



# RFC 6062 #
STUN_ATTRIBUTE_MAPPED_ADDRESS='0001'
STUN_ATTRIBUTE_CHANGE_REQUEST='0003'
STUN_ATTRIBUTE_USERNAME='0006'
STUN_ATTRIBUTE_MESSAGE_INTEGRITY='0008'
STUN_ATTRIBUTE_MESSAGE_ERROR_CODE='0009'


STUN_ATTRIBUTE_CHANNEL_NUMBER='000c'
STUN_ATTRIBUTE_LIFETIME='000d'
STUN_ATTRIBUTE_BANDWIDTH='0010'
STUN_ATTRIBUTE_XOR_PEER_ADDRESS='0012'
STUN_ATTRIBUTE_DATA='0013'

STUN_ATTRIBUTE_FINGERPRINT='8028'
STUN_ATTRIBUTE_UUID='8001'
STUN_ATTRIBUTE_RUUID='8002'
STUN_ATTRIBUTE_STATE='8003'
STUN_ATTRIBUTE_MUUID='8004'
STUN_ATTRIBUTE_MRUUID='8005'


#Lifetimes

CRC_MASK=0xFFFFFFFF
STUN_STRUCT_FMT='!HHI12s' # 固定20Byte的头， 类型，长度，魔数，SSID
STUN_UUID_VENDOR='20sI'
STUN_UVC='16s4sI' # uuireturn check_packet_crc32(buf)
SOCK_BUFSIZE=4096
SOCK_TIMEOUT=7200
UUID_SIZE=struct.calcsize(STUN_UVC)
TUUID_SIZE=16
REFRESH_TIME=50
CRCMASK=0x5354554e
CRCPWD=0x6a686369
HEAD_MAGIC="4a4c0001"
STUN_HEADER_FMT='!2sHHIIHI'
STUN_HEADER_LENGTH=struct.calcsize(STUN_HEADER_FMT)*2
UCLIENT_SESSION_LIFETIME=int(600)

STUN_ERROR_UNKNOWN_ATTR='%08x' % 0x401
STUN_ERROR_UNKNOWN_HEAD='%08x' % 0x402
STUN_ERROR_UNKNOWN_PACKET='%08x' % 0x404
STUN_ERROR_UNKNOWN_METHOD='%08x' %0x403
STUN_ERROR_USER_EXIST='%08x' % 0x405
STUN_ERROR_AUTH='%08x' % 0x406
STUN_ERROR_DEVOFFLINE='%08x' % 0x407
STUN_ERROR_FORMAT='%08x' % 0x408
STUN_ERROR_OBJ_NOT_EXIST='%08x' % 0x410
STUN_ERROR_NONE=None


STUN_ONLINE='00000001'
STUN_OFFLINE='00000000'

LOG_SIZE=536870912
LOG_COUNT=128

STUN_HEAD_CUTS=(4,8,12,20,28,32,40) # 固定长度的包头
STUN_HEAD_KEY=('magic','version','length','srcsock','dstsock','method','sequence') # 包头的格式的名称
mthlist=(STUN_METHOD_BINDING,\
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
        STUN_METHOD_REGISTER)

__author__ = 'liuchunyang'

class DictClass:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)

def get_crc32(s):
    return binascii.crc32(binascii.unhexlify(s.lower()))

def stun_is_success_response_str(mth):
    n = int(mth,16) & 0xFFFF
    return ((n & 0x1100) == 0x1000)

def get_packet_head_list(buf):
    tlist = list(STUN_HEAD_CUTS)
    return [buf[i:j] for i,j in zip([0]+tlist,tlist+[None])]

def get_packet_head_class(buf): # 把包头解析成可以识的类属性
    hlist = filter(None,get_packet_head_list(buf))
    if len(hlist) != len(STUN_HEAD_KEY):
        return None
    d = dict(zip(STUN_HEAD_KEY,hlist))
    cc = DictClass()
    s= ('srcsock','dstsock')
    for k in d.keys():
        if k in s:
            setattr(cc,k,int(d.get(k),16))
        else:
            setattr(cc,k,d.get(k))

    if stun_get_type(cc.method) not in mthlist: #命令类形不能识别
        return None
    t = ('02','03')
    m = (STUN_METHOD_SEND,STUN_METHOD_DATA)
    if cc.method in m:
        if cc.sequence[:2] in t:
            return cc
        else:
            return None
    else:
        if cmp(cc.sequence,'00000000'):
            return None
        else:
            return cc

def stun_make_success_response(method):
    #print "success response %04x" % ((stun_make_type(method) & 0xFEEF) | 0x0100)
    return '%04x' % ((stun_make_type(method) & 0xFEFF) | 0x1000)

def stun_make_error_response(method):
    return '%04x' % ((stun_make_type(method) & 0xFEFF) | 0x1100)

def stun_make_type(method):
    t  = int(method,16) & 0xFFFF
    #t = (( t & 0x000F) | ((t  & 0x0070) << 1) | ((t & 0x0380) << 2) | ((t & 0x0C00) << 2))
    t = ( t & 0x00FF) | ((t  & 0x0700) << 1) | ((t & 0x3800) << 2)
    return t

def stun_get_type(method):
    tt = int(method,16) & 0xFFFF
    #t = (tt & 0x000F)| ((tt & 0x00E0) >> 1)|((tt & 0x0E00)>>2)|((tt & 0x3000)>>2)
    t = (tt & 0x00FF)| ((tt & 0x0E00) >> 1)|((tt & 0xEE00)>>2)
    return '%04x' % t

def stun_attr_append_str(od,attr,add_value):
    #buf[1] = "%04x" % (len(''.join(buf)) / 2 - STUN_HEADER_LENGTH)
    # 属性名，属性长度，属性值
    #buf.append(attr)
    od['lst'].append(attr) 
    alen = len(add_value) / 2
    od['lst'].append("%04x" % alen)
    tb = add_value
    # 4Byte 对齐
    rem4 = (alen & 0x0003)& 0xf
    if rem4:
        rem4 = alen+4-rem4
    while (rem4 -alen) > 0:
        tb += '00'
        rem4 -= 1
    od['lst'].append(tb)
    #buf[2] ="%04x" % (len(''.join(buf)) / 2 )

def get_list_from_od(od):
    lst = chain(od.values()[:-1],od['lst'])
    for n in STUN_HEAD_KEY:
        od.pop(n,None)
    od.pop('lst',None)
    del od
    return lst

def stun_add_fingerprint(od):
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_FINGERPRINT,'00000000')
    #buf.append('00000000')
    #buf[2] = '%04x' % (int(buf[2],16)+4)
    od['length'] = '%04x' %  (len(''.join(chain(od.values()[:-1],od['lst'])))+4) # 4Byte crc32
    crc_str = ''.join(chain(od.values()[:-1],od['lst']))
    crcval = get_crc32(crc_str)
    del crc_str
    crcstr = "%08x" % ((crcval  ^ CRCMASK) & 0xFFFFFFFF)
    #buf[-1] = crcstr.replace('-','')
    od['lst'].append(crcstr.replace('-',''))


def stun_init_command_head(msg_type):
    d = OrderedDict()
    d['magic'] = '4a4c'
    d['version'] = '0001'
    d['length']='0014'
    d['srcsock']='FFFFFFFF'
    d['dstsock']='FFFFFFFF'
    d['method'] = msg_type
    d['sequence'] = '00000000'
    d['lst'] = []
#    setattr(d,'magic','4a4c')
#    setattr(d,'version','0001')
#    setattr(d,'length','0014')
#    setattr(d,'srcsock','FFFFFFFF')
#    setattr(d,'dstsock','FFFFFFFF')
#    setattr(d,'method',msg_type)
#    setattr(d,'sequence','00000000')
#    setattr(d,'lst',[])
#    #setattr(d,'crc32','0')
    return d
    

def stun_init_command_str(msg_type,buf):
    buf.append("4a4c") # 魔数字
    buf.append("0001") # 版本号
    buf.append("0014") # 长度
    buf.append("FFFFFFFF") # SRC
    buf.append("FFFFFFFF") # DST
    buf.append(msg_type) # CMD
    buf.append("00000000")  # 序列号

def check_packet_crc32(buf): # 检查包的CRC
    #crc = struct.unpack('!HHI',binascii.unhexlify(buf[-16:]))
    rcrc =(get_crc32(buf[:-8]) ^ CRCMASK) & 0xFFFFFFFF
    return cmp(buf[-8:],'%08x' %  rcrc)

def check_packet_vaild(buf):
    if cmp(buf[:8],HEAD_MAGIC) or check_packet_crc32(buf):
        return True
    else:
        return False
    #return check_packet_crc32(buf)

def stun_error_response(res):
    buf = []
    #stun_init_command_str(stun_make_error_response(res.method),buf)
    od = stun_init_command_head(stun_make_error_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_ERROR_CODE,res.eattr)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def get_jluuid_crc32(uhex):
    ucrc = get_crc32(uhex)
    return "%08x" % ((ucrc ^ CRCPWD) & 0xFFFFFFFF)

def check_uuid_format(uid):
    n = [ x for x in uid[:TUUID_SIZE*2] if x > 'f' or x < '0']
    return  len(n) > 0 or uid[1] < 24

def check_uuid_valid(uhex):
    #print "my crc",crcstr,'rcrc',uhex[-8:]
    return cmp(get_jluuid_crc32(uhex[:-8]),uhex[-8:])

def check_jluuid(huid): # 自定义24B的UUID
    if check_uuid_valid(huid):
        return STUN_ERROR_UNKNOWN_PACKET

    if check_uuid_format(huid):
        return STUN_ERROR_UNKNOWN_PACKET
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

def split_requests_buf(hbuf):
    nset = set([''.join([HEAD_MAGIC,n]) for n in hbuf.split(HEAD_MAGIC) if n])
    nlist = list(nset)
    del nset
    chl = int(nlist[-1][8:12],16) # 检查最后一个是否是完整的。
    if len(nlist[-1]) != (chl * 2):
        return nlist[:-1]
    return nlist


def read_attributes_from_buf(response):
    attr_name = response[:4]
    fmt = []
    vfunc = lambda x: [4,8,int(x,16)]
    if attr_name == STUN_ATTRIBUTE_LIFETIME:
        fmt = vfunc(response[4:8])
    #elif attr_name == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
    #    fmt = '!HH2sHI'
    elif attr_name == STUN_ATTRIBUTE_FINGERPRINT:
        fmt = '!HHI'
    elif attr_name == STUN_ATTRIBUTE_STATE:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_UUID:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_RUUID:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_MESSAGE_INTEGRITY:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_DATA:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_USERNAME:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_MESSAGE_ERROR_CODE:
        fmt = vfunc(response[4:8])
    elif attr_name == STUN_ATTRIBUTE_MUUID:
        fmt = vfunc(response[4:8])
        if fmt[-1] % UUID_SIZE:
            return None # 不是UUID_SIZE的倍数，错误的格式
    elif attr_name == STUN_ATTRIBUTE_MRUUID:
        fmt = vfunc(response[4:8])
        if fmt[-1] % (UUID_SIZE+4):
            return None # 不是UUID_SIZE的倍数，错误的格式
    else:
        #print 'unkown attr_name',attr_name
        return None
    return (attr_name,fmt)

def parser_buf_to_list(buf):
    mlist = []
    tbuf = buf
    while len(tbuf):
        fmt = read_attributes_from_buf(tbuf)
        if fmt is None:
            return None
        attr_size = fmt[1][-1]
        hexpos = 8 + attr_size * 2
        rem4 = attr_size & 0x0003
        if rem4:
            rem4 = attr_size+4-rem4
            attr_size += (rem4 - attr_size)
        fmt[1][-1] = 8+attr_size*2
        l = [tbuf[i:j] for i,j in zip([0]+fmt[1],fmt[1]+[None])]
        mlist.append(l[:3])
        if len(l) == 4:
            tbuf=l[3]
        else:
            tbuf=[]
    del tbuf
    return mlist
        
def parser_stun_package(buf):
    lst = parser_buf_to_list(buf)
    k = v = [] 
    try:
        k = [v[0] for v in lst]
        v = [ v[2][:int(v[1],16)*2] for v in lst]
    except TypeError:
        #print "TypeError,buf",buf
        del k
        del v
        del lst
        return None
    return  (dict(zip(k,v)),lst)

#def parser_stun_package(buf):
#    #if check_packet_vaild(buf): return None
#    #attrdict= DictClass()
#    attrdict = {}
#    rlen = len(buf)
#    hexpos = 0
#    s = 0
#    tbuf = buf
#    while len(tbuf):
#        fmt = read_attributes_from_buf(tbuf)
#        if fmt is None:
#            return None
#        attr_size = fmt[1][-1]
#        hexpos = 8+attr_size * 2
#        rem4 = attr_size & 0x0003
#        if rem4: # 这里要与客户端一样,4Byte 对齐
#            rem4 = attr_size+4-rem4
#            attr_size += (rem4 - attr_size)
#        fmt[1][-1]=  8+attr_size * 2
#
#        l = [tbuf[i:j] for i,j in zip([0]+fmt[1],fmt[1]+[None])]
#        ttt = l[:3]
#        ttt[-1] = ttt[-1][:int(ttt[1],16)*2] #实际长度，如果是字节对齐的在这里要去掉
#        attrdict[fmt[0]] = tuple(ttt)
#        if len(l) == 4:
#            tbuf=l[3]
#        else:
#            tbuf =[]
#
#        #if attrdict.has_key(STUN_ATTRIBUTE_LIFETIME): # 请求的时间大于服务器的定义的，使用服务端的定义 # 请求的时间大于服务器的定义的，使用服务端的定义
#        #    if int(attrdict[STUN_ATTRIBUTE_LIFETIME][-1],16) > UCLIENT_SESSION_LIFETIME:
#        #        attrdict[STUN_ATTRIBUTE_LIFETIME] = (STUN_ATTRIBUTE_LIFETIME,'0004',STR_UCLIENT_SESSION_LIFETIME)
#
#    return attrdict

def split_muuid(b):
    hlen = UUID_SIZE * 2
    return  [b[k:k+hlen] for k in xrange(0,len(b),hlen)]

def split_mruuid(b):
    hlen = UUID_SIZE * 2+8
    return  [b[k:k+hlen] for k in xrange(0,len(b),hlen)]
    

def gen_random_jluuid(vendor):
    n = ''.join([str(uuid.uuid4()).replace('-',''),vendor])
    return ''.join([n,get_jluuid_crc32(n)])


def stun_struct_refresh_request():
    buf = []
    #stun_init_command_str(STUN_METHOD_REFRESH,buf)
    od = stun_init_command_head(STUN_METHOD_REFRESH)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(od,STUN_ATTRIBUTE_LIFETIME,filed)
    del filed
    stun_add_fingerprint(od)
    return get_list_from_od(od)

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


class QueryDB():
    def __init__(self):
        #self.engine = create_engine('postgresql+psycopg2cffi://postgres:postgres@127.0.0.1:5432/nath',pool_size=8192,max_overflow=4096,\
        #        poolclass=QueuePool)
        self.engine = create_engine('postgresql+psycopg2cffi://postgres:postgres@127.0.0.1:5432/nath')

    def check_table(self,table):
        return table.exists(self.engine)

    def get_engine(self):
        return self.engine

    def get_dbconn(self):
        return self.get_engine().connect()
    
    def execute(self,stmt):
        return self.get_dbconn().execute(stmt)
        

    def create_table(self,sql_txt):
        self.engine.connect().execute(sql_txt)
    @staticmethod
    def select(sql_txt):
        engine = create_engine('postgresql+psycopg2cffi://postgres:postgres@127.0.0.1:5432/nath')
        conn = engine.connect()
        
        try:
            result = conn.execute(sql_txt)
        except ProgrammingError:
            raise ProgrammingError
        else:
            conn.close()
            return result



    @staticmethod
    def get_account_bind_table(name):
        metadata = MetaData()
        table = Table(name,metadata,
                Column('uuid',pgsql.VARCHAR(48),nullable=False,primary_key=True),
                Column('pwd',pgsql.BYTEA),
                Column('reg_time',pgsql.TIME,nullable=False)
                )
        return table

    @staticmethod
    def get_account_status_table():
        metadata = MetaData()
        table = Table('account_status',metadata,
                Column('uname',pgsql.VARCHAR(255)),
                Column('is_login',pgsql.BOOLEAN,nullable=False),
                Column('last_login_time',pgsql.TIME,nullable=False),
                Column('chost',pgsql.ARRAY(pgsql.BIGINT),nullable=False)
                )
        return table
    
    @staticmethod
    def get_account_table():
        metadata = MetaData()
        account = Table('account',metadata,
                #Column('uuid',pgsql.UUID,primary_key=True),
                Column('uname',pgsql.VARCHAR(255),primary_key=True),
                Column('pwd',pgsql.BYTEA),
                Column('is_active',pgsql.BOOLEAN,nullable=False),
                Column('reg_time',pgsql.TIME,nullable=False)
                )
        return account

    @staticmethod
    def get_devices_table(tname):
        metadata = MetaData()
        mirco_devices = Table(tname,metadata,
                Column('devid',pgsql.UUID,primary_key=True,unique=True),
                Column('is_active',pgsql.BOOLEAN,nullable=False),
                Column('last_login_time',pgsql.TIMESTAMP,nullable=False),
                Column('is_online',pgsql.BOOLEAN,nullable=False),
                Column('chost',pgsql.ARRAY(pgsql.BIGINT),nullable=False),
                Column('data',pgsql.BYTEA)
                )
        return mirco_devices

