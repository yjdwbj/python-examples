#coding=utf-8
import socket
import select
import time
import struct
import binascii
import threading
import uuid

from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql
from sqlalchemy.orm import relationship,backref
from sqlalchemy.dialects import postgresql as pgsql

STUN_METHOD_BINDING='0001'
STUN_METHOD_ALLOCATE='0003'
STUN_METHOD_REFRESH='0004'
STUN_METHOD_SEND='0006'
STUN_METHOD_DATA='0007'
STUN_METHOD_CREATE_PERMISSION='0008'
STUN_METHOD_CHANNEL_BIND='0009'

STUN_METHOD_CONNECT='000a'
STUN_METHOD_CONNECTION_BIND='000b'
STUN_METHOD_CONNECTION_ATTEMPT='000c'

# RFC 6062 #
STUN_ATTRIBUTE_MAPPED_ADDRESS='0001'
STUN_ATTRIBUTE_CHANGE_REQUEST='0003'
STUN_ATTRIBUTE_USERNAME='0006'
STUN_ATTRIBUTE_MESSAGE_INTEGRITY='0008'
STUN_ATTRIBUTE_MESSAGE_ERROR_CODE='0009'
STUN_ATTRIBUTE_MESSAGE_UNKNOWN_ATTRIBUTES='000a'
STUN_ATTRIBUTE_REALM='0014'
STUN_ATTRIBUTE_NONCE='0015'
STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY='0017'
STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS='0020'
OLD_STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS='8020'


STUN_ATTRIBUTE_CHANNEL_NUMBER='000c'
STUN_ATTRIBUTE_LIFETIME='000d'
STUN_ATTRIBUTE_BANDWIDTH='0010'
STUN_ATTRIBUTE_XOR_PEER_ADDRESS='0012'
STUN_ATTRIBUTE_DATA='0013'
STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS='0016'
STUN_ATTRIBUTE_EVENT_PORT='0018'
STUN_ATTRIBUTE_REQUESTED_TRANSPORT='0019'
STUN_ATTRIBUTE_DONT_FRAGMENT='001a'
STUN_ATTRIBUTE_TIMER_VAL='0021'
STUN_ATTRIBUTE_RESERVATION_TOKEN='0022'


STUN_ATTRIBUTE_SOFTWARE='8022'
STUN_ATTRIBUTE_ALTERNATE_SERVER='8023'
STUN_ATTRIBUTE_FINGERPRINT='8028'
STUN_ATTRIBUTE_UUID='8001'

STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE=int(6)
STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE=int(17)
STUN_ATTRIBUTE_TRANSPORT_TLS_VALUE=int(56)
STUN_ATTRIBUTE_TRANSPORT_DTLS_VALUE=int(250)

STUN_HEADER_LENGTH=int(20)
STUN_HEADER_FMT='!HHI12s'

#Lifetimes
STUN_DEFAULT_ALLOCATE_LIFETIME=int(600)
UCLIENT_SESSION_LIFETIME=int(60)

STUN_MAGIC_COOKIE=0x2112A442

SOCK_BUFSIZE=2048

dictAttrStruct={
        STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_XOR_PEER_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_RESERVATION_TOKEN:'!HH8s',
        STUN_ATTRIBUTE_LIFETIME:'!HHI',
        STUN_ATTRIBUTE_FINGERPRINT:'!HHI'
        #STUN_ATTRIBUTE_UUID:'!HH32s'
        }

Base = declarative_base()

def get_crc32(str):
    return binascii.crc32(binascii.a2b_hex(str.lower()))

def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(24))
    return a

def stun_attr_append_str(buf,attr,add_value):
    #buf[1] = "%04x" % (len(''.join(buf)) / 2 - STUN_HEADER_LENGTH)
    # 属性名，属性长度，属性值
    buf.append(attr)
    alen = len(add_value) / 2
    buf.append("%#04d" % alen)
    buf.append(add_value)
    # 4Byte 对齐
    rem4 = (alen & 0x0003)& 0xf
    if rem4:
        rem4 = alen+4-rem4
    while rem4 > 1:
        buf[-1] += '00'
        rem4 -= 1
    buf[1] ="%04x" % (len(''.join(buf)) / 2 - STUN_HEADER_LENGTH)

def stun_add_fingerprint(buf):
    stun_attr_append_str(buf,STUN_ATTRIBUTE_FINGERPRINT,'00000000')
    crc_str = ''.join(buf[:-3])
    crcval = binascii.crc32(binascii.a2b_hex(crc_str))
    crcstr = "%08x" % ((crcval  ^ 0x5354554e) & 0xFFFFFFFF)
    buf[-1] = crcstr.replace('-','')

def stun_make_type(method):
    method  = int(method,16) & 0x0FFF
    method = ((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0380) << 2) | ((method & 0x0C00) << 2))
    return '%04x' % ((method & 0xFEEF) | 0x0100)

def stun_init_command_str(msg_type,buf,tran_id):
    buf.append(msg_type)
    buf.append("%04x" % 0)
    buf.append("%08x" % STUN_MAGIC_COOKIE)
    buf.append(tran_id)

def check_crc_is_valid(buf): # 检查包的CRC
    if len(buf) < 17:  # 包太小
        return False
    crc = struct.unpack('!HHI',binascii.unhexlify(buf[-16:]))
    rcrc =(get_crc32(buf[:-16]) ^ 0x5354554e ) & 0xFFFFFFFF
    if crc[-1] != rcrc:
        return False
    return True

def handle_client_request(buf,fileno):
    blen = len(buf)
    if not check_crc_is_valid(buf):
        print "CRC wrong"
        epoll.unregister(fileno)
        mdict['clients'][fileno].close()
        del mdict['clients'][fileno]
        return
    response_result = mdict['responses'][fileno]
    reqhead = struct.unpack(STUN_HEADER_FMT,binascii.unhexlify(buf[:STUN_HEADER_LENGTH*2]))
    method = '%04x' % reqhead[0]
    tran_id = binascii.hexlify(reqhead[-1])
    if method == STUN_METHOD_REFRESH:
        res = {}
        hexpos = STUN_HEADER_LENGTH*2
        print "method is ",method
        while  hexpos < blen:
            print "hexpos",hexpos,"blen",blen
            hexpos += stun_get_first_attr(buf[hexpos:],res)
        handle_refresh_request(fileno,res[STUN_ATTRIBUTE_LIFETIME][-1])
        refresh_sucess(response_result,tran_id)
    elif method == STUN_METHOD_ALLOCATE:
        res = {}
        hexpos = STUN_HEADER_LENGTH*2
        host = mdict['clients'][fileno].getpeername()
        while hexpos < blen:
            hexpos += stun_get_first_attr(buf[hexpos:],res)
        binding_sucess(response_result,tran_id,host)
        update_newdevice(host,res[STUN_ATTRIBUTE_UUID][-1])
    print "response_result",response_result

def refresh_sucess(buf,tran_id): # 刷新成功
    stun_init_command_str(stun_make_type(STUN_METHOD_REFRESH),buf,tran_id)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_add_fingerprint(buf)

def binding_sucess(buf,tran_id,host): # 客服端向服务器绑定自己的IP
    stun_init_command_str(stun_make_type(STUN_METHOD_ALLOCATE),buf,tran_id)
    #eip = "0001%04x%08x" % (ehost[1],ehost[0])
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,eip)
    #mip = "0001%04x%s" % (host[1],binascii.hexlify(socket.inet_aton(host[0])))
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_MAPPED_ADDRESS,mip)
    mip = "0001%04x%08x" % (host[1]^ (STUN_MAGIC_COOKIE >> 16),
            STUN_MAGIC_COOKIE ^ (int(binascii.hexlify(socket.inet_aton(host[0])),16)))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,mip)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_add_fingerprint(buf)

def handle_refresh_request(fileno,ntime):
    print "refresh new time",ntime
    mdict['sessions'][fileno] = ntime

def update_newdevice(host,uid):
    dbcon = engine.connect()
    metadata = MetaData()
    mirco_devices = Table('mirco_devices',metadata,
            Column('devid',pgsql.UUID),
            Column('is_active',pgsql.BOOLEAN),
            Column('last_login_time',pgsql.TIMESTAMP),
            Column('is_online',pgsql.BOOLEAN),
            Column('chost',pgsql.ARRAY(pgsql.INTEGER)),
            Column('data',pgsql.TEXT)
            )
    metadata.create_all(engine)
    s = sql.select([mirco_devices.c.devid])
    result = dbcon.execute(s)
    row = result.fetchone()
    if not row or row[0] != uuid.UUID(binascii.hexlify(uid)): # 找不到这个UUID 就插入新的
        ipadr = int(binascii.hexlify(socket.inet_aton(host[0])),16) & 0xFFFFFFFF
        ipprt = host[1] & 0xFFFF
        ins = mirco_devices.insert().values(devid=binascii.hexlify(uid),is_active=True,
                is_online=True,chost=[ipadr,ipprt])
        dbcon.execute(ins)


def stun_get_first_attr(response,res):
    attr_name = response[:4]
    pos = 0
    print "attr_name",attr_name
    fmt =''
    if attr_name == STUN_ATTRIBUTE_LIFETIME:
        fmt = '!HHI'
    elif attr_name == STUN_ATTRIBUTE_UUID:
        fmt = '!HH16s'
    elif attr_name == STUN_ATTRIBUTE_FINGERPRINT:
        fmt = '!HHI'
    attr_size = struct.calcsize(fmt)
    pos += attr_size*2
    res[attr_name] = struct.unpack(fmt,binascii.unhexlify(response[:attr_size*2]))
    return pos

class CheckSesionThread(threading.Thread):
    def run(self):
        while True:
            time.sleep(1)
            for x in mdict['sessions']:
                print "x is now",x
                if mdict['sessions'][x] == 0:
                    del mdict['sessions'][x]
                    mdict['clients'][x].close()
                else:
                    mdict['sessions'][x] -=1


def Server():
    srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srvsocket.bind(('',port))
    srvsocket.listen(1)
    srvsocket.setblocking(0)
    print "Start Server",srvsocket.getsockname()
    epoll.register(srvsocket.fileno(),select.EPOLLIN)
    mthread = CheckSesionThread()
    mthread.setDaemon(True)
    mthread.start()
    try:
        #clients = {}; requests = {} ; responses= {};sessons = {}
        while True:
            events = epoll.poll(1)
            for fileno,event in events:
                if fileno == srvsocket.fileno(): #新的连接
                    conn,addr = srvsocket.accept()
                    print "new peer name",conn.getpeername()
                    conn.setblocking(0)
                    print "mdict",mdict
                    mdict['clients'][conn.fileno()] = conn
                    mdict['responses'][conn.fileno()] = []
                    epoll.register(conn.fileno(),select.EPOLLIN)
                elif event & select.EPOLLIN: # 读取socket 的数据
                    mdict['requests'][fileno] = mdict['clients'][fileno].recv(2048)
                    handle_client_request(binascii.b2a_hex(mdict['requests'][fileno]),fileno)
                    epoll.modify(fileno,select.EPOLLOUT)
                elif event & select.EPOLLOUT:
                    print "new data"
                    mdict['clients'][fileno].send(binascii.a2b_hex(''.join(mdict['responses'][fileno])))
                    mdict['responses'][fileno] = []
                    epoll.modify(fileno,select.EPOLLIN)
                elif event & select.EPOLLHUP:
                    print "Client is close",mdict['clients'][fileno].getpeername()
                    epoll.unregister(fileno)
                    mdict['clients'][fileno].close()
                    del mdict['clients'][fileno]
    finally:
        epoll.unregister(srvsocket.fileno())
        epoll.close()
        srvsocket.close()


store = ['clients','requests','responses','sessions']
mdict = {} # 这个嵌套字典就是用来存放运行时的状态与数据的
for element in store:
    mdict[element]={}
epoll = select.epoll()
engine = create_engine('postgresql://postgres@localhost:5432/nath',pool_size=20,max_overflow=2)
port = 3478
Server()


