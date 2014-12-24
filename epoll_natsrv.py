#coding=utf-8
import socket
import select
import time
import struct
import binascii
import threading
import zlib

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column,Integer,String,ForeignKey,Date
from sqlalchemy import sql
from sqlalchemy.orm import relationship,backref


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

dictAttrStruct={
        STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_XOR_PEER_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_RESERVATION_TOKEN:'!HH8s',
        STUN_ATTRIBUTE_LIFETIME:'!HHI',
        STUN_ATTRIBUTE_FINGERPRINT:'!HHI'
        }


Base = declarative_base()



def get_crc32(str):
    return zlib.crc32(binascii.a2b_hex(str.lower()))

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
    crcval = zlib.crc32(binascii.a2b_hex(crc_str))
    crcstr = "%08x" % ((crcval  ^ 0x5354554e) & 0xFFFFFFFF)
    buf[-1] = crcstr.replace('-','')

def stun_make_type(method):
    method  = int(method,16) & 0x0FFF
    return '%04x' % ((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0380) << 2) | ((method & 0x0C00) << 2))

def stun_init_command_str(msg_type,buf,tran_id):
    buf.append(msg_type)
    buf.append("%04x" % 0)
    buf.append("%08x" % STUN_MAGIC_COOKIE)
    buf.append(tran_id)

def check_crc_is_valid(buf):
    crc = struct.unpack('!HHI',binascii.unhexlify(buf[-16:]))
    rcrc = get_crc32(buf[:-16])
    print "crc " ,crc
    print "rcrc",rcrc
    if crc[-1] != rcrc:
        return False
    return True

def handle_client_request(buf,epoll,fileno,clients,responses):
    if not check_crc_is_valid(buf):
        print "CRC wrong"
        epoll.unregister(fileno)
        clients[fileno].close()
        del clients[fileno]
        return
    r = []
    reqhead = struct.unpack(STUN_HEADER_FMT,buf[:STUN_HEADER_LENGTH*2])
    method = '%04x' % reqhead[0]
    tran_id = binascii.hexlify(reqhead[-1])
    if method == STUN_METHOD_REFRESH:
        refresh_sucess(r,tran_id)
    elif method == STUN_METHOD_BINDING:
        binding_sucess(r,tran_id,clients[fileno].getpeerkname())

    response = binascii.a2b_hex(''.join(r))
    epoll.modify(fileno,select.EPOLLOUT)


def refresh_sucess(buf,tran_id): # 刷新成功
    stun_init_command_str(stun_make_type(STUN_METHOD_REFRESH),buf,tran_id)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%04x' % UCLIENT_SESSION_LIFETIME)
    stun_add_fingerprint(buf)

def binding_sucess(buf,tran_id,host): # 客服端向服务器绑定自己的IP
    stun_init_command_str(stun_make_type(STUN_METHOD_REFRESH),buf,tran_id)
    #eip = "0001%04x%08x" % (ehost[1],ehost[0])
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS,eip)
    mip = "0001%04x%08x" % (host[1],host[0])
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MAPPED_ADDRESS,mip)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%04x' % UCLIENT_SESSION_LIFETIME)
    stun_add_fingerprint(buf)

def read_client_attr(recv,response_result):
    pass


def stun_get_first_attr(response,response_result):
    attr_name = response[:4]
    pos = 0
    if attr_name in dictAttrStruct:
        attr_size = struct.calcsize(dictAttrStruct[attr_name])
        pos += attr_size*2
        res = struct.unpack(dictAttrStruct[attr_name],binascii.unhexlify(response[:attr_size*2]))
    elif attr_name == STUN_ATTRIBUTE_UUID:
        fmt = '!HH32s'
        attr_size = struct.calcsize(fmt)
        res = struct.unpack(fmt,binascii.unhexlify(response[:attr_size*2]))
        dbcon = engine.conn()
        mirco = Table('mirco')
        result = dbcon.execute('select * from mirco')
        if len(result) == 0:
            ins = mirco.insert().values(uuid=res[-1])
            str(ins)


    elif attr_name == STUN_ATTRIBUTE_SOFTWARE:
        fmt = '!HH%ds' % (int("0x%s" % response[4:8],16) & 0xFFFF)
        attr_size = struct.calcsize(fmt)
        pos += attr_size*2
        res = struct.unpack(fmt,binascii.unhexlify(response[:attr_size*2]))
    if res:
        response_result.append(res)
    return pos



def Server():
    srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srvsocket.bind(('',port))
    srvsocket.listen(1)
    srvsocket.setblocking(0)
    print "Start Server",srvsocket.getsockname()
    epoll.register(srvsocket.fileno(),select.EPOLLIN)
    response = b'Welcomei\r\n'
    try:
        clients = {}; requests = {} ; responses= {}
        while True:
            events = epoll.poll(1)
            for fileno,event in events:
                if fileno == srvsocket.fileno(): #新的连接
                    conn,addr = srvsocket.accept()
                    print "new peer name",conn.getpeername()
                    conn.setblocking(0)
                    clients[conn.fileno()] = conn
                    responses[conn.fileno()] = []
                    epoll.register(conn.fileno(),select.EPOLLIN)
                elif event & select.EPOLLIN: # 读取socket 的数据
                    requests[fileno] = clients[fileno].recv(1024)
                    handle_client_request(binascii.b2a_hex(requests[fileno]),epoll,fileno,clients,responses[fileno])
                elif event & select.EPOLLOUT:
                    byteswritten = clients[fileno].send(responses[fileno])
                elif event & select.EPOLLHUP:
                    epoll.unregister(fileno)
                    clients[fileno].close()
                    del clients[fileno]
    finally:
        epoll.unregister(srvsocket.fileno())
        epoll.close()
        srvsocket.close()



epoll = select.epoll()

engine = create_engine('postgresql://postgres@localhost:5432/nath',pool_size=20,max_overflow=2)
port = 3478
Server()


