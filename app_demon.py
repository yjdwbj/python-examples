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
import uuid


DEFAULTS = {
        'stun_port': 3478,
        'source_ip': '127.0.0.1',
        'source_port': 54321
}


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

STUN_METHOD_CHECK_USER='000e'
STUN_METHOD_REGISTER='000f'

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
STUN_ATTRIBUTE_DATABASE_RES='8002'
STUN_ATTRIBUTE_REGISTER_SUCCESS='8003'
STUN_ATTRIBUTE_VENDOR='8004'

STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE=int(6)
STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE=int(17)
STUN_ATTRIBUTE_TRANSPORT_TLS_VALUE=int(56)
STUN_ATTRIBUTE_TRANSPORT_DTLS_VALUE=int(250)

STUN_HEADER_LENGTH=int(20)

#Lifetimes
STUN_DEFAULT_ALLOCATE_LIFETIME=int(600)
UCLIENT_SESSION_LIFETIME=int(60)

STUN_MAGIC_COOKIE=0x2112A442
STUN_MAGIC_COOKIE_STR = struct.pack("I",STUN_MAGIC_COOKIE)
CRC_MASK=0xFFFFFFFF
STUN_STRUCT_FMT='!HHI12s' # 固定20Byte的头， 类型，长度，魔数，SSID

STUN_STRUCT_ATTR_HEAD='!HH'




dictMethodToVal={
        'StunMethodBinding':STUN_METHOD_BINDING,
        'StunMethodAllocte':STUN_METHOD_ALLOCATE,
        'StunMethodRefresh':STUN_METHOD_REFRESH,
        'StunMethodSend':STUN_METHOD_SEND,
        'StunMethodData':STUN_METHOD_DATA,
        'StunMethodCreatePermission':STUN_METHOD_CREATE_PERMISSION,
        'StunMethodChannelBind':STUN_METHOD_CHANNEL_BIND,
        'StunMethodConnect':STUN_METHOD_CONNECT,
        'StunMethodConnectionBind':STUN_METHOD_CONNECTION_BIND,
        'StunMethodConnectionAttempt':STUN_METHOD_CONNECTION_ATTEMPT
        }

dictAttrStruct={
        STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_XOR_PEER_ADDRESS:'!HH2sHI', # type,len,reserved,protocl,port,ipaddr
        STUN_ATTRIBUTE_RESERVATION_TOKEN:'!HH8s',
        STUN_ATTRIBUTE_LIFETIME:'!HHI',
        STUN_ATTRIBUTE_FINGERPRINT:'!HHI'
        }

def get_crc32(str):
    return zlib.crc32(binascii.a2b_hex(str.lower()))

def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(24))
    return a


def stun_init_command_str(msg_type,buf):
    buf.append(msg_type)
    buf.append("%04x" % 0)
    buf.append("%08x" % STUN_MAGIC_COOKIE)
    #buf.append(STUN_MAGIC_COOKIE_STR)
    buf.append(gen_tran_id())

def stun_attr_append_str(buf,attr,add_value):
    #buf[1] = "%04x" % (len(''.join(buf)) / 2 - STUN_HEADER_LENGTH)
    # 属性名，属性长度，属性值
    buf.append(attr) 
    alen = len(add_value) / 2
    buf.append("%04x" % alen)
    buf.append(add_value)
    # 4Byte 对齐
    rem4 = (alen & 0x0003)& 0xf 
    print "the rem4 is",rem4
    if rem4:
        rem4 = alen+4-rem4
        print "rem4",rem4
    while (rem4 - alen)  > 0:
        buf[-1] += '00'
        rem4 -= 1
    buf[1] ="%04x" % (len(''.join(buf)) / 2 - STUN_HEADER_LENGTH)


def stun_message_integrity(key):
    #data = hmac.new(key,msg).hexdigest()
    obj = hmac.new('')
    obj.update(key)
    return obj.hexdigest()
    hobj = hashlib.sha1()
    hobj.update(key)
    data = hobj.hexdigest()
    print "data is %s,len %d" % (data,len(data))
    return data

def stun_check_user_valid(buf,uname):
    stun_init_command_str(STUN_METHOD_CHECK_USER,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    stun_add_fingerprint(buf)

def stun_register_request(buf,uname,pwd):
    stun_init_command_str(STUN_METHOD_REGISTER,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    nmac = hashlib.sha256()
    nmac.update(pwd)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,nmac.hexdigest())
    stun_add_fingerprint(buf)
    print "buf len",len(''.join(buf))

def stun_login_request(buf,uname,pwd):
    stun_init_command_str(STUN_METHOD_BINDING,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    obj = hashlib.sha256()
    obj.update(pwd)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,obj.hexdigest())
    #filed = "%08x" % UCLIENT_SESSION_LIFETIME
    filed = "%08x" % 30
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)

def stun_connect_peer_with_uuid(buf,uuid):
    stun_init_command_str(STUN_METHOD_CONNECT,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_UUID,binascii.hexlify(uuid))
    stun_add_fingerprint(buf)


    

def stun_contract_allocate_request(buf):
    stun_init_command_str(STUN_METHOD_BINDING,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify("lcy"))
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    print "buf is",buf


def stun_xor_peer_address(host,port):
    cfiled = []
    cfiled.append('0001')
    xor_port = (port ^ (STUN_MAGIC_COOKIE >> 16)) & 0xFFFF
    cfiled.append("%04x" % port)
    xor_addr = host ^ STUN_MAGIC_COOKIE
    cfiled.append("%08x" % host)
    return ''.join(cfiled)

def stun_add_fingerprint(buf):
    stun_attr_append_str(buf,STUN_ATTRIBUTE_FINGERPRINT,'00000000')
    crc_str = ''.join(buf[:-3])
    print "crc_str",crc_str
    crcval = binascii.crc32(binascii.unhexlify(crc_str))
    crcstr = "%08x" % ((crcval  ^ 0x5354554e) & 0xFFFFFFFF)
    buf[-1] = crcstr.replace('-','')
    



#### Refresh Request ######
def stun_refresh_request(sock,host,port):
    buf =[]
    global last_request
    print "refresh time"
    stun_struct_refresh_request(buf)
    sdata = binascii.a2b_hex(''.join(buf))
    last_request = buf
    sock.send(sdata)


def stun_struct_refresh_request(buf):
    stun_init_command_str(STUN_METHOD_REFRESH,buf)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_add_fingerprint(buf)
    
########## handle response packets ##############

def stun_make_type(method):
    method  = method & 0x0FFF
    return ((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0380) << 2) | ((method & 0x0C00) << 2))

def stun_make_success_response(method):
    return ((stun_make_type(method) & 0xFEEF) | 0x0100)

def stun_get_method_str(method):
    id = method & 0x3FFF 
    return int(( id & 0x000F) | ((id & 0x00E0) >> 1)|
        ((id & 0x0E00)>>2) | ((id & 0x3000)>>2))

def stun_tranid_from_msg(buf):
    print "tranid is",buf[16:16+24]
    return buf[16:16+24]

def is_channel_msg_str(mth):
    return (mth >= 0x4000) and (mth <= 0x7FFF) 


def stun_is_success_response_str(mth):
    if is_channel_msg_str(mth): return False
    flag = ((mth & 0x0110 ) == 0x0100)
    return ((mth & 0x0110 ) == 0x0100)

def get_first_attr(response,res):
    attr_name = response[:4]
    pos = 0
    print "attr_name",attr_name
    fmt =''
    if attr_name == STUN_ATTRIBUTE_LIFETIME:
        fmt = '!HHI'
    elif attr_name == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
        fmt = '!HH2sHI'
    elif attr_name == STUN_ATTRIBUTE_FINGERPRINT:
        fmt = '!HHI'
    else:
        return 0
    attr_size = struct.calcsize(fmt)
    pos += attr_size*2
    res[attr_name] = struct.unpack(fmt,binascii.unhexlify(response[:attr_size*2]))
    return pos

def stun_handle_response(response,result):
    global last_request
    global channel_number
    res = -1
    ss = struct.Struct(STUN_STRUCT_FMT)
    hexpos = struct.calcsize(STUN_STRUCT_FMT)*2
    rdict = {}
    rdict['header'] = recv_header = ss.unpack(binascii.unhexlify(response[:hexpos]))
    
    send_header = ss.unpack(binascii.a2b_hex(''.join(last_request[:4])))
    res_mth = "%04x" % stun_get_method_str(recv_header[0])
    rdict['rmethod'] = res_mth
    print "This method is",res_mth,"send method is",send_header[0]
    result.append(res_mth)
    result.append('%04x' % recv_header[1])
    result.append('%04x' % recv_header[2])
    result.append(binascii.hexlify(recv_header[3]))
    if res_mth !=  ("%04x" % send_header[0]):
        print "Received wrong response method:",response[:4],"expected :",last_request[0]
        return rdict
    if cmp(recv_header[3:],send_header[3:]) != 0:
        print "Received wrong response tranid; trying again...."
        return  rdict

    if stun_is_success_response_str(recv_header[0]) == False:
        print "Not success response"
        return  rdict
    hexpos = 40
    blen = len(response)
    while hexpos < blen:
        n = get_first_attr(response[hexpos:],rdict)
        if n == 0:
            print "Unkown Attribute"
            return rdict
        else:
            hexpos += n

    if res_mth == STUN_METHOD_BINDING: # 登录
        print "Allocate success_allocate"
        res = STUN_METHOD_BINDING
    elif res_mth == STUN_METHOD_REFRESH: #刷新
        res = STUN_METHOD_REFRESH
        pass  # 这里暂略过，假定时间一直有效
    elif res_mth == STUN_METHOD_CONNECT: # 连接小机
        print "handle connect"
        res = STUN_METHOD_CONNECT
    elif res_mth ==STUN_METHOD_CHECK_USER: #注册时，检查用户名
        print "Check User"
        res = res_mth
    elif res_mth == STUN_METHOD_REGISTER: #注册新的用户名
        print "Register"
        res = res_mth
    return rdict


def stun_setLogin(sock,host,port):
    buf = []
    global last_request
    global success_allocate
    xor_port = 0
    xor_addr = ''
    response_result = []
    #stun_contract_allocate_request(buf)
    #stun_register_request(buf,'lcy','test')
    stun_check_user_valid(buf,'lcy')
    #stun_login_request(buf,'lcy','test') 
    print "send buf",buf
    sdata = binascii.a2b_hex(''.join(buf))
    last_request = buf
    sock.bind(('',54321))
    #sock.sendto(sdata,(host,port))
    sock.connect((host,port))
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
                continue

            if rdict['rmethod'] == STUN_METHOD_BINDING:
                print "thread start"
                response_result = []
                #refresh  = threading.Timer(3,stun_refresh_request,(sock,host,port))
                #refresh.start()
                buf = []
                uid = "ce8f91f82ff423da42d977177d365e84"
                stun_connect_peer_with_uuid(buf,uid) 
                last_request = buf
                sock.send(binascii.a2b_hex(''.join(buf)))
            elif rdict['rmethod'] == STUN_METHOD_REFRESH:
                #refresh  = threading.Timer(3,stun_refresh_request,(sock,host,port))
                #refresh.start()
                print "app refresh time"
            elif rdict['rmethod'] == STUN_METHOD_CONNECT:
                if rdict.has_key(STUN_ATTRIBUTE_MESSAGE_ERROR_CODE):
                    pass
                # 可以去连接对端了
                else:
                    if rdict.has_key(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS):
                        phost = rdict[STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS][-2:]
                        break
            else:
                print "Command error"
    return
    sock.close()
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if len(phost) != 2: return
    print "phost",phost
    hhh = socket.inet_ntoa(binascii.unhexlify("%x" % (phost[1] ^ STUN_MAGIC_COOKIE)))
    ppp = phost[0] ^  (STUN_MAGIC_COOKIE >> 16)
    print "xor phost",  hhh,ppp

    print "connect peer",hhh,ppp
    sock.bind(('',54321))
    print "local",sock.getsockname()
    sock.connect((hhh,ppp))
    print "remote",sock.getpeername()
    sock.send("Hi I'm app")
    while True:
        data = sock.recv(2048)
        sock.send("Hi I'm app")
        if not data:
            break
        else:
            print data
            sock.send("I'am app %s" % time.time())
        time.sleep(1)

def connect_turn_server():
    srv_host = '192.168.8.9'
    #srv_host = '192.168.56.1'
    srv_port = 3478
    #srv_port = 3478
    #sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    stun_setLogin(sock,srv_host,srv_port)


ehost = [] # 外部地址
phost = [] # 对端地址
def main():
    connect_turn_server()

if __name__ == '__main__':
    main()

