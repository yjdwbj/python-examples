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

#Lifetimes
STUN_DEFAULT_ALLOCATE_LIFETIME=int(600)
UCLIENT_SESSION_LIFETIME=int(777)

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

def gen_channel_number():
    global channel_number
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(4))
    port = 0x4000 + (struct.unpack('H',binascii.unhexlify(a))[0]  % (0x7FFF - 0x4000+1))
    channel_number = port
    return port

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

def stun_attr_software_gen():
    return binascii.hexlify("Python 'lcy'")



def stun_contract_allocate_request(buf):
    stun_init_command_str(STUN_METHOD_ALLOCATE,buf)
    filed = "%08x" % socket.htonl(STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_REQUESTED_TRANSPORT,filed)
    filed = "%08x" % UCLIENT_SESSION_LIFETIME
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,filed)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DONT_FRAGMENT,'')
    stun_attr_append_str(buf,STUN_ATTRIBUTE_SOFTWARE,stun_attr_software_gen())
    stun_attr_append_str(buf,STUN_ATTRIBUTE_EVENT_PORT,'80')
    #buf[-1]="%s000000" % buf[-1]  # 这个是为
    stun_add_fingerprint(buf)
#### Create-Permission Request ####

def stun_create_permission_request(buf,host,port):
    stun_init_command_str(STUN_METHOD_CREATE_PERMISSION,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_PEER_ADDRESS,stun_xor_peer_address(host,port))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_SOFTWARE,stun_attr_software_gen())
    stun_add_fingerprint(buf)



#### Channel-Bind #######
def stun_channel_bind_request(buf,host,port):
    stun_struct_cbr(buf,host,port)
    

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
    crcval = zlib.crc32(binascii.a2b_hex(crc_str))
    crcstr = "%08x" % ((crcval  ^ 0x5354554e) & 0xFFFFFFFF)
    buf[-1] = crcstr.replace('-','')
    

def stun_struct_cbr(buf,host,port):
    global success_allocate
    stun_init_command_str(STUN_METHOD_CHANNEL_BIND,buf)
    channel_number = "%04x" % gen_channel_number()
    stun_attr_append_str(buf,STUN_ATTRIBUTE_CHANNEL_NUMBER,"%s0000" % channel_number)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_PEER_ADDRESS,stun_xor_peer_address(host,port))
    stun_add_fingerprint(buf)


#### Refresh Request ######
def stun_refresh_request(sock,host,port):
    buf =[]
    global last_request
    stun_struct_refresh_request(buf)
    #print "Refresh %s and Len %d" % (buf,len(buf))
    sdata = binascii.a2b_hex(''.join(buf))
    last_request = buf
    sock.sendto(sdata,(host,port))


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

def stun_get_first_attr(response,response_result):
    attr_name = response[:4]
    pos = 0
    if attr_name in dictAttrStruct:
        attr_size = struct.calcsize(dictAttrStruct[attr_name])
        pos += attr_size*2
        res = struct.unpack(dictAttrStruct[attr_name],binascii.unhexlify(response[:attr_size*2]))
    elif attr_name == STUN_ATTRIBUTE_SOFTWARE:
        fmt = '!HH%ds' % (int("0x%s" % response[4:8],16) & 0xFFFF)
        attr_size = struct.calcsize(fmt)
        pos += attr_size*2
        res = struct.unpack(fmt,binascii.unhexlify(response[:attr_size*2]))
    if res:
        response_result.append(res)
    return pos

        

def stun_get_dict_header(dict,struct_str):
    dict['method'] =  "%04x" % struct_str[0]
    dict['len'] = '%04x' % struct_str[1]
    dict['cookie'] = '%08x'% struct_str[2]
    dict['tranid'] = binascii.hexlify(struct_str[3])
    

def stun_handle_allocate_response(hexpos,blen,response,result):
    while hexpos < blen:
        hexpos += stun_get_first_attr(response[hexpos:],result)

def stun_handle_response(response,result):
    global last_request
    global channel_number
    res = -1
    ss = struct.Struct(STUN_STRUCT_FMT)
    hexpos = struct.calcsize(STUN_STRUCT_FMT)*2
    recv_header= ss.unpack(binascii.unhexlify(response[:hexpos]))
    send_header = ss.unpack(binascii.a2b_hex(''.join(last_request[:4])))
    res_mth = stun_get_method_str(recv_header[0])
    print "This method is",res_mth
    result.append(res_mth)
    result.append('%04x' % recv_header[1])
    result.append('%04x' % recv_header[2])
    result.append(binascii.hexlify(recv_header[3]))
    if res_mth != send_header[0]:
        print "Received wrong response method:",response[:4],"expected :",last_request[0]
        return res
    if cmp(recv_header[3:],send_header[3:]) != 0:
        print "Received wrong response tranid; trying again...."
        return  res

    if stun_is_success_response_str(recv_header[0]) == False:
        return  res

    if res_mth == int(STUN_METHOD_ALLOCATE,16):
        stun_handle_allocate_response(hexpos,len(response),response,result)
        res = STUN_METHOD_ALLOCATE
    elif res_mth == int(STUN_METHOD_REFRESH,16):
        res = STUN_METHOD_REFRESH
        pass  # 这里暂略过，假定时间一直有效
    elif res_mth == int(STUN_METHOD_CHANNEL_BIND,16):
        print "handle channel bind"
        res = STUN_METHOD_CHANNEL_BIND
    elif res_mth == int(STUN_METHOD_CREATE_PERMISSION,16):
        print "handle channel bind"
        res = STUN_METHOD_CREATE_PERMISSION


    return res


def stun_setAllocate(sock,host,port):
    buf = []
    global last_request
    global success_allocate
    xor_port = 0
    xor_addr = ''
    response_result = []
    stun_contract_allocate_request(buf)
    sdata = binascii.a2b_hex(''.join(buf))
    last_request = buf
    sock.bind(('',56780))
    sock.sendto(sdata,(host,port))
    while True:
        data,addr = sock.recvfrom(2048)
        if not data:
            break
        else:
            myrecv = binascii.b2a_hex(data)
            if stun_handle_response(myrecv,response_result) == STUN_METHOD_ALLOCATE:
                refresh  = threading.Timer(60,stun_refresh_request,(sock,host,port))
                refresh.start()
                nbuf = []
                xor_port = response_result[4][3]
                xor_addr = response_result[4][4]
                stun_channel_bind_request(nbuf,xor_addr,xor_port)
                last_request = nbuf
                sock.sendto(binascii.a2b_hex(''.join(nbuf)),addr)
                response_result = []
            elif stun_handle_response(myrecv,response_result) == STUN_METHOD_REFRESH:
                response_result = []
                pass
            elif stun_handle_response(myrecv,response_result) == STUN_METHOD_CHANNEL_BIND:
                print "Channel bind success"
                nbuf = []
                stun_create_permission_request(nbuf,xor_addr,xor_port)
                last_request = nbuf
                sock.sendto(binascii.a2b_hex(''.join(nbuf)),addr)
                response_result = []
            elif stun_handle_response(myrecv,response_result) == STUN_METHOD_CREATE_PERMISSION:
                print "Create Permission success"
                break

    len = 170
    head = "%04x%04x" % (channel_number,len)
    sdata = ''.join(random.choice('0123456789ABCDEF') for i in range(len*2))
    last_request = [head,data]
    while True:
        sock.sendto(binascii.a2b_hex(''.join([head,sdata])),(host,port))
        data,addr = sock.recvfrom(2048)
        myrecv = binascii.b2a_hex(data)
        if myrecv[:4] == STUN_METHOD_REFRESH:
            pass
        elif myrecv[:4] == "%04x" % channel_number:
            print "Recv data",myrecv[8:]
        response_result = []
        time.sleep(10)

                        
def connect_turn_server():
    srv_host = '192.168.56.1'
    srv_port = 3478
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    stun_setAllocate(sock,srv_host,srv_port)


def main():
    connect_turn_server()

if __name__ == '__main__':
    main()

