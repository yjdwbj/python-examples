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
from epoll_global import *

class ThreadRefreshTime(threading.Thread):
    def __init__(self,sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self.rtime = binascii.unhexlify(''.join(stun_struct_refresh_request()))

    def run(self):
        while self.sock:
            self.sock.send(self.rtime)
            time.sleep(30)


def stun_register_request(uname,pwd):
    buf = []
    stun_init_command_str(STUN_METHOD_REGISTER,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    nmac = hashlib.sha256()
    nmac.update(pwd)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,nmac.hexdigest())
    stun_add_fingerprint(buf)
    print "register buf is",buf
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
    print "login buf is",buf
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
    print "buf is",buf




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



def stun_setLogin(host,port):
    buf = []
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    response_result = []
    #stun_contract_allocate_request(buf)
    buf = stun_register_request('jl1','1234')
    #stun_register_request(buf,'lcy','1234')
    #stun_check_user_valid(buf,'lcy333')
    #stun_login_request(buf,'lcy','test') 
    #stun_struct_refresh_request(buf)
    #uid = "ab8f91f82ff423db42d977177d365e84"
    #uid = "ce8f91f82ff423da42d977177d365963"
    uid = "ab8f5f82ff423db42d97c7177dc38920"
    #uid = "ab8f5f82ff423db42d97c7177dc31159"
    #uid ="aaa7de16db28436dbccfc9481c18a0ce26537166"
    uid ='19357888aa07418584391d0adb61e79026537166'
    #uid='2860014389504773b2c2b7252d3eb8b074657374'
    #ruuid = ''.join([uid,("%08x" % get_uuid_crc32(uid))])
    #buf = stun_connect_peer_with_uuid(ruuid,'lcy','1234') 
    print "send buf",buf
    sdata = binascii.a2b_hex(''.join(buf))
    sock.bind(('',0))
    sock.connect((host,port))
    sock.send(sdata)
    while True:
        data,addr = sock.recvfrom(2048)
        if not data:
            break
        else:
            myrecv = binascii.b2a_hex(data)
            print "recv buf",myrecv
            if check_packet_vaild(myrecv): # 校验包头
                print "unkown packet"
                break

            hattr = get_packet_head_class(myrecv[:STUN_HEADER_LENGTH*2])

            rdict = parser_stun_package(myrecv[STUN_HEADER_LENGTH*2:-8]) # 去头去尾
            if not stun_is_success_response_str(hattr.method):
                print "server response error"
                print errDict.get(rdict[STUN_ATTRIBUTE_MESSAGE_ERROR_CODE][-1])
                continue

            hattr.method = stun_get_type(hattr.method)

            if hattr.method  == STUN_METHOD_BINDING:
                print "thread start"
                refresh  = ThreadRefreshTime(sock)
                refresh.start()
            if hattr.method == STUN_METHOD_REGISTER:
                buf = stun_login_request('jl1','1234')
                sock.send(binascii.unhexlify(''.join(buf)))
            elif hattr.method  == STUN_METHOD_REFRESH:
                #refresh  = threading.Timer(3,stun_refresh_request,(sock,host,port))
                #refresh.start()
                print "app refresh time"
            elif hattr.method == STUN_METHOD_CHANNEL_BIND:
                # 绑定小机命令o
                pass
            else:
                print "Command error"
    srvport = sock.getsockname()[1]
    print phost
    sock.close()
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if len(phost) != 2:
        return
    print "phost",phost
    hhh = socket.inet_ntoa(binascii.unhexlify("%x" % (phost[1] ^ STUN_MAGIC_COOKIE)))
    ppp = phost[0] ^  (STUN_MAGIC_COOKIE >> 16)
    print "xor phost",  hhh,ppp
    print "connect peer",hhh,ppp
    sock.bind(('',srvport))
    print "local",sock.getsockname()
    n = 20
    while n > 0:
        try:
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
        except:
            print "connect peer occur error"
        n -=1
        time.sleep(1)

def connect_turn_server():
    #srv_host = '120.24.235.68'
    srv_host = '192.168.8.9'
    #srv_host = '192.168.56.1'
    srv_port = 3478
    #srv_port = 3478
    #sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    #connect_devid_from_file(srv_host,srv_port)
    stun_setLogin(srv_host,srv_port)


ehost = [] # 外部地址
phost = [] # 对端地址
def main():
    connect_turn_server()

if __name__ == '__main__':
    main()

