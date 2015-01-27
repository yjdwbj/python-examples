#coding=utf-8
#####################################################################
# lcy
#                                                                   #
#                                                                   #
#
#
####################################################################
import socket
import time
import struct
import binascii
import threading
import uuid
import sys
import unittest
import argparse

from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql,and_
from sqlalchemy.dialects import postgresql as pgsql
sys.path.insert(0,'/usr/local/lib/python2.7/dist-packages/psycopg2')
import _psycopg
sys.modules['psycopg2._psycopg'] = _psycopg
sys.path.pop(0)
import psycopg2
import hashlib
import select
import logging
from logging import handlers
from epoll_global import *


class GetPkgObj:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)

class DictClass:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)

class ComState: pass

def delete_fileno(fileno):
    epoll.unregister(fileno)
    if gClass.clients.has_key(fileno):
        gClass.clients.get(fileno).close()
        gClass.clients.pop(fileno)


def handle_client_request(buf,fileno):
    """
    -1 CRC 错误的
    -2 非法刷新请求
    0  正常值
    1  APP的连接请求
    2  小机的回复
    """
    #print "handle allocate request\n"

    try:
        reqhead = struct.unpack(STUN_HEADER_FMT,binascii.unhexlify(buf[:STUN_HEADER_LENGTH*2]))
    except:
        log.error("unpack head is wrong  %s" % buf[:STUN_HEADER_LENGTH*2])
        delete_fileno(fileno)
        return ([],-1)

    method = '%04x' % reqhead[-2]
    if not gClass.timer.has_key(fileno):
        if method == STUN_METHOD_REFRESH:  # 非法刷新请求
            log.info("Wrong Request. Host: %s:%d" % gClass.clients[fileno].getpeername())
            delete_fileno(fileno)
            return ([],-2)

    res = ComState()
    # = binascii.hexlify(reqhead[-1]).lower()
    res.host = gClass.clients.get(fileno).getpeername()
    res.fileno = fileno
    res.method = method
    hexpos = STUN_HEADER_LENGTH*2
    upkg = parser_stun_package(buf[hexpos:-8],res)
    if not (type(upkg) is dict):
        res.eattr = STUN_ERROR_UNKNOWN_ATTR
        log.error("Unkown Attribute %s %s" % (res['eattr'],buf[hexpos:]))
        return  (stun_attr_error_response(res),0)

    res.attrs = upkg
    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME) and method != STUN_METHOD_REFRESH:
        update_refresh_time(fileno,res.attrs.get(STUN_ATTRIBUTE_LIFETIME)[-1])

    if res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) and res.attrs.get(STUN_ATTRIBUTE_MESSAGE_INTEGRITY)[1] != 32:
        #res.eattr = binascii.hexlify('Password is to short')
        res.eattr = STUN_ERROR_UNAUTH
        log.error("Pasword is to short. Host: %s:%d" % gClass.clients[fileno].getpeername())
        return  (stun_attr_error_response(res),0)



    if dictMethod.has_key(method):
        #if gClass.uuids.has_key(): # 小机收到服务器转发的连接请求，回复APP
        #    sock = gClass.uuids[]
        #    thost = gClass.clients[fileno].getpeername()
        #    gClass.uuids.pop()
        #    gClass.responses[sock] = stun_connect_address(thost,res)
        #    epoll.modify(sock,select.EPOLLOUT)
        #    return ([],2)

        return  dictMethod[method](res)
        #if method == STUN_METHOD_CONNECT and not buf:
        #    return ([],1)
        #else:
        #    return (buf,0)
    else:
        res.eattr = STUN_ERROR_UNKNOWN_METHOD
        log.error("Unkown Method %s %s" % (res['eattr'],buf[hexpos:]))
        return  (stun_attr_error_response(res),0)

def bind_each_uuid(ustr,fileno):
    if not gClass.appbinds.has_key(fileno):
        gClass.appbinds[fileno]={}
    if gClass.devuuid.has_key(ustr):
        # 通知在线的小机，有APP要绑定它
        b = '%08x' % gClass.devuuid[ustr]
        gClass.appbinds[fileno][ustr]= b
        gClass.responses[fileno] = notify_peer(''.join([b,STUN_ONLINE]))
        epoll.modify(gClass.devuuid[ustr],select.EPOLLOUT)
    else:
        gClass.appbinds[fileno][ustr]='%08x' % 0xFFFFFFFF




def handle_app_bind_device(res):
    #绑定小机的命的命令包
    if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
        chk = check_jluuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1]))
        if chk:
            res.eattr = chk
            log.error("UUID Packet Error. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
            return stun_attr_error_response(res)
    elif res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
        mlist =  split_muuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_MUUID][-1]))
        p = [check_jluuid(n) for n in mlist]
        e = [ x for x in p if x]
        if len(e):
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            #log.info("Not UUID Attribute. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
            return stun_attr_error_response(res)
        [bind_each_uuid(n,res.fileno) for n in mlist]
    else:
        res.eattr = STUN_ERROR_UNKNOWN_PACKET
        log.info("Not UUID Attribute. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
        return stun_attr_error_response(res)

    return stun_bind_devices_ok(res)


def stun_bind_devices_ok(res):
    """
    绑定成功，回复APP
    """
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    joint = [''.join([k,v]) for k,v in gClass.appbinds[res.fileno].iteritems()]
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MRUUID,''.join(joint))
    stun_add_fingerprint(buf)
    return (buf)

def notify_peer(state_info):
    buf = []
    stun_init_command_str(STUN_METHOD_NOTIFY,buf)
    stun_attr_append_str(STUN_ATTRIBUTE_STATE,state_info)
    stun_add_fingerprint(buf)
    return buf

def handle_app_login_request(res):
    gClass.appsock[res.fileno] = tcs = ComState()
    if not res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) or  not res.attrs.has_key(STUN_ATTRIBUTE_USERNAME):
       res.eattr = binascii.hexlify("Not Authentication")
       return  stun_attr_error_response(res)# APP端必须带用认证信息才能发起连接.

    result = app_user_login(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1])
    #result = app_user_login(res.attrs[STUN_ATTRIBUTE_UUID][-1],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1])
    print "login result",result
    if not result:
        res.eattr = binascii.hexlify("Unauthorised")
        return  stun_attr_error_response(res)
    #jluid = ''.join([str(result[0][0]).replace('-',''),'%08x' % 0])
    #tcs.uuid = make_uuid(jluid)
    gClass.actives[res.fileno] = res.attrs[STUN_ATTRIBUTE_USERNAME]
    tcs.name = result[0][1]
    app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.host)
    return app_user_auth_success(res)

def handle_app_send_data_to_device(res): # APP 发给小机的命令
    if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
        chk = check_jluuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1]))
        if chk:
            res.eattr = chk
            log.error("UUID Packet Error. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
            return stun_attr_error_response(res)
    else:
        res.eattr = binascii.hexlify("Not Found UUID")
        log.info("Not UUID Attribute. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
        return stun_attr_error_response(res)

    row = find_device_state(res.attrs[STUN_ATTRIBUTE_UUID][-1])
    if not row:
        res.eattr = binascii.hexlify("!not device!")
        return  stun_attr_error_response(res)
        #设备不存在
    else:
        rlist = list(row[0])
        if rlist[1] == False: # 设备没有激活
            res.eattr = binascii.hexlify("device disabled")
            return  stun_attr_error_response(res)

        huid = binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1])
        #if rlist[3] and mdict['uuids'].has_key(huid): # 下面是发一个包给小机，确认它一定在线,收到对方确认之后再回复APP
        if rlist[3] and gClass.uuids.has_key(huid): # 下面是发一个包给小机，确认它一定在线,收到对方确认之后再回复APP
            sock = gClass.uuids.__dict__.get(res.fileno)
            if not gClass.clients.has_key(sock):
                res.eattr = binascii.hexlify('device offline')
                return  stun_attr_error_response(res)

            try:#这里先去告诉小机，有一个客户端要连接它
                gClass.timer[sock] += FINDDEV_TIMEOUT
                res.eattr = binascii.hexlify("Check mirco_devices timeout")
                asktimer = threading.Timer(FINDDEV_TIMEOUT,stun_ask_mirco_devices_timeout, (res))
                asktimer.start()
                #mdict['responses'][sock] = stun_connect_address(res['host'],res)
                gClass.responses[sock] = stun_connect_address(res.host,res)
                epoll.modify(sock,select.EPOLLOUT)
            except IOError:
                log.error("microc_devices sock has closed")
        else:
            res.eattr = binascii.hexlify('device offline')
            return  stun_attr_error_response(res)



def handle_device_send_data_to_app(res): # 小机发给APP 的命令
    pass


def handle_app_connect_peer_request(res):
    if not res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) or  not res.attrs.has_key(STUN_ATTRIBUTE_USERNAME):
       res.eattr = binascii.hexlify("Not Authentication")
       return  stun_attr_error_response(res)# APP端必须带用认证信息才能发起连接.

    # 检查用户名与密码
    if not app_user_login(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1]):
        res.eattr = binascii.hexlify("Unauthorised")
        return  stun_attr_error_response(res)

    chk = check_jluuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1]))
    if chk:
        res.eattr = chk
        log.error("UUID Packet Error. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
        return stun_attr_error_response(res)

    app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.host)
    #mdict['actives'][res['fileno']] = res[STUN_ATTRIBUTE_USERNAME]
    #gClass.actives[res.fileno] = res.attrs[STUN_ATTRIBUTE_USERNAME]
    row = find_device_state(res.attrs[STUN_ATTRIBUTE_UUID][-1])
    #mdict['uuids'][res['tid']] = res['fileno'] # 这里用APP 端TID做键,后面要用到
    if not row:
        res.eattr = binascii.hexlify("!not device!")
        return  stun_attr_error_response(res)
        #设备不存在
    else:
        rlist = list(row[0])
        if rlist[1] == False: # 设备没有激活
            res.eattr = binascii.hexlify("device disabled")
            return  stun_attr_error_response(res)

        huid = binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1])
        #if rlist[3] and mdict['uuids'].has_key(huid): # 下面是发一个包给小机，确认它一定在线,收到对方确认之后再回复APP
        if rlist[3] and gClass.uuids.has_key(huid): # 下面是发一个包给小机，确认它一定在线,收到对方确认之后再回复APP
            #sock = mdict['uuids'][huid]
            sock = gClass.uuids.sock
            #if not mdict['clients'].has_key(sock):
            if not gClass.clients.has_key(sock):
                #return  stun_mirco_device_error('device offline',res['tid'])
                res.eattr = binascii.hexlify('device offline')
                return  stun_attr_error_response(res)

            try:#这里先去告诉小机，有一个客户端要连接它
                #print "send ask package to the mirco_devices",mdict['clients'][sock].getpeername()
                #mdict['timer'][sock] += FINDDEV_TIMEOUT
                gClass.timer[sock] += FINDDEV_TIMEOUT
                res.eattr = binascii.hexlify("Check mirco_devices timeout")
                asktimer = threading.Timer(FINDDEV_TIMEOUT,stun_ask_mirco_devices_timeout, (res))
                asktimer.start()
                #mdict['responses'][sock] = stun_connect_address(res['host'],res)
                gClass.responses[sock] = stun_connect_address(res.host,res)
                epoll.modify(sock,select.EPOLLOUT)
            except IOError:
                log.error("microc_devices sock has closed")
        else:
            res.eattr = binascii.hexlify('device offline')
            return  stun_attr_error_response(res)

def stun_ask_mirco_devices_timeout(res):
    #超过一定时间，小机没有回复服务器，就假定小机不可以连接，回复APP端一个错误
    if gClass.uuids.has_key():
        gClass.responses[res.fileno] = stun_attr_error_response(res)
        try:
            epoll.modify(res.fileno,select.EPOLLOUT)
        except:
            log.error("app sock %d has closed" % res.fileno)


def stun_connect_address(host,res):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_CONNECT),buf,)
    mip = "0001%04x%08x" % (host[1]^ (STUN_MAGIC_COOKIE >> 16),
            STUN_MAGIC_COOKIE ^ (int(binascii.hexlify(socket.inet_aton(host[0])),16)))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,mip)
    if res.attrs.has_key(STUN_ATTRIBUTE_DATA): #转发小机的基本信息
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,binascii.hexlify(res.attrs[STUN_ATTRIBUTE_DATA][-1]))
    stun_add_fingerprint(buf)
    return (buf)


def stun_attr_error_response(res):
    buf = []
    stun_init_command_str(stun_make_error_response(res.method),buf,)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_MESSAGE_UNKNOWN_ATTRIBUTES,res.eattr)
    stun_add_fingerprint(buf)
    return (buf)

def handle_register_request(res):
    #nuuid = str(uuid.uuid4()).replace('-','')
    if app_user_register(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],
            res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1]):
         # 用户名已经存了。
        log.debug("User has Exist!i %s" % res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
        res.eattr = STUN_ERROR_USER_EXIST
        return stun_attr_error_response(res)
    return register_success(res.attrs[STUN_ATTRIBUTE_USERNAME][-1])

def register_success(uname):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REGISTER),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(uname))
    stun_add_fingerprint(buf)
    log.debug("Regsiter is success %s" % uname)
    return (buf)

def handle_chkuser_request(res):
    f = check_user_in_database(res[STUN_ATTRIBUTE_USERNAME][-1])
    if f != 0:
        log.debug("User Exist %s" % res[STUN_ATTRIBUTE_USERNAME][-1])
        res.eattr = STUN_ERROR_USER_EXIST
        return stun_attr_error_response(res)
    else:
        return check_user_sucess(res)



def check_user_sucess(res):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf,)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(res.attrs[STUN_ATTRIBUTE_USERNAME][-1]))
    stun_add_fingerprint(buf)
    log.debug("User not register! %s" % res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
    return (buf)

def get_jluuid_crc32(uhex):
    ucrc = get_crc32(uhex[:-8])
    return "%08x" % ((ucrc ^ CRCPWD) & 0xFFFFFFFF)

def check_uuid_format(uid):
    n = [ x for x in binascii.hexlify(uid[-1]) if x > 'f' or x < '0']
    return  len(n) > 0 or uid[1] < 24

def check_uuid_valid(uhex):
    #print "my crc",crcstr,'rcrc',uhex[-8:]
    return cmp(get_jluuid_crc32(uhex[:-8]),uhex[-8:])

def check_jluuid(huid): # 自定义24B的UUID
    if 0 != check_uuid_valid(huid):
        return STUN_ERROR_UNKNOWN_PACKET

    if check_uuid_format(huid):
        return STUN_ERROR_UNKNOWN_PACKET
    return None

def handle_allocate_request(res):
    """
    小机登录服务器的命令，必须要有uuid,data
    """
    if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
        chk = check_jluuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1]))
        print 'chk is',chk
        if chk:
            res.eattr = chk
            log.error("UUID Packet Error. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
            return stun_attr_error_response(res)
    else:
        #res.eattr= binascii.hexlify("Not Found UUID")
        res.eattr=STUN_ERROR_UNKNOWN_PACKET
        #log.info("Not UUID Attribute. Host:%s:%d" % mdict['clients'][res['fileno']].getpeername())
        log.info("Not UUID Attribute. Host:%s:%d" % gClass.clients[res.fileno].getpeername())
        return stun_attr_error_response(res)

    huid = binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1])
    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
        gClass.timer[res.fileno] = time.time()+ res.attrs.get(STUN_ATTRIBUTE_LIFETIME,0)[-1]
    else:
        gClass.timer[res.fileno] = time.time() + UCLIENT_SESSION_LIFETIME

    if not res.attrs.has_key(STUN_ATTRIBUTE_DATA):
        res.data = ''
    res.vendor = huid[32:40]
    res.host = gClass.clients[res.fileno].getpeername()
    res.tuid = huid[:32]
    update_newdevice(res)
    gClass.actives[res.fileno] = huid
    gClass.devsock[res.fileno] = tcs = ComState()
    gClass.devuuid[huid] = res.fileno
    tcs.uuid = huid
    print "login devid is",tcs.uuid
    return device_login_sucess(res)

def app_user_auth_success(res):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_add_fingerprint(buf)
    return (buf)

def device_login_sucess(res): # 客服端向服务器绑定自己的IP
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_add_fingerprint(buf)
    return (buf)

def handle_refresh_request(res):
    update_refresh_time(res.fileno,res.attrs[STUN_ATTRIBUTE_LIFETIME][-1])
    return refresh_sucess(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1])

def refresh_sucess(ntime): # 刷新成功
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REFRESH),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % ntime)
    stun_add_fingerprint(buf)
    return (buf)
    #print "refresh response buf",buf

def update_refresh_time(fileno,ntime):
    gClass.timer[fileno] = time.time()+ntime


def app_user_register(user,pwd):
    account = get_account_table()
    dbcon = engine.connect()
    #print "register new account %s,%s" % (user,pwd)
    sss = sql.select([account]).where(account.c.uname == user)
    res = dbcon.execute(sss)
    if len(res.fetchall()):
        return True
    else:
        obj = hashlib.sha256()
        obj.update(user)
        obj.update(pwd)
        ins = account.insert().values(uname=user,pwd=obj.digest(),is_active=True,reg_time=datetime.now())
        try:
            dbcon.execute(ins)
        except:
            log.error("app_user_register error %s" % user)
            return True
        return False

def app_user_update_status(user,host):
    status_tables = get_account_status_table()
    ipadr = int(binascii.hexlify(socket.inet_aton(host[0])),16) & 0xFFFFFFFF
    ipprt = host[1] & 0xFFFF
    s = sql.select([status_tables]).where(status_tables.c.uname == user)
    dbcon = engine.connect()
    result = dbcon.execute(s)
    row = result.fetchall()
    #print "row is",row
    sss = 0
    if row:
        #修改
        sss = status_tables.update().values(last_login_time = datetime.now(),chost=[ipadr,ipprt]).where(status_tables.c.uname == user)
    else:
        sss = status_tables.insert().values(uname=user,is_login=True,chost=[ipadr,ipprt])
    try:
        result = dbcon.execute(sss)
    except:
        log.error("Update User Status to DB Occur Error %s:%d" % host)
        pass


def app_user_login(user,pwd):
    account = get_account_table()
    dbcon = engine.connect()
    obj = hashlib.sha256()
    #uhex = binascii.hexlify(uid)[:32]
    obj.update(user)
    obj.update(pwd)
    s = sql.select([account]).where(and_(account.c.uname == user,account.c.pwd == obj.digest(),
    #s = sql.select([account]).where(and_(account.c.uuid  == uhex,account.c.pwd == obj.digest(),
        account.c.is_active == True))
    try:
        result = dbcon.execute(s)
    except:
        log.error("(Login) Select User From DB Occur Error. UUID is %s" % tuid)
    return result.fetchall()


def get_account_status_table():
    metadata = MetaData()
    table = Table('account_status',metadata,
            Column('uname',pgsql.VARCHAR(255)),
            Column('is_login',pgsql.BOOLEAN,nullable=False),
            Column('last_login_time',pgsql.TIME,nullable=False),
            Column('chost',pgsql.ARRAY(pgsql.BIGINT),nullable=False)
            )
    return table

def get_account_table():
    metadata = MetaData()
    account = Table('%08x' % 0,metadata,
            Column('uuid',pgsql.UUID,primary_key=True),
            Column('uname',pgsql.VARCHAR(255),primary_key=True),
            Column('pwd',pgsql.BYTEA),
            Column('is_active',pgsql.BOOLEAN,nullable=False),
            Column('reg_time',pgsql.TIME,nullable=False)
            )
    return account

def check_user_in_database(uname):
    account = get_account_table()
    dbcon = engine.connect()
    s = sql.select([account.c.uname]).where(account.c.uname == uname)
    try:
        result = dbcon.execute(s)
    except:
        log.error("Check User %s" % uname)
        log.error("from DB Occur Error. Host: %s:%d" % gClass.clients[fileno].getpeername())
    return result.fetchall()

def get_devices_table(tname):
    metadata = MetaData()
    mirco_devices = Table(tname,metadata,
            Column('devid',pgsql.UUID,primary_key=True),
            Column('is_active',pgsql.BOOLEAN,nullable=False),
            Column('last_login_time',pgsql.TIMESTAMP,nullable=False),
            Column('is_online',pgsql.BOOLEAN,nullable=False),
            Column('chost',pgsql.ARRAY(pgsql.BIGINT),nullable=False),
            Column('data',pgsql.BYTEA)
            )
    return mirco_devices


def find_device_state(uid):
    try:
        suid = struct.unpack(STUN_UVC,uid)
    except:
        log.error('unpck is occur error %s' % binascii.hexlify(uid))
        return None 
    vendor = binascii.hexlify(suid[1])
    #print "find uuid is",uid,"vendor is",vendor
    dbcon = engine.connect()
    mirco_devices = get_devices_table(vendor)
    if not mirco_devices.exists(engine):
        return None
    s = sql.select([mirco_devices]).where(mirco_devices.c.devid == binascii.hexlify(suid[0]))
    try:
        result = dbcon.execute(s)
        return result.fetchall()
    except:
        log.error("Find UUID From DB Occur Error. UUID is %s" % binascii.hexlify(uuid))
        return None


def update_newdevice(res):
    '''添加新的小机到数据库'''
    #tuid = binascii.hexlify(pair[0])
    #print "vendor is",binascii.hexlify(pair[1])
    #print "uid is",uid[:UUID_SIZE*2],"vendor is",vendor
    dbcon = engine.connect()
    #mirco_devices = get_devices_table(binascii.hexlify(pair[1]))
    mirco_devices = get_devices_table(res.vendor)
    if not mirco_devices.exists(engine):
        mirco_devices.create(engine)
    s = sql.select([mirco_devices.c.devid]).where(mirco_devices.c.devid == res.tuid)
    row = ''
    try:
        result = dbcon.execute(s)
        row = result.fetchall()
    except:
        log.error("Select UUID From DB Occur Error. UUID is %s" % res.tuid)
    ipadr = int(binascii.hexlify(socket.inet_aton(res.host[0])),16) & 0xFFFFFFFF
    ipprt = res.host[1] & 0xFFFF
    #print "host %d:%d" % (ipadr,ipprt)
    if not row: # 找不到这个UUID 就插入新的
        ins = mirco_devices.insert().values(devid=res.tuid,is_active=True,
                is_online=True,chost=[ipadr,ipprt],data=res.data,last_login_time=datetime.now())
        try:
            result = dbcon.execute(ins)
        except:
            log.error("Insert UUID To DB Occur Error. UUID is %s" % res.tuid)
        #print "insert new devices result fetchall"
    else:
        upd = mirco_devices.update().values(is_online=True,chost = [ipadr,ipprt],data=res.data,
                last_login_time=datetime.now()).where(mirco_devices.c.devid == res.tuid)
        try:
            result = dbcon.execute(upd)
        except:
            log.error("Update UUIDTo DB Occur Error. UUID is %s" % res.tuid)

class CheckSesionThread(threading.Thread):
    def run(self):
        #print 'mdict[timer]',mdict['timer']
        while True:
            time.sleep(1)
            #[clean_timeout_sock(x)  for x in  mdict['timer'].keys()]
            [clean_timeout_sock(x)  for x in  gClass.timer.keys()]

def clean_timeout_sock(fileno): # 清除超时的连接
    #print 'mdict[timer][%d]' % fileno,mdict['timer'][fileno]
    if gClass.timer.has_key(fileno):
        if gClass.timer[fileno] < time.time():
            log.debug("Client %d life time is end,close it" % fileno )
            epoll.unregister(fileno)
            #print "mdict[uuids] is",mdict['uuids']
            if gClass.clients.has_key(fileno):
                gClass.clients[fileno].close()
            remove_fileno_resources(fileno)

def mirco_devices_logout(devid):
#    try:
#        suid = struct.unpack(STUN_UVC,devid)
#    except:
#        log.error('unpck is occur error %s' % binascii.hexlify(devid))
#        return 0
    vendor = devid[32:40]
    #print "update status for tuid",binascii.hexlify(suid[0])
    mtable = get_devices_table(vendor)
    conn = engine.connect()
    #ss = mtable.update().values(is_online=False).where(mtable.c.devid == binascii.hexlify(suid[0]))
    ss = mtable.update().values(is_online=False).where(mtable.c.devid == devid[:32])
    try:
        res = conn.execute(ss)
    except IOError:
        log.error("Update UUID  Logout Status To DB Occur Error. UUID is %s" % devid[:32])
        return 0

def app_user_logout(uname):
    print uname,"logout"
    atable = get_account_status_table()
    conn = engine.connect()
    ss = atable.update().values(is_login=False).where(atable.c.uname == uname)
    try:
        res = conn.execute(ss)
    except :
        log.error("Update User  Logout Status To DB Occur Error. User is %s" % uname)


def sock_fail_pass(fileno):
    # sock 关闭时产生的异常处理
    epoll.unregister(fileno)
    if gClass.appsock.has_key(fileno): #更新相应的数据库在线状态
        app_user_logout(gClass.appsock[fileno].name)
        gClass.appsock.pop(fileno)
    elif gClass.devsock.has_key(fileno):
        mirco_devices_logout(gClass.devsock[fileno].uuid)
        gClass.devsock.pop(fileno)

    remove_fileno_resources(fileno)

def remove_fileno_resources(fileno):
    for k in gClass.__dict__:
        if gClass.__dict__[k].has_key(fileno):
            gClass.__dict__[k].pop(fileno)

    #for k in store:
    #    if mdict[k].has_key(fileno):
    #        mdict[k].pop(fileno)


def Server(port):
    srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srvsocket.bind(('',port))
    srvsocket.listen(1)
    srvsocket.setblocking(0)
    log.info("Start Server")
    epoll.register(srvsocket.fileno(),select.EPOLLIN)
    mthread = CheckSesionThread()
    mthread.setDaemon(True)
    mthread.start()
    try:
        while True:
            events = epoll.poll(1)
            for fileno,event in events:
                if fileno == srvsocket.fileno(): #新的连接
                    try:
                        conn,addr = srvsocket.accept()
                    except:
                        log.error("Too many file opened")
                        continue
                    #print "new accept",conn.fileno()
                    #print "new clients",addr
                    log.info("new clientsi %s:%d" % addr)
                    conn.setblocking(0)
                    gClass.clients[conn.fileno()] = conn
                    gClass.responses[conn.fileno()] = []
                    gClass.timer[conn.fileno()] = 10
                    epoll.register(conn.fileno(),select.EPOLLIN)
                elif event & select.EPOLLIN: # 读取socket 的数据
                    try:
                        #mdict['requests'][fileno] = mdict['clients'][fileno].recv(SOCK_BUFSIZE)
                        gClass.requests[fileno] = gClass.clients[fileno].recv(SOCK_BUFSIZE)
                        #if check_packet_length_and_magic(gClass.requests[fileno]):
                        hbuf = binascii.b2a_hex(gClass.requests[fileno])
                        if check_packet_vaild(hbuf):
                            print hbuf
                            log.error('unkown packet format')
                            continue
                        rbuf = handle_client_request(hbuf,fileno)

                        if rbuf[1] < 0:  #出错与非法请求关闭就行了
                            delete_fileno(fileno)
                        elif rbuf[1] == 1:  # app端的连接小机请求
                            epoll.modify(fileno,select.EPOLLWRBAND)
                        elif rbuf[1] == 2:  # 小机端的回答，收到之后不用改状态
                            continue
                        else:
                            #mdict['responses'][fileno] = rbuf[0]
                            gClass.responses[fileno] = rbuf[0]
                            epoll.modify(fileno,select.EPOLLOUT)
                        #mdict['requests'].pop(fileno)
                        gClass.requests.pop(fileno)
                    except IOError:
                        sock_fail_pass(fileno)
                        log.debug("sock has closed %d" % fileno)
                elif event & select.EPOLLOUT:
                    try:
                        #if not mdict['responses'].has_key(fileno): #连接命令的时候返回是NULL
                        if not gClass.responses.has_key(fileno): #连接命令的时候返回是NULL
                            #epoll.modify(fileno,select.EPOLLIN)
                            log.debug("responses is null. Host: %s:%d" % gClass.clients[fileno].getpeername())
                            epoll.modify(fileno,select.EPOLLWRBAND)
                            continue
                        #nbyte =  mdict['clients'][fileno].send(binascii.a2b_hex(''.join(mdict['responses'][fileno])))
                        nbyte =  gClass.clients[fileno].send(binascii.a2b_hex(''.join(gClass.responses[fileno])))
                        #print "send %d byte" % nbyte
#                        if not stun_is_success_response_str(mdict['responses'][fileno][0][:4]): # 不正确的请求，关闭它。
#                            log.info("illegal request , Host: %s:%d" % mdict['clients'][fileno].getpeername())
#                            log.info("buf is %s " % ''.join(mdict['responses'][fileno]))
#                            mdict['clients'][fileno].close()
#                            epoll.unregister(fileno)
#                            mdict['clients'].pop(fileno)
#                        else:
                        #mdict['responses'].pop(fileno)
                        gClass.responses.pop(fileno)
                        epoll.modify(fileno,select.EPOLLIN)
                    except IOError:
                        log.debug("sock has closed %d" % fileno)
                        sock_fail_pass(fileno)
                elif event & select.EPOLLHUP:
                    #log.debug("sock has hup %d" % fileno)
                    #log.info("sock is hup , Host: %s:%d" % mdict['clients'][fileno].getpeername())
                    #sock_fail_pass(fileno)
                    #print "Client is close",mdict['clients'][fileno].getpeername()
                    epoll.unregister(fileno)
                    #mdict['clients'][fileno].close()
                    gClass.clients[fileno].close()
                    gClass.clients.pop(fileno)
                    #mdict['clients'].pop(fileno)
    finally:
        epoll.unregister(srvsocket.fileno())
        epoll.close()
        srvsocket.close()

def get_log_level(id):
    r = None
    if id == 0:
        r = logging.NOTSET
    elif id == 1:
        r = logging.DEBUG
    elif id == 2:
        r = logging.INFO
    elif id == 3:
        r = logging.WARNING
    elif id == 4:
        r = logging.ERROR
    elif id == 5:
        r = logging.CRITICAL
    else:
        r = None
    return r

def make_argument_parser():
    parser = argparse.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
            )
    parser.add_argument('-d',action='store',dest='loglevel',type=int,help='''set Logging to Debug level\
            CRITTICAL == 5,
            ERROR = 4,
            WARNING = 3,
            INFO = 2(defult),
            DEBUG = 1,
            NOTEST = 0''')
    parser.add_argument('-H',action='store',dest='srv_port',type=int,help='Set Services Port')
    parser.add_argument('--version',action='version',version=__version__)
    return parser

__version__ = '0.1.0'

options = make_argument_parser().parse_args()
if options.loglevel:
    DebugLevel = get_log_level(options.loglevel)
else:
    DebugLevel = logging.INFO

if not options.srv_port:
    port = 3478
else:
    port = options.srv_port




dictMethod = {STUN_METHOD_REFRESH:handle_refresh_request,
              STUN_METHOD_ALLOCATE:handle_allocate_request, # 小机登录方法
              STUN_METHOD_CHECK_USER:handle_chkuser_request,
              STUN_METHOD_REGISTER:handle_register_request,
              STUN_METHOD_BINDING:handle_app_login_request,  # app端登录方法
              STUN_METHOD_CONNECT:handle_app_connect_peer_request,
              STUN_METHOD_SEND:handle_app_send_data_to_device, # APP 发给小机的命令
              STUN_METHOD_DATA:handle_device_send_data_to_app, # 小机发给APP 的命令
              STUN_METHOD_CHANNEL_BIND:handle_app_bind_device  # APP 绑定小机的命令
              }
store = ['timer','clients','requests','responses','uuids','actives','appbinds','appsock','devsock','devuuid']
mdict = {}

gClass = ComState()
for x in store:
   #mdict[x]={} # 这个嵌套字典就是用来存放运行时的状态与数据的
   gClass.__dict__[x] = {}

epoll = select.epoll()
engine = create_engine('postgresql://postgres@localhost:5432/nath',pool_size=20,max_overflow=2)
atable = get_account_table()
if not atable.exists(engine):
    engine.connect().execute("""
    CREATE TABLE "00000000"
(
  uname character varying(255) NOT NULL PRIMAY_KEY,
  pwd BYTEA,
  is_active boolean NOT NULL DEFAULT true,
  reg_time timestamp with time zone DEFAULT now()
)
""")

stable = get_account_status_table()
if not stable.exists(engine):
    engine.connect().execute('''
CREATE TABLE account_status
(
  uname character varying(255) NOT NULL,
  is_login boolean NOT NULL DEFAULT false,
  last_login_time timestamp with time zone DEFAULT now(),
  chost bigint[] NOT NULL DEFAULT '{0,0}'::bigint[],
  CONSTRAINT account_status_uname_fkey FOREIGN KEY (uname)
      REFERENCES 00000000 (uname) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
''')


log = logging.getLogger("NatSrv")
log.setLevel(DebugLevel)
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
file_handler = handlers.RotatingFileHandler("nath.log",maxBytes=5242880,backupCount=10,encoding=None)

file_handler.setFormatter(formatter)
log.addHandler(file_handler)
log.addHandler(logging.StreamHandler())




if __name__ == '__main__':
    Server(port)


