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


LOG_ERROR_UUID='UUID Format Error'
LOG_ERROR_AUTH='Guest Authentication error'
LOG_ERROR_METHOD='Unkown Method command'
LOG_ERROR_SOCK='Socket pipe was broke'
LOG_ERROR_REGISTER='Register user occur error'
LOG_ERROR_DB='Operator db occur error'
LOG_ERROR_PACKET='Unkown packet format'
LOG_ERROR_FILENO='Too many fileno opened'
LOG_ERROR_IILAGE_CLIENT='Iilegal Client request'

class GetPkgObj:
    def __init__(self,**kwargs):
        self.__dict__.update(kwargs)


class ComState: pass

def delete_fileno(fileno):
    try:
        epoll.unregister(fileno)
    except:
        log.info('already delete socket %d' % fileno)
    if gClass.clients.has_key(fileno):
        gClass.clients.get(fileno).close()
        gClass.clients.pop(fileno)
    if gClass.requests.has_key(fileno):
        gClass.requests.pop(fileno)


def handle_client_request(buf,fileno):
    """
    -1 CRC 错误的
    -2 非法刷新请求
    0  正常值
    1  APP的连接请求
    2  小机的回复
    3  转发命令
    """
    res = get_packet_head_class(buf[:STUN_HEADER_LENGTH*2])
    res.eattr = STUN_ERROR_NONE
    if not gClass.timer.has_key(fileno):
        if res.method != STUN_METHOD_ALLOCATE or \
                res.method != STUN_METHOD_BINDING:  # 非法刷新请求
            log.info(','.join([LOG_ERROR_IILAGE_CLIENT,'sock %d' % fileno]))
            delete_fileno(fileno)
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            return ([],res)

    #判断如果是转发命令就直接转发了。
    if res.method == STUN_METHOD_SEND or res.method == STUN_METHOD_DATA:
        #print "forward packet"
        #print 'dstsock',res.dstsock
        #print 'srcsock',res.srcsock
        dstsock = int(res.dstsock,16)
        srcsock = int(res.srcsock,16)
        #转发的信息不正确
        if dstsock == 0xFFFFFFFF or srcsock == 0xFFFFFFFF:
            res.eattr = STUN_ERROR_UNKNOWN_HEAD
            return  (stun_error_response(res),res)

        if gClass.clients.has_key(dstsock):
            # 转发到时目地
            gClass.responses[dstsock] = buf
            epoll.modify(dstsock,select.EPOLLOUT)
            return ([],res)
        else: # 目标不存在
            res.eattr = STUN_ERROR_DEVOFFLINE
            #epoll.modify(fileno,select.EPOLLOUT)
            #gClass.responses[fileno] = ''.join(stun_error_response(res))
            return (stun_error_response(res),res)

    res.host= gClass.clients.get(fileno).getpeername()
    res.fileno=fileno
    hexpos = STUN_HEADER_LENGTH*2
    upkg = parser_stun_package(buf[hexpos:-8])
    if upkg is None:
        res.eattr = STUN_ERROR_UNKNOWN_ATTR
        return  (stun_error_response(res),res)

    res.attrs = upkg

    if res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) and int(res.attrs.get(STUN_ATTRIBUTE_MESSAGE_INTEGRITY)[1],16) != 32:
        res.eattr = STUN_ERROR_AUTH
        log.error(','.join([LOG_ERROR_AUTH,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        return  (stun_error_response(res),res)

    if dictMethod.has_key(res.method):
        return  (dictMethod[res.method](res),res)
    else:
        res.eattr = STUN_ERROR_UNKNOWN_METHOD
        log.error(','.join([LOG_ERROR_METHOD,res.method,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        return  (stun_error_response(res),res)

def bind_each_uuid(ustr,fileno):
    if not gClass.appbinds.has_key(fileno):
        gClass.appbinds[fileno]={}

    if gClass.devuuid.has_key(ustr):
        # 通知在线的小机，有APP要绑定它
        dstsock = gClass.devuuid[ustr]
        b = '%08x' % fileno
        gClass.appbinds[fileno][ustr]= dstsock
        notifybuf = notify_peer(''.join([b,STUN_ONLINE]))
        #print 'info',notifybuf
        gClass.responses[dstsock] = notify_peer(''.join([b,STUN_ONLINE]))
        epoll.modify(dstsock,select.EPOLLOUT )
    else:
        gClass.appbinds[fileno][ustr]=0xFFFFFFFF

def handle_app_bind_device(res):
    #绑定小机的命的命令包
    if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
        chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID][-1])
        if chk:
            res.eattr = chk
            log.error(','.join([LOG_ERROR_UUID,gClass.clients[res.fileno].getpeername()[0],str(str(sys._getframe().f_lineno))]))
            return stun_error_response(res)
        bind_each_uuid(res.attrs[STUN_ATTRIBUTE_UUID][-1],res.fileno)
    elif res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
        mlist =  split_muuid(res.attrs[STUN_ATTRIBUTE_MUUID][-1])
        p = [check_jluuid(n) for n in mlist]
        e = [ x for x in p if x]
        if len(e):
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            log.error(','.join([LOG_ERROR_UUID,gClass.clients[res.fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
        [bind_each_uuid(n,res.fileno) for n in mlist]
    else:
        res.eattr = STUN_ERROR_UNKNOWN_PACKET
        log.error(','.join([LOG_ERROR_UUID,gClass.clients[res.fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        return stun_error_response(res)

    return stun_bind_devices_ok(res)


def stun_bind_devices_ok(res):
    """
    绑定成功，回复APP
    """
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    if res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
        joint = [''.join([k,'%08x' % gClass.appbinds[res.fileno][k]]) for k in gClass.appbinds[res.fileno].keys()]
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MRUUID,''.join(joint))
    else:
        jluid = res.attrs[STUN_ATTRIBUTE_UUID][-1]
        stun_attr_append_str(buf,STUN_ATTRIBUTE_RUUID,\
                 ''.join([jluid,'%08x' %gClass.appbinds[res.fileno][jluid]]))
    stun_add_fingerprint(buf)
    return (buf)

def notify_peer(state_info):
    buf = []
    stun_init_command_str(STUN_METHOD_INFO,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,state_info)
    stun_add_fingerprint(buf)
    return buf

def notify_app_bind_islogin(bindinfo):
    buf = []
    stun_init_command_str(STUN_METHOD_INFO,buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_RUUID,bindinfo)
    stun_add_fingerprint(buf)
    return buf

def handle_app_login_request(res):
    if not res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) or  not res.attrs.has_key(STUN_ATTRIBUTE_USERNAME):
       res.eattr = STUN_ERROR_AUTH
       return  stun_error_response(res)# APP端必须带用认证信息才能发起连接.

    result = app_user_login(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],
            res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1])
    if not result:
        res.eattr = STUN_ERROR_AUTH
        return  stun_error_response(res)

    gClass.appsock[res.fileno] = tcs = ComState()
    tcs.name = result[0][0]
    app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.host)
    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
        update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
    else:
        update_refresh_time(res.fileno,UCLIENT_SESSION_LIFETIME)
    return app_user_auth_success(res)

def handle_app_send_data_to_device(res): # APP 发给小机的命令
    return
    if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
        chk = check_jluuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1]))
        if chk:
            res.eattr = chk
            log.error(','.join([LOG_ERROR_UUID,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
    else:
        res.eattr = STUN_ERROR_UNKNOWN_PACKET
        log.error(','.join([LOG_ERROR_UUID,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        return stun_error_response(res)

    row = find_device_state(res.attrs[STUN_ATTRIBUTE_UUID][-1])
    if not row:
        res.eattr =  STUN_ERROR_DEVOFFLINE
        return  stun_error_response(res)
        #设备不存在
    else:
        rlist = list(row[0])
        if rlist[1] == False: # 设备没有激活
            res.eattr =  STUN_ERROR_DEVOFFLINE
            return  stun_error_response(res)

        huid = res.attrs[STUN_ATTRIBUTE_UUID][-1]
        if rlist[3] and gClass.devuuid.has_key(huid): # 下面是发一个包给小机，确认它一定在线,收到对方确认之后再回复APP
            sock = getattr(gClass.devuuid,res.fileno)
            if not gClass.clients.has_key(sock):
                res.eattr = STUN_ERROR_DEVOFFLINE
                return  stun_error_response(res)

            try:#这里先去告诉小机，有一个客户端要连接它
                gClass.timer[sock] += FINDDEV_TIMEOUT
                res.eattr = STUN_ERROR_DEVOFFLINE
                asktimer = threading.Timer(FINDDEV_TIMEOUT,stun_ask_mirco_devices_timeout, (res))
                asktimer.start()
                gClass.responses[sock] = stun_connect_address(res.host,res)
                epoll.modify(sock,select.EPOLLOUT)
            except IOError:
                log.error(','.join([LOG_ERROR_SOCK,str(sys._getframe().f_lineno)]))
        else:
            res.eattr = STUN_ERROR_DEVOFFLINE
            return  stun_error_response(res)


def handle_app_connect_peer_request(res):
    if not res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) or  not res.attrs.has_key(STUN_ATTRIBUTE_USERNAME):
       res.eattr = STUN_ERROR_AUTH
       return  stun_error_response(res)# APP端必须带用认证信息才能发起连接.

    # 检查用户名与密码
    if not app_user_login(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1]):
        res.eattr = STUN_ERROR_AUTH
        return  stun_error_response(res)

    chk = check_jluuid(binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1]))
    if chk:
        res.eattr = chk
        log.error(','.join([LOG_ERROR_UUID,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        return stun_error_response(res)

    app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.host)
    row = find_device_state(res.attrs[STUN_ATTRIBUTE_UUID][-1])
    if not row:
        res.eattr = STUN_ERROR_DEVOFFLINE
        return  stun_error_response(res)
        #设备不存在
    else:
        rlist = list(row[0])
        if rlist[1] == False: # 设备没有激活
            res.eattr = STUN_ERROR_DEVOFFLINE
            return  stun_error_response(res)

        huid = binascii.hexlify(res.attrs[STUN_ATTRIBUTE_UUID][-1])
        if rlist[3] and gClass.devuuid.has_key(huid): # 下面是发一个包给小机，确认它一定在线,收到对方确认之后再回复APP
            sock = getattr(gClass.devuuid,huid)
            if not gClass.clients.has_key(sock):
                res.eattr = STUN_ERROR_DEVOFFLINE
                return  stun_error_response(res)

            try:#这里先去告诉小机，有一个客户端要连接它
                gClass.timer[sock] += FINDDEV_TIMEOUT
                res.eattr = STUN_ERROR_DEVOFFLINE
                asktimer = threading.Timer(FINDDEV_TIMEOUT,stun_ask_mirco_devices_timeout, (res))
                asktimer.start()
                gClass.responses[sock] = stun_connect_address(res.host,res)
                epoll.modify(sock,select.EPOLLOUT)
            except IOError:
                log.error(','.join([LOG_ERROR_SOCK,str(sys._getframe().f_lineno)]))
        else:
            res.eattr = STUN_ERROR_DEVOFFLINE
            return  stun_error_response(res)

def stun_ask_mirco_devices_timeout(res):
    #超过一定时间，小机没有回复服务器，就假定小机不可以连接，回复APP端一个错误
    if gClass.devuuid.has_key(res.fileno):
        gClass.responses[res.fileno] = stun_error_response(res)
        try:
            epoll.modify(res.fileno,select.EPOLLOUT)
        except:
            log.error(','.join([LOG_ERROR_SOCK,str(sys._getframe().f_lineno)]))


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

def handle_register_request(res):
    if app_user_register(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],
            res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1]):
        # 用户名已经存了。
        log.debug("User has Exist!i %s" % res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
        res.eattr = STUN_ERROR_USER_EXIST
        return stun_error_response(res)
    return register_success(res.attrs[STUN_ATTRIBUTE_USERNAME][-1])

def register_success(uname):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REGISTER),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,uname)
    stun_add_fingerprint(buf)
    log.debug("Regsiter is success %s" % uname)
    return (buf)

def handle_chkuser_request(res):
    f = check_user_in_database(res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
    if f != 0:
        log.debug("User Exist %s" % res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
        res.eattr = STUN_ERROR_USER_EXIST
        return stun_error_response(res)
    else:
        return check_user_sucess(res)

def check_user_sucess(res):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf,)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,binascii.hexlify(res.attrs[STUN_ATTRIBUTE_USERNAME][-1]))
    stun_add_fingerprint(buf)
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

def noify_app_uuid_just_login(sock,uuidstr,devsock):
    gClass.responses[sock] = notify_app_bind_islogin(''.join([uuidstr,'%08x' % devsock]))
    epoll.modify(sock,select.EPOLLOUT)

def device_login_notify_app(uuidstr,devsock):
    for fk in gClass.appbinds.keys():
        if gClass.appbinds.get(fk,None) is dict and gClass.appbinds[fk].has_key(uuidstr):
            noify_app_uuid_just_login(fk,uuidstr,devsock)

def handle_allocate_request(res):
    """
    小机登录服务器的命令，必须要有uuid,data
    """
    if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
        chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID][-1])
        if chk:
            res.eattr = chk
            log.error(','.join([LOG_ERROR_UUID,gClass.clients[res.fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
    else:
        #res.eattr= binascii.hexlify("Not Found UUID")
        res.eattr=STUN_ERROR_UNKNOWN_PACKET
        log.error(','.join([LOG_ERROR_UUID,gClass.clients[res.fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        return stun_error_response(res)

    huid = res.attrs[STUN_ATTRIBUTE_UUID][-1]
    device_login_notify_app(huid,res.fileno)
    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
        update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
    else:
        update_refresh_time(res.fileno,UCLIENT_SESSION_LIFETIME)

    res.vendor = huid[32:40]
    res.tuid = huid[:32]
    update_newdevice(res)
    #gClass.actives[res.fileno] = huid
    gClass.devsock[res.fileno] = tcs = ComState()
    gClass.devuuid[huid] = res.fileno
    tcs.uuid = huid
    #print "login devid is",tcs.uuid
    return device_login_sucess(res)

def app_user_auth_success(res):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
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
    update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
    return refresh_sucess(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1])

def refresh_sucess(ntime): # 刷新成功
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REFRESH),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,ntime)
    stun_add_fingerprint(buf)
    return (buf)

def update_refresh_time(fileno,ntime):
    gClass.timer[fileno] = time.time()+ntime

def app_user_register(user,pwd):
    account = get_account_table()
    dbcon = engine.connect()
    #print "register new account %s,%s" % (user,pwd)
    uname = binascii.unhexlify(user)
    sss = sql.select([account]).where(account.c.uname == uname)
    res = dbcon.execute(sss)
    if len(res.fetchall()):
        return True
    else:
        obj = hashlib.sha256()
        obj.update(uname)
        obj.update(pwd)
        ins = account.insert().values(uname=uname,pwd=obj.digest(),is_active=True,reg_time=datetime.now())
        try:
            dbcon.execute(ins)
        except:
            log.error(','.join([LOG_ERROR_REGISTER,uname,str(sys._getframe().f_lineno)]))
            return True
        return False

def app_user_update_status(user,host):
    uname = binascii.unhexlify(user)
    status_tables = get_account_status_table()
    ipadr = int(binascii.hexlify(socket.inet_aton(host[0])),16) & 0xFFFFFFFF
    ipprt = host[1] & 0xFFFF
    s = sql.select([status_tables]).where(status_tables.c.uname == uname)
    dbcon = engine.connect()
    result = dbcon.execute(s)
    row = result.fetchall()
    #print "row is",row
    sss = 0
    if row:
        sss = status_tables.update().values(last_login_time = datetime.now(),chost=[ipadr,ipprt]).where(status_tables.c.uname == user)
    else:
        sss = status_tables.insert().values(uname=uname,is_login=True,chost=[ipadr,ipprt])
    try:
        result = dbcon.execute(sss)
    except:
        log.error(','.join([LOG_ERROR_DB,host,str(sys._getframe().f_lineno)]))


def app_user_login(user,pwd):
    uname = binascii.unhexlify(user)
    account = get_account_table()
    dbcon = engine.connect()
    obj = hashlib.sha256()
    obj.update(uname)
    obj.update(pwd)
    s = sql.select([account]).where(and_(account.c.uname == uname,account.c.pwd == obj.digest(),
        account.c.is_active == True))
    try:
        result = dbcon.execute(s)
    except:
        log.error(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))
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
    account = Table('account',metadata,
            #Column('uuid',pgsql.UUID,primary_key=True),
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
        log.error(','.join([LOG_ERROR_DB,uname,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
    return result.fetchall()

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


def find_device_state(uid):
    vendor = uid[32:40]
    #print "find uuid is",uid,"vendor is",vendor
    dbcon = engine.connect()
    mirco_devices = get_devices_table(vendor)
    if not mirco_devices.exists(engine):
        return None
        s = sql.select([mirco_devices]).where(mirco_devices.c.devid == uid[:32] )
    try:
        result = dbcon.execute(s)
        return result.fetchall()
    except:
        log.error(','.join([LOG_ERROR_DB,uuid,str(sys._getframe().f_lineno)]))
        return None


def update_newdevice(res):
    '''添加新的小机到数据库'''
    dbcon = engine.connect()
    mirco_devices = get_devices_table(res.vendor)
    if not mirco_devices.exists(engine):
        mirco_devices.create(engine)
    s = sql.select([mirco_devices.c.devid]).where(mirco_devices.c.devid == res.tuid)
    row = ''
    try:
        result = dbcon.execute(s)
        row = result.fetchall()
    except:
        log.error(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
    ipadr = int(binascii.hexlify(socket.inet_aton(res.host[0])),16) & 0xFFFFFFFF
    ipprt = res.host[1] & 0xFFFF
    #print "host %d:%d" % (ipadr,ipprt)
    data = ''
    if res.attrs.has_key(STUN_ATTRIBUTE_DATA):
        data = res.attrs[STUN_ATTRIBUTE_DATA][-1]

    if not row: # 找不到这个UUID 就插入新的
        ins = mirco_devices.insert().values(devid=res.tuid,is_active=True,
                is_online=True,chost=[ipadr,ipprt],data=data,last_login_time=datetime.now())
        try:
            result = dbcon.execute(ins)
        except:
            log.error(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
        #print "insert new devices result fetchall"
    else:
        upd = mirco_devices.update().values(is_online=True,chost = [ipadr,ipprt],data=data,
                last_login_time=datetime.now()).where(mirco_devices.c.devid == res.tuid)
        try:
            result = dbcon.execute(upd)
        except:
            log.error(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))

class CheckSesionThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(1)
            [clean_timeout_sock(x)  for x in  gClass.timer.keys()]

def notify_peer_is_logout(fileno,dstsock):
    gClass.responses[fileno] =  notify_peer(''.join(['%08x' % dstsock,STUN_OFFLINE]))
    try:
        epoll.modify(fileno,select.EPOLLOUT)
    except:
        log.error(''.join([LOG_ERROR_PACKET,\
                'socket error %d' % fileno,str(sys._getframe().f_lineno)]))

def clean_timeout_sock(fileno): # 清除超时的连接
    if gClass.timer.has_key(fileno):
        if gClass.timer[fileno] < time.time():
            log.info("Client %d life time is end,close it" % fileno )
            dealwith_sock_close_update_binds(fileno)
            dealwith_sock_close_update_db(fileno)
            delete_fileno(fileno)
            remove_fileno_resources(fileno)

def mirco_devices_logout(devid):
    vendor = devid[32:40]
    #print "update status for tuid",binascii.hexlify(suid[0])
    mtable = get_devices_table(vendor)
    conn = engine.connect()
    #ss = mtable.update().values(is_online=False).where(mtable.c.devid == binascii.hexlify(suid[0]))
    ss = mtable.update().values(is_online=False).where(mtable.c.devid == devid[:32])
    try:
        res = conn.execute(ss)
    except IOError:
        log.error(','.join([LOG_ERROR_DB,devid,str(sys._getframe().f_lineno)]))
        return 0


def notify_uuid_app_logout(fileno):
    # app 下线，通知小机
    #binds = [v for k,v in gClass.appbinds[fileno].iteritems()]
    if gClass.appbinds.has_key(fileno):
        binds = gClass.appbinds[fileno].values()
        gClass.appsock.pop(fileno) # 回收这个APP的BIND资源
        [notify_peer_is_logout(n,fileno) for n in binds if gClass.devsock.has_key(n)]

def notify_app_uuid_logout(fileno):
    # 小机下线，通知APP
    devid = gClass.devsock[fileno].uuid
    #print "devid",devid,"has logout"
    binds = [k for k in gClass.appbinds.keys() if gClass.appbinds.get(k).has_key(devid)]
    [notify_peer_is_logout(n,fileno) for n in binds if gClass.appsock.has_key(n)]
    alist = [n for n in binds if gClass.appsock.has_key(n)]
    for n in alist:
        gClass.appbinds[n][devid]=0xFFFFFFFF

def app_user_logout(uname):
    atable = get_account_status_table()
    conn = engine.connect()
    ss = atable.update().values(is_login=False).where(atable.c.uname == uname)
    try:
        res = conn.execute(ss)
    except :
        log.error(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))


def dealwith_sock_close_update_db(fileno):
    # socket 关闭，更新数据库
    if gClass.appsock.has_key(fileno): #更新相应的数据库在线状态
        #print "appsock is",gClass.appsock
        app_user_logout(gClass.appsock[fileno].name)
        try:
            gClass.appsock.pop(fileno)
        except:
            pass
    elif gClass.devsock.has_key(fileno):
        mirco_devices_logout(gClass.devsock[fileno].uuid)
        try:
            gClass.devsock.pop(fileno)
        except:
            pass

def dealwith_sock_close_update_binds(fileno):
    if gClass.appsock.has_key(fileno):
        notify_uuid_app_logout(fileno)
        # APP 应该下线了
    elif gClass.devsock.has_key(fileno):
        notify_app_uuid_logout(fileno)
        # 小机下线，通知APP

def sock_send_fail(fileno):
    # 要检查一下是不是转发失败了，要通知发送方
    phead = get_packet_head_class(gClass.responses[fileno])
    if phead.method == STUN_METHOD_SEND or phead.method == STUN_METHOD_DATA:
        phead.eattr = STUN_ERROR_DEVOFFLINE
        srcsock = int(phead.srcsock,16)
        gClass.responses[srcsock] = ''.join(stun_error_response(phead))
        epoll.modify(srcsock,select.EPOLLOUT)

    # sock 关闭时产生的异常处理
    epoll.unregister(fileno)
    dealwith_sock_close_update_db(fileno)
    dealwith_sock_close_update_binds(fileno)
    remove_fileno_resources(fileno)

def sock_recv_fail(fileno):
    # sock 关闭时产生的异常处理
    try:
        epoll.unregister(fileno)
    except:
        pass
    dealwith_sock_close_update_binds(fileno)
    dealwith_sock_close_update_db(fileno)
    remove_fileno_resources(fileno)

def remove_fileno_resources(fileno):
    clist =[ n for n in [getattr(gClass,k) for k in store] if n.has_key(fileno)]
    [n.pop(fileno) for n in clist]
    #print "delete list is",clist,"fileno",fileno

def handle_requests_buf(hbuf,fileno):
    if check_packet_crc32(hbuf):
        log.error(','.join([LOG_ERROR_PACKET,'sock %d' %fileno,str(sys._getframe().f_lineno)]))
        delete_fileno(fileno)
        return 

    rbuf = handle_client_request(hbuf,fileno)
    res = rbuf[1]
    if res.eattr == STUN_ERROR_UNKNOWN_PACKET:
        log.info(','.join([LOG_ERROR_IILAGE_CLIENT,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
        delete_fileno(fileno)
        return 

    if not len(rbuf[0]): # 是转发包
        return

    gClass.responses[fileno] = rbuf[0]
    epoll.modify(fileno,select.EPOLLOUT)
    if gClass.timer.has_key(fileno):
        gClass.timer[fileno] = time.time()+UCLIENT_SESSION_LIFETIME




def Server(port):
    srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srvsocket.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    srvsocket.bind(('',port))
    srvsocket.listen(50)
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
                if fileno == srvsocket.fileno():
                    #新的连接
                    try:
                        nsock,addr = srvsocket.accept()
                    except:
                        log.error(','.join([LOG_ERROR_FILENO,str(sys._getframe().f_lineno)]))
                        continue
                    nf = nsock.fileno()
                    log.info(','.join(["new client %s:%d" % addr,"new fileno %d" % nf, 'srv fileno %d'%fileno]))
                    nsock.setblocking(0)
                    gClass.clients[nf] = nsock
                    gClass.responses[nf] = []
                    gClass.timer[nf] = time.time()+10
                    epoll.register(nf,select.EPOLLIN)
                elif event & select.EPOLLIN: # 读取socket 的数据
                    try:
                        if not gClass.clients.has_key(fileno):
                            log.info(','.join(['sock %d' % fileno,'not in clients']))
                            delete_fileno(fileno)
                            continue
                        recvbuf = gClass.clients[fileno].recv(SOCK_BUFSIZE)
                        #print 'recv ',binascii.hexlify(recvbuf)
                        log.info(','.join(['sock %d' % fileno,'recv: %d' % len(recvbuf)]))
                        if not recvbuf:
                            log.info(','.join(['sock %d' % fileno,'recv no buffer']))
                            delete_fileno(fileno)
                            continue

                        hbuf = binascii.hexlify(recvbuf)
                        if cmp(hbuf[:4],HEAD_MAGIC): # 检查JL关键字
                            log.error(','.join([LOG_ERROR_PACKET,gClass.clients[fileno].getpeername()[0],str(sys._getframe().f_lineno)]))
                            delete_fileno(fileno)
                            continue
                        mplist = []
                        if (len(hbuf)/2)  > int(hbuf[8:12],16):
                            #print 'hbuf len',len(hbuf),'h len',int(hbuf[8:12],16)
                            #读到两个包了
                            mplist = [''.join([HEAD_MAGIC,n]) for n in hbuf.split(HEAD_MAGIC) if n ]
                            #print "two packet",mplist
                            [handle_requests_buf(n,fileno) for n in mplist]    
                        else:
                            handle_requests_buf(hbuf,fileno)
                    except IOError:
                        sock_recv_fail(fileno)
                        log.debug("sock has closed %d" % fileno)
                elif event & select.EPOLLOUT:
                    try:
                        if not gClass.responses.has_key(fileno): #连接命令的时候返回是NULL
                            log.error(','.join([LOG_ERROR_PACKET,'sock %d' % fileno,str(sys._getframe().f_lineno)]))
                            #epoll.modify(fileno,select.EPOLLWRBAND)
                            continue
                        nbyte =  gClass.clients[fileno].send(\
                                binascii.unhexlify(''.join(gClass.responses[fileno])))
                        log.info(','.join(['sock %d' % fileno,'send: %d'%nbyte]))
                        gClass.responses.pop(fileno)
                        if gClass.timer.has_key(fileno):
                            # 给这个联接添加生存时间
                            gClass.timer[fileno] = time.time()+UCLIENT_SESSION_LIFETIME
                        epoll.modify(fileno,select.EPOLLIN)
                    except IOError:
                        log.debug("sock has closed %d" % fileno)
                        sock_send_fail(fileno)
                elif event & select.EPOLLHUP:
                    log.debug("sock hup %d" % fileno)
                    delete_fileno(fileno)
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

port = options.srv_port if options.srv_port else 3478


dictMethod = {STUN_METHOD_REFRESH:handle_refresh_request,
              STUN_METHOD_ALLOCATE:handle_allocate_request, # 小机登录方法
              STUN_METHOD_CHECK_USER:handle_chkuser_request,
              STUN_METHOD_REGISTER:handle_register_request,
              STUN_METHOD_BINDING:handle_app_login_request,  # app端登录方法
              STUN_METHOD_CONNECT:handle_app_connect_peer_request,
              STUN_METHOD_SEND:handle_app_send_data_to_device, # APP 发给小机的命令
              #STUN_METHOD_DATA:handle_device_send_data_to_app, # 小机发给APP 的命令
              STUN_METHOD_CHANNEL_BIND:handle_app_bind_device  # APP 绑定小机的命令
              }
store = ['timer','clients','requests','responses','appbinds','appsock','devsock','devuuid']

gClass = ComState()
[setattr(gClass,x,{}) for x in store]

epoll = select.epoll()
engine = create_engine('postgresql+psycopg2://postgres:postgres@localhost:5432/nath',pool_size=200,max_overflow=20)
atable = get_account_table()
if not atable.exists(engine):
    engine.connect().execute("""
    CREATE TABLE "account"
(
  uname character varying(255) NOT NULL,
  pwd BYTEA,
  is_active boolean NOT NULL DEFAULT true,
  reg_time timestamp with time zone DEFAULT now(),
  CONSTRAINT uname_pkey PRIMARY KEY(uname),
  CONSTRAINT uname_ukey UNIQUE(uname)
)
""")

stable = get_account_status_table()
if not stable.exists(engine):
    engine.connect().execute('''
CREATE TABLE account_status
(
  uname character varying(255) NOT NULL ,
  is_login boolean NOT NULL DEFAULT false,
  last_login_time timestamp with time zone DEFAULT now(),
  chost bigint[] NOT NULL DEFAULT '{0,0}'::bigint[],
  CONSTRAINT account_status_uname_fkey FOREIGN KEY (uname)
      REFERENCES account (uname) MATCH SIMPLE
      ON UPDATE NO ACTION ON DELETE NO ACTION
)
''')

appname = 'JL_SRV'
log = logging.getLogger(appname)
log.setLevel(DebugLevel)
formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s','%a, %d %b %Y %H:%M:%S',)
file_handler = handlers.RotatingFileHandler("%s.log" % appname,maxBytes=LOG_SIZE,backupCount=LOG_COUNT,encoding=None)

file_handler.setFormatter(formatter)
log.addHandler(file_handler)
if log.level ==  1:
    log.addHandler(logging.StreamHandler())


if __name__ == '__main__':
    Server(port)


