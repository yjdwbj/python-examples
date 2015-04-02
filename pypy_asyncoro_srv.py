#!/opt/pypy-2.5.0-src/pypy-c
#-*- coding: utf-8 -*-
#!/opt/stackless-279/bin/python2 
#####################################################################
# lcy
#                                                                   #
#                                                                   #
#
#
####################################################################
#import socket
import time
import struct
import threading
import uuid
import sys
import os
import gc
import unittest
import argparse
import errno

from binascii import unhexlify,hexlify
from datetime import datetime
import hashlib
from sockbasic import *
import socket,asyncoro

from asyncoro import AsynCoro



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


class ComState: pass

def clean_dict(p):
    try:
        p[0].pop(p[1])
    except KeyError:
        pass

def notify_peer(state_info):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_INFO),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,state_info)
    stun_add_fingerprint(buf)
    return buf

def notify_app_bind_islogin(bindinfo):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_INFO),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_RUUID,bindinfo)
    stun_add_fingerprint(buf)
    return buf

def stun_connect_address(host,res):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_CONNECT),buf,)
    mip = "0001%04x%08x" % (host[1]^ (STUN_MAGIC_COOKIE >> 16),
            STUN_MAGIC_COOKIE ^ (int(hexlify(socket.inet_aton(host[0])),16)))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,mip)
    if res.attrs.has_key(STUN_ATTRIBUTE_DATA): #转发小机的基本信息
        stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,hexlify(res.attrs[STUN_ATTRIBUTE_DATA]))
    stun_add_fingerprint(buf)
    return (buf)

def register_success(uname):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REGISTER),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,uname)
    stun_add_fingerprint(buf)
    return buf


def check_user_sucess(res):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf,)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,hexlify(res.attrs[STUN_ATTRIBUTE_USERNAME]))
    stun_add_fingerprint(buf)
    return (buf)

def app_user_auth_success(res):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,res.attrs[STUN_ATTRIBUTE_USERNAME])
    stun_add_fingerprint(buf)
    return (buf)

def device_login_sucess(res): # 客服端向服务器绑定自己的IP
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_add_fingerprint(buf)
    return (buf)

def app_user_pull_table(res,data):
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_DATA,data)
    stun_add_fingerprint(buf)
    return buf

def refresh_sucess(ntime): # 刷新成功
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REFRESH),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,ntime)
    stun_add_fingerprint(buf)
    return (buf)

def stun_return_same_package(res):
    buf =[]
    stun_init_command_str(stun_make_success_response(res.method),buf)
    t = sum([(buf.extend(v),len(v[-1])+8)[1] for v in res.reqlst])
    buf[2] = "%04x" % (t/2 +20)
    stun_add_fingerprint(buf)
    return (buf)

class A:
    pass

def EpollServer(errqueue,statqueue,coro=None):
    coro.set_daemon()
    mstore.srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    mstore.srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    mstore.srvsocket.setsockopt(socket.SOL_SOCKET,socket.TCP_NODELAY,1)
    mstore.srvsocket.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
    mstore.srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
    mstore.srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_DEBUG,0)
    mstore.srvsocket.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,6)
    mstore.srvsocket.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,60)
    mstore.srvsocket.setsockopt(socket.SOL_TCP,socket.TCP_KEEPIDLE,120)
    mstore.srvsocket = asyncoro.AsyncSocket(mstore.srvsocket)
    mstore.srvsocket.bind(('0.0.0.0',3478))
    mstore.srvsocket.listen(1024)
    mstore.errqueue = errqueue
    mstore.statqueue = statqueue
    mstore.db_engine = QueryDB().get_engine()
    mstore.execute = mstore.db_engine.connect().execute
    [setattr(mstore,x,{}) for x in store]

    mstore.prefunc= {
          STUN_METHOD_ALLOCATE:handle_allocate_request, # 小机登录方法
          STUN_METHOD_CHECK_USER:handle_chkuser_request,
          STUN_METHOD_REGISTER:handle_register_request,
          STUN_METHOD_BINDING:handle_app_login_request  # app端登录方法
          }

    #认证后的处理
    mstore.postfunc={
            STUN_METHOD_CHANNEL_BIND:handle_app_bind_device,  # APP 绑定小机的命令
            #STUN_METHOD_REFRESH:mstore.handle_refresh_request,
            STUN_METHOD_MODIFY:handle_modify_bind_item, #修改绑定的信息
            STUN_METHOD_DELETE:handle_delete_bind_item, #删除现有的绑定
            STUN_METHOD_PULL:handle_app_pull
            }
    while True:
        try:
            nsock,addr = yield mstore.srvsocket.accept()
            nf = nsock.fileno()
            mstore.clients[nf] = nsock
            mstore.hosts[nf] = addr
            mstore.requests[nf] =''
            asyncoro.Coro(handle_new_accept,nsock)
            #mstore.gpool.spawn_n(mstore.handle_new_accept,nsock)
        except (SystemExit,KeyboardInterrupt):
            print "Server exit"
            break

def handle_new_accept(fd):
    fileno = fd.fileno()
    while True:
        data = ''
        try:
            data = yield fd.recv(SOCK_BUFSIZE)
        except IOError:
            mstore.errqueue.put('sock %d, IOError ,host: %s:%d' % (fileno,mstore.hosts[fileno][0],mstore.hosts[fileno][1]))
            dealwith_peer_hup(fileno)
            break
        except socket.error:
            dealwith_peer_hup(fileno)
            break
        else:
            if not data:
                dealwith_peer_hup(fileno)
                break
            mstore.requests[fileno] += hexlify(str(data))
            process_handle_first(fileno)


def handle_modify_bind_item(res):
    try:
        btable = QueryDB.get_account_bind_table(mstore.users[res.fileno])
        s = btable.update().values(pwd=res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]).\
                where(btable.c.uuid == res.attrs[STUN_ATTRIBUTE_UUID])
        mstore.execute(s)
        return stun_return_same_package(res)
    except ProgrammingError:
        #print "table not exits"
        res.eattr = STUN_ERROR_OBJ_NOT_EXIST
        return  stun_error_response(res)
    except KeyError:
        res.eattr =STUN_ERROR_UNKNOWN_ATTR
        return stun_error_response(res)

def handle_delete_bind_item(res):
    uname = mstore.users[res.fileno]
    uids = res.attrs[STUN_ATTRIBUTE_UUID]
    try:
        n = [ n for n in mstore.appbinds.values if n.has_key(uids)]
        popfunc = lambda d,v: d.pop(v)
        k = mcore_handle(popfunc,(n))
    except TypeError:
        print "TypeError %d,n is none" % res.fileno
    delete_binds_in_db(uname,uids)
    return  stun_return_same_package(res)
    

def delete_binds_in_db(uname,uids):
    try:
        btable = QueryDB.get_account_bind_table(uname)
        res =  mstore.execute(btable.delete().where(btable.c.uuid == uids ))
        return False
    except KeyError:
        return True


def handle_app_pull(res):
    uname = mstore.users[res.fileno]
    try:
        btable = QueryDB.get_account_bind_table(uname)
        s = sql.select([btable])
        #fall = mstore.execute(s).fetchall()
        fall = mstore.execute(s).fetchall()
        data = ''.join([ ''.join([r[0],r[1]]) for r in fall])
        if not data:
            res.eattr = STUN_ERROR_OBJ_NOT_EXIST
            return  stun_error_response(res)
        return  app_user_pull_table(res,data)
    except ProgrammingError:
        #print "table not exits"
        res.eattr = STUN_ERROR_OBJ_NOT_EXIST
        return  stun_error_response(res)
    except KeyError:
        res.eattr =STUN_ERROR_UNKNOWN_PACKET
        return  stun_error_response(res)

def delete_fileno(fileno):
    try:
        mstore.clients[fileno].close()
        mstore.clients.pop(fileno)
    except KeyError:
        pass



def write_to_sock(fileno):
    sock = mstore.clients[fileno]
    try:
        sock.send(unhexlify(''.join(mstore.responses[fileno])))
    except socket.error:
        dealwith_peer_hup(fileno)


def handle_refresh_request(res):
    pass
    #return refresh_sucess(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1])
def process_mp_buf(pair):
    handle_requests_buf(pair[0],pair[1])


def process_handle_first(fileno):
    l = mstore.requests[fileno].count(HEAD_MAGIC) #没有找到JL关键字
    if not l:
        mstore.errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (fileno,mstore.requests[fileno]))
        return
    plen = len(mstore.requests[fileno])
    if l > 1:
        #mstore.errqueue.put('sock %d,recv unkown msg %s' % (fileno,mstore.requests[:l])
        mstore.statqueue.put("sock %d,recv multi buf,len %d, buf: %s" % (fileno,plen,mstore.requests[fileno]))
        #hbuf = hbuf[l:] # 从找到标识头开始处理
        pos = sum([len(v) for v in split_requests_buf(mstore.requests[fileno])])
        mstore.requests[fileno] = mstore.requests[fileno][pos:]
        [mstore.handle_requests_buf(n,fileno) for n in  split_requests_buf(mstore.requests[fileno])]
    else: # 找到一个标识，还不知在什么位置
        pos = mstore.requests[fileno].index(HEAD_MAGIC)
        mstore.requests[fileno] = mstore.requests[fileno][pos:]
        nlen = int(mstore.requests[fileno][8:12],16) *2
        if len(mstore.requests[fileno]) < nlen:
            print "sock %d, recv packet not complete, %s" % (fileno,mstore.requests[fileno])
            return
        onepack = mstore.requests[fileno][:nlen]
        mstore.requests[fileno] = mstore.requests[fileno][nlen:]
        handle_requests_buf(onepack,fileno)
        
                
def handle_requests_buf(hbuf,fileno): # pair[0] == hbuf, pair[1] == fileno
    if len(hbuf) % 2:
        return 
    res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
    if not res:
        return
    res.eattr = STUN_ERROR_NONE
    res.host= mstore.hosts[fileno]
    res.fileno=fileno
    gc.collect()

    #通过认证的socket 直接转发了
    try:
        aforward = mstore.appsock[fileno]
        if res.method == STUN_METHOD_REFRESH:
            return
        elif res.method == STUN_METHOD_SEND: 
            if check_dst_and_src(res):
                mstore.responses[fileno] = stun_error_response(res)
                write_to_sock(fileno,mstore.EV_OUT)
            else:
                """
                 直接转发了
                """
                handle_forward_packet(hbuf,res,mstore.devsock)
        else:
            handle_postauth_process(res,hbuf)
        return # 一切正常返回
    except KeyError:
        pass

    try:
        dforward = mstore.devsock[fileno]
        if res.method == STUN_METHOD_REFRESH:
            return
        elif res.method == STUN_METHOD_DATA:
            if check_dst_and_src(res):
                mstore.responses[fileno] = stun_error_response(res)
                write_to_sock(fileno)
            else:
                handle_forward_packet(hbuf,res,mstore.appsock)
        else:
            handle_postauth_process(res,hbuf)
        return # 一切正常返回
    except KeyError:
        pass

    """
    处理要认证的客务端
    """
    handle_client_request_preauth(res,hbuf)

def handle_postauth_process(res,hbuf):
    """
    执行认证后的函数
    """
    hexpos = STUN_HEADER_LENGTH
    trip =  parser_stun_package(hbuf[hexpos:-8])
    if trip is None:
        res.eattr = STUN_ERROR_UNKNOWN_ATTR
        print "hbuf is wrong",hbuf,mstore.hosts[res.fileno]
        mstore.errqueue.put(','.join([LOG_ERROR_ATTR,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        mstore.responses[res.fileno] = stun_error_response(res)
        write_to_sock(res.fileno)
    else:
        res.attrs = trip[0]
        res.reqlst = trip[1]
        try:
           mstore.responses[res.fileno]=  mstore.postfunc[res.method](res)
           write_to_sock(res.fileno)
        except KeyError:
            handle_client_request_preauth(res,hbuf)

            print "KeyError,fileno %d,method %s,not auth clients,forward to preauth" % (res.fileno,res.method)

    

            
def handle_forward_packet(hbuf,res,dst):
    try:
        s = dst[res.dstsock]
        # 转发到时目地
        mstore.responses[res.dstsock] = hbuf
        write_to_sock(res.dstsock)
    except KeyError: # 目标不存在
        res.eattr = STUN_ERROR_DEVOFFLINE
        #mstore.epoll.modify(fileno,select.EPOLLOUT)
        #mstore.responses[fileno] = ''.join(stun_error_response(res))
        #tbuf = stun_error_response(res)
        tbuf =  notify_peer(''.join(['%08x' % res.dstsock,STUN_OFFLINE]))
        tbuf[3]='%08x' % res.srcsock
        tbuf[4]='%08x' % res.dstsock
        tbuf.pop()
        tbuf[2] = '%04x' % (int(tbuf[2],16)-4)
        stun_add_fingerprint(tbuf)
        mstore.responses[res.fileno] = tbuf
        write_to_sock(res.fileno)

def handle_client_request_preauth(res,hbuf): # pair[0] == hbuf, pair[1] == fileno

    if check_packet_crc32(hbuf):
        mstore.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d,buf %s' % (res.fileno,hbuf),str(sys._getframe().f_lineno)]))
        mstore.delete_fileno(res.fileno)
        return 

    if not (res.method == STUN_METHOD_ALLOCATE or\
            res.method == STUN_METHOD_BINDING or\
            res.method == STUN_METHOD_CHECK_USER or\
            res.method == STUN_METHOD_REGISTER):
                # 非法请求
        #print 'fileno',fileno
        #print 'mstore.appsock',mstore.appsock
        res.eattr = STUN_ERROR_UNKNOWN_PACKET
        mstore.errqueue.put(','.join([LOG_ERROR_IILAGE_CLIENT,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        mstore.delete_fileno(res.fileno)
        return

    hexpos = STUN_HEADER_LENGTH
    trip = parser_stun_package(hbuf[hexpos:-8])
    if trip is None:
        print "preauth hbuf is wrong",hbuf,mstore.hosts[res.fileno]
        res.eattr = STUN_ERROR_UNKNOWN_ATTR
        mstore.errqueue.put(','.join([LOG_ERROR_ATTR,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        return

    res.attrs = trip[0]
    res.reqlst = trip[1]
    if res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) and (len(res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY])/2) != 32:
        print "attrs",res.attrs
        print 'pwd',res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]
        res.eattr = STUN_ERROR_AUTH
        mstore.errqueue.put(','.join([LOG_ERROR_AUTH,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        return
    try:
        mstore.responses[res.fileno] = mstore.prefunc[res.method](res)
    except KeyError:
        res.eattr = STUN_ERROR_UNKNOWN_METHOD
        print "head",res.__dict__
        print "attrs",upkg
        print "method",res.method
        mstore.errqueue.put(','.join([LOG_ERROR_METHOD,res.method,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
    else:
        write_to_sock(res.fileno)

def handle_app_login_request(res):
    user = b''
    pwd = b''
    try:
        pwd = res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]
        user = unhexlify(res.attrs[STUN_ATTRIBUTE_USERNAME])
        result = app_user_login(user,pwd)
        if not result:
            res.eattr = STUN_ERROR_AUTH
            return  stun_error_response(res)
    except KeyError:
       res.eattr = STUN_ERROR_AUTH
       return  stun_error_response(res)# APP端必须带用认证信息才能发起连接.

    mstore.appsock[res.fileno] = tcs = ComState()
    tcs.name = result[0][0]
    app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME],res.host)
    mstore.statqueue.put('user %s login,socket is %d,host %s:%d' % (tcs.name,res.fileno,res.host[0],res.host[1]))
    mstore.users[res.fileno] = user
    return app_user_auth_success(res)

def handle_allocate_request(res):
    """
    小机登录服务器的命令，必须要有uuid,data
    """
    try:
        chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID])
        if chk:
            print "chkuuid",chk
            res.eattr = chk
            mstore.errqueue.put(','.join([LOG_ERROR_UUID,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
    except KeyError:
        #res.eattr= hexlify("Not Found UUID")
        res.eattr=STUN_ERROR_UNKNOWN_PACKET
        mstore.errqueue.put(','.join([LOG_ERROR_UUID,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        return stun_error_response(res)

    huid = res.attrs[STUN_ATTRIBUTE_UUID]
    device_login_notify_app(huid,res.fileno)
#    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
#        update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
#    else:
#        update_refresh_time(res.fileno,UCLIENT_SESSION_LIFETIME)

    res.vendor = huid[32:40]
    res.tuid = huid[:32]
    update_newdevice(res)
    #mstore.actives[res.fileno] = huid
    mstore.devsock[res.fileno] = tcs = ComState()
    mstore.devuuid[huid] = res.fileno
    tcs.uuid = huid
    #print "login devid is",tcs.uuid
    mstore.statqueue.put('device login uuid is %s,socket is %d, host %s:%d' % (huid,res.fileno,res.host[0],res.host[1]))
    return device_login_sucess(res)

def handle_chkuser_request(res):
    f = check_user_in_database(res.attrs[STUN_ATTRIBUTE_USERNAME])
    if f != 0:
        mstore.errqueue.put("User Exist %s" % res.attrs[STUN_ATTRIBUTE_USERNAME])
        res.eattr = STUN_ERROR_USER_EXIST
        return stun_error_response(res)
    else:
        return check_user_sucess(res)

def handle_register_request(res):
    if app_user_register(res.attrs[STUN_ATTRIBUTE_USERNAME],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]):
        # 用户名已经存了。
        mstore.errqueue.put("User has Exist! %s" % res.attrs[STUN_ATTRIBUTE_USERNAME])
        res.eattr = STUN_ERROR_USER_EXIST
        return stun_error_response(res)
    return register_success(res.attrs[STUN_ATTRIBUTE_USERNAME])

def handle_add_bind_to_user(res):
    """
    绑定小机到用户表里
    """
    table  = QueryDB.get_account_bind_table(mstore.users[res.fileno])
    try:
        table.create(mstore.db_engine)
    except ProgrammingError:
        pass
    #添加新绑定的小机用户表下面
    s = ''
    try:
        s = table.insert().values(uuid=res.attrs[STUN_ATTRIBUTE_UUID],\
                pwd=res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY],reg_time=datetime.now())
    except KeyError:
        mstore.errqueue.put(','.join(['sock %d' % res.fileno,'no uuid attr to bind']))
        res.eattr = STUN_ERROR_UNKNOWN_PACKET
        print "bind KeyError",fileno
        return 
    except TypeError:
        p = res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]
        print "pwd len %d, %s" %(len(p),p)
        return

    try:
        #mstore.execute(ins)
        result = yield mstore.execute(s)
    except IntegrityError:
        s = table.update().values(reg_time = datetime.now()).where(table.c.uuid == res.attrs[STUN_ATTRIBUTE_UUID])
        #mstore.execute(s)
        result = yield mstore.execute(s)
    except ProgrammingError:
        s = table.update().values(reg_time = datetime.now()).where(table.c.uuid == res.attrs[STUN_ATTRIBUTE_UUID])
        #mstore.execute(stmt)
        result = yield mstore.execute(s)

def handle_app_bind_device(res):
    #绑定小机的命的命令包
    try:
        chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID])
        if chk:
            res.eattr = chk
            print "sock %d, uuid wrong %s" %(res.fileno,res.attrs[STUN_ATTRIBUTE_UUID])
            mstore.errqueue.put(','.join([LOG_ERROR_UUID,mstore.hosts[res.fileno][0],str(str(sys._getframe().f_lineno))]))
            return stun_error_response(res)
        bind_each_uuid((res.attrs[STUN_ATTRIBUTE_UUID],res.fileno))
        handle_add_bind_to_user(res)
#        elif res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
#            mlist =  split_muuid(res.attrs[STUN_ATTRIBUTE_MUUID])
#            p = mcore_handle(check_jluuid,mlist)
#            #p = [check_jluuid(n) for n in mlist]
#            e = [ x for x in p if x]
#            if len(e):
#                res.eattr = STUN_ERROR_UNKNOWN_PACKET
#                mstore.errqueue.put(','.join([LOG_ERROR_UUID,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
#                return stun_error_response(res)
#            #multiprocessing_handle(bind_each_uuid,[(res.fileno,n) for n in mlist])
#            [mstore.bind_each_uuid((n,res.fileno)) for n in mlist]
    except KeyError:
        res.eattr = STUN_ERROR_UNKNOWN_PACKET 
        mstore.errqueue.put(','.join([LOG_ERROR_UUID,mstore.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        print "uuid KeyError,sock %d, dicts" % res.fileno,res.attrs
        return stun_error_response(res)
    if res.eattr != STUN_ERROR_NONE:
        mstore.errqueue.put("socket %d,bind error" % res.fileno)
        return stun_error_response(res)
    return stun_bind_devices_ok(res)


def dealwith_sock_close_update_db(fileno):
    # socket 关闭，更新数据库
    try:
        name = mstore.appsock[fileno].name
        mstore.appsock.pop(fileno)
        mstore.statqueue.put('dev sock close, %d' % fileno)
        mstore.app_user_logout(name)
        return
    except KeyError:
        pass

    try:
        uuid = mstore.devsock[fileno].uuid
        mstore.devsock.pop(fileno)
        mstore.statqueue.put('dev sock close, %d' % fileno)
        mirco_devices_logout(mstore.devsock[fileno].uuid)
    except KeyError:
        pass


def dealwith_peer_hup(fileno):
    delete_fileno(fileno)
    dealwith_sock_close_update_db(fileno)
    dealwith_sock_close_update_binds(fileno)
    remove_fileno_resources(fileno)

def notify_peer_is_logout(pair): # pair[0] == fileno, pair[1] == dstsock
    fileno = pair[0]
    dstsock = pair[1]
    mstore.responses[fileno] =  notify_peer(''.join(['%08x' % dstsock,STUN_OFFLINE]))
    mstore.statqueue.put('socket %d logout send info to socket %d' % (dstsock,fileno))
    try:
        write_to_sock(fileno)
    except IOError:
        mstore.errqueue.put(''.join([LOG_ERROR_SOCK,\
                'socket error %d' % fileno,str(sys._getframe().f_lineno)]))

def clean_timeout_sock(fileno): # 清除超时的连接
    if mstore.timer.has_key(fileno):
        if mstore.timer[fileno] < time.time():
            mstore.statqueue.put("Client %d life time is end,close it" % fileno )
            dealwith_peer_hup(fileno)

def mirco_devices_logout(devid):
    vendor = devid[32:40]
    #print "update status for tuid",hexlify(suid[0])
    mtable = QueryDB.get_devices_table(vendor)
    #ss = mtable.update().values(is_online=False).where(mtable.c.devid == hexlify(suid[0]))
    s = mtable.update().values(is_online=False).where(mtable.c.devid == devid[:32])
    try:
        #res = mstore.execute(ss)
        result =  mstore.execute(s)
    except IOError:
        mstore.errqueue.put(','.join([LOG_ERROR_DB,devid,str(sys._getframe().f_lineno)]))
        return 0


def notify_uuid_app_logout(fileno):
    try:
        binds = mstore.appbinds[fileno].values()
        mstore.appsock.pop(fileno) # 回收这个APP的BIND资源
        [notify_peer_is_logout((n,fileno)) for n in binds if mstore.devsock.has_key(n)]
    except KeyError:
        pass
        #nl = [notify_peer_is_logout(n,fileno) for n in binds if mstore.devsock.has_key(n)]
        #multiprocessing_handle(notify_peer_is_logout,nl)


def notify_app_uuid_logout(fileno):
    # 小机下线，通知APP
    devid = mstore.devsock[fileno].uuid
    #print "devid",devid,"has logout"
    binds = [k for k in mstore.appbinds.keys() if mstore.appbinds.get(k).has_key(devid)]
    [notify_peer_is_logout((n,fileno)) for n in binds if mstore.appsock.has_key(n)]
    #multiprocessing_handle(notify_peer_is_logout,[(n,fileno) for n in binds if mstore.appsock.has_key(n)])
    alist = [n for n in binds if mstore.appsock.has_key(n)]
    for n in alist:
        mstore.appbinds[n][devid]=0xFFFFFFFF

def app_user_logout(uname):
    atable = QueryDB.get_account_status_table()
    ss = atable.update().values(is_login=False).where(atable.c.uname == uname)
    try:
        #res = mstore.execute(ss)
        result = yield mstore.execute(s)
    except :
        mstore.errqueue.put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))


def dealwith_sock_close_update_binds(fileno):
    try:
        name = mstore.appsock[fileno].name
        mstore.statqueue.put('app %s logout info dev,mstore fileno %d' % (name,fileno))
        notify_uuid_app_logout(fileno)
        # APP 应该下线了
    except KeyError:
        pass

    try:
        uuid = mstore.devsock[fileno].uuid
        mstore.statqueue.put('dev %s logout info app,mstore fileno %d' % (uuid,fileno))
        notify_app_uuid_logout(fileno)
        # 小机下线，通知APP
    except KeyError:
        pass

def sock_send_fail(fileno):
    # 要检查一下是不是转发失败了，要通知发送方
#        phead = get_packet_head_class(hbuf)
#        if phead.method == STUN_METHOD_SEND or phead.method == STUN_METHOD_DATA:
#            phead.eattr = STUN_ERROR_DEVOFFLINE
#            srcsock = int(phead.srcsock,16)
#            tbuf = stun_error_response(phead)
#            tbuf[3]=phead.srcsock
#            tbuf[4]=phead.dstsock
#            tbuf.pop()
#            tbuf[2] = '%04x' % (int(tbuf[2],16)-4)
#            stun_add_fingerprint(tbuf)
#            mstore.responses[srcsock] = ''.join(tbuf)
#            mstore.epoll.modify(srcsock,select.EPOLLOUT | select.EPOLLET)
#    
    # sock 关闭时产生的异常处理
    dealwith_peer_hup(fileno)

def sock_recv_fail(fileno):
    # sock 关闭时产生的异常处理
    dealwith_peer_hup(fileno)

def remove_fileno_resources(fileno):
    m = [(getattr(mstore,n),fileno) for n in store]
    mcore_handle(clean_dict,m)


def bind_each_uuid(pair): # pair[0] == ustr,pair[1] == fileno
    ustr = pair[0]
    fileno = pair[1]
    try:
        mstore.appbinds[fileno] is dict
    except KeyError:
        mstore.appbinds[fileno]={}

        # 通知在线的小机，有APP要绑定它
    try:
        dstsock = mstore.devuuid[ustr]
        mstore.appbinds[fileno][ustr]= dstsock
        b = '%08x' % fileno
        #notifybuf = notify_peer(''.join([b,STUN_ONLINE]))
        mstore.responses[dstsock] = notify_peer(''.join([b,STUN_ONLINE]))
        try:
            write_to_sock(dstsock)
        except IOError:
            mstore.errqueue.put(','.join(['dstsock %d has closed' % dstsock,'host is',mstore.hosts[dstsock][0]]))  
            dealwith_peer_hup(dstsock)
    except KeyError:
        mstore.appbinds[fileno][ustr]=0xFFFFFFFF



def stun_bind_devices_ok(res):
    """
    绑定成功，回复APP
    """
    buf = []
    stun_init_command_str(stun_make_success_response(res.method),buf)
    if res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
        joint = [''.join([k,'%08x' % mstore.appbinds[res.fileno][k]]) for k in mstore.appbinds[res.fileno].keys()]
        stun_attr_append_str(buf,STUN_ATTRIBUTE_MRUUID,''.join(joint))
    else:
        jluid = res.attrs[STUN_ATTRIBUTE_UUID]
        stun_attr_append_str(buf,STUN_ATTRIBUTE_RUUID,\
                 ''.join([jluid,'%08x' %mstore.appbinds[res.fileno][jluid]]))

    stun_add_fingerprint(buf)
    return (buf)

def noify_app_uuid_just_login(sock,uuidstr,devsock):
    mstore.responses[sock] = notify_app_bind_islogin(''.join([uuidstr,'%08x' % devsock]))
    mstore.statqueue.put('sock %d, uuid %s login,info to %d user %s' % (devsock,uuidstr,sock,mstore.users[sock]))
    write_to_sock(sock)

def device_login_notify_app(uuidstr,devsock):
    for fk in mstore.appbinds.keys():
        try:
            if mstore.appbinds[fk].has_key(uuidstr):
                noify_app_uuid_just_login(fk,uuidstr,devsock)
                break
        except KeyError:
            pass


def app_user_register(user,pwd):
    account = QueryDB.get_account_table()
    uname = unhexlify(user)
    try:
        obj = hashlib.sha256()
        obj.update(uname)
        obj.update(pwd)
        s = account.insert().values(uname=uname,pwd=obj.digest(),is_active=True,reg_time=datetime.now())
        #mstore.execute(ins)
        result = mstore.execute(s)
        return False
    except IntegrityError:
        mstore.errqueue.put(','.join([LOG_ERROR_REGISTER,uname,str(sys._getframe().f_lineno)]))
        return True
    except DataError:
        print "db error"
        mstore.errqueue.put(','.join([LOG_ERROR_REGISTER,uname,str(sys._getframe().f_lineno)]))
        return True


def app_user_update_status(user,host):
    uname = unhexlify(user)
    status_tables = QueryDB.get_account_status_table()
    ipadr = int(hexlify(socket.inet_aton(host[0])),16) & 0xFFFFFFFF
    ipprt = host[1] & 0xFFFF
    sss = ''
    try:
        sss = status_tables.update().values(last_login_time = datetime.now(),chost=[ipadr,ipprt]).where(status_tables.c.uname == user)
    except DataError:
        sss = status_tables.insert().values(uname=uname,is_login=True,chost=[ipadr,ipprt])

    try:
        #result = mstore.execute(sss)
        result = yield mstore.execute(s)
    except:
        mstore.errqueue.put(','.join([LOG_ERROR_DB,host[0],str(sys._getframe().f_lineno)]))


def app_user_login(uname,pwd):
    account = QueryDB.get_account_table()
    obj = hashlib.sha256()
    obj.update(uname)
    obj.update(pwd)
    s = sql.select([account]).where(and_(account.c.uname == uname,account.c.pwd == obj.digest(),
        account.c.is_active == True))
    try:
        #result = mstore.execute(s)
        result = mstore.execute(s)
        return result.fetchall()
    except:
        mstore.errqueue.put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))


def check_user_in_database(uname):
    account = QueryDB.get_account_table()
    s = sql.select([account.c.uname]).where(account.c.uname == uname)
    try:
        result = mstore.execute(s)
    except:
        mstore.errqueue.put(','.join([LOG_ERROR_DB,uname,mstore.clients[fileno],str(sys._getframe().f_lineno)]))
    return result.fetchall()

def find_device_state(uid):
    vendor = uid[32:40]
    #print "find uuid is",uid,"vendor is",vendor
    mirco_devices = QueryDB.get_devices_table(vendor)
    s = sql.select([mirco_devices]).where(mirco_devices.c.devid == uid[:32] )
    try:
        #result = mstore.execute(s)
        result =  mstore.execute(s)
        return result.fetchall()
    except:
        mstore.errqueue.put(','.join([LOG_ERROR_DB,uuid,str(sys._getframe().f_lineno)]))
        return None
    
    
def update_newdevice(res):
    '''添加新的小机到数据库'''
    mirco_devices = QueryDB.get_devices_table(res.vendor)
    if not mirco_devices.exists(engine):
        mirco_devices.create(engine)
    ipadr = int(hexlify(socket.inet_aton(res.host[0])),16) & 0xFFFFFFFF
    ipprt = res.host[1] & 0xFFFF
    #print "host %d:%d" % (ipadr,ipprt)
    data = ''
    try:
        data = res.attrs[STUN_ATTRIBUTE_DATA]
    except:
        pass

    try: 
        upd = mirco_devices.update().values(is_online=True,chost = [ipadr,ipprt],data=data,
                last_login_time=datetime.now()).where(mirco_devices.c.devid == res.tuid)
        try:
            result = mstore.execute(upd)
        except:
            mstore.errqueue.put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
    except DataError: 
        ins = mirco_devices.insert().values(devid=res.tuid,is_active=True,
                is_online=True,chost=[ipadr,ipprt],data=data,last_login_time=datetime.now())
        try:
            result = mstore.execute(ins)
        except:
            mstore.errqueue.put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
        #print "insert new devices result fetchall"




    
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
port = options.srv_port if options.srv_port else 3478

dirs = ['log']
dirclass = ComState()
for n in dirs:
    fdir = os.path.join(os.path.curdir,n)
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    elif os.path.exists(fdir) and not os.path.isdir(fdir):
        os.rename(fdir,'%s.bak' % fdir)
        os.mkdir(fdir)
    setattr(dirclass,n,fdir)



store = ['clients','hosts','responses','appbinds','appsock','devsock','devuuid','users','requests']
mstore = A()
if __name__ == '__main__':
    atable = QueryDB.get_account_table()
    engine = QueryDB().get_engine()
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
    
    stable = QueryDB.get_account_status_table()
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

    errqueue = Queue()
    statqueue = Queue()
    errlog = ErrLog('epoll_mt_srv')
    statlog = StatLog('epoll_mt_srv')
    errworker = WorkerThread(errqueue,errlog,)
    errworker.daemon = True
    errworker.start()
    statworker = WorkerThread(statqueue,statlog)
    statworker.daemon = True
    statworker.start()
    srv = asyncoro.Coro(EpollServer,errqueue,statqueue)
    while True:
        cmd = sys.stdin.readline().strip().lower()
        if cmd == 'exit' or cmd == 'quit':
                break



