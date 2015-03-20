#!/opt/stackless-279/bin/python2 
#-*- coding: utf-8 -*-
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
import os
import unittest
import argparse

from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql,and_
from sqlalchemy.dialects import postgresql as pgsql
sys.path.insert(0,'/opt/stackless-279/lib/python2.7/site-packages/psycopg2')
import _psycopg
sys.modules['psycopg2._psycopg'] = _psycopg
sys.path.pop(0)
import psycopg2
import hashlib
import select
from epoll_global import *
from multiprocessing import Queue,Process


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

def clean_dict(d,k):
    try:
        d.pop(k)
    except:
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


def stun_ask_mirco_devices_timeout(res):
    #超过一定时间，小机没有回复服务器，就假定小机不可以连接，回复APP端一个错误
    if self.devuuid.has_key(res.fileno):
        self.responses[res.fileno] = stun_error_response(res)
        try:
            self.epoll.modify(res.fileno,select.EPOLLOUT | select.EPOLLET)
        except:
            self.errqueue.put(','.join([LOG_ERROR_SOCK,str(sys._getframe().f_lineno)]))


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


def register_success(uname):
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REGISTER),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_USERNAME,uname)
    stun_add_fingerprint(buf)
    return (buf)


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


def refresh_sucess(ntime): # 刷新成功
    buf = []
    stun_init_command_str(stun_make_success_response(STUN_METHOD_REFRESH),buf)
    stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,ntime)
    stun_add_fingerprint(buf)
    return (buf)

def update_refresh_time(fileno,ntime):
    self.timer[fileno] = time.time()+ntime


class CheckSesionThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(1)
            [clean_timeout_sock(x)  for x in  self.timer.keys()]



class MTWorker(threading.Thread):
#class MTWorker():
    def __init__(self,srvsocket,epoll,errqueue,statqueue):
        threading.Thread.__init__(self)
        self.srvsocket = srvsocket
        self.errqueue = errqueue
        self.statqueue = statqueue
        self.db_engine = QueryDB().get_engine()
        self.dbcon = self.db_engine.connect()
        self.epoll = epoll 
        [setattr(self,x,{}) for x in store]

        self.func= {
              STUN_METHOD_ALLOCATE:self.handle_allocate_request, # 小机登录方法
              STUN_METHOD_REFRESH:self.handle_refresh_request, # 小机登录方法
              STUN_METHOD_CHECK_USER:self.handle_chkuser_request,
              STUN_METHOD_REGISTER:self.handle_register_request,
              STUN_METHOD_BINDING:self.handle_app_login_request,  # app端登录方法
              STUN_METHOD_CHANNEL_BIND:self.handle_app_bind_device  # APP 绑定小机的命令
              }

        #认证后的处理
        self.postfunc={STUN_METHOD_CHANNEL_BIND:self.handle_app_bind_device,
                STUN_METHOD_REFRESH:self.handle_refresh_request,
                STUN_METHOD_MODIFY:self.handle_modify_bind_item,
                STUN_METHOD_DELETE:self.handle_delete_bind_item,
                STUN_METHOD_PULL:self.handle_app_pull
                }

    def handle_modify_bind_item(self,res):
        pass


    def handle_delete_bind_item(self,res):
        pass

    def handle_app_pull(self,res):
        pass

    def delete_fileno(self,fileno):
        try:
            self.epoll.unregister(fileno)
        except:
            self.statqueue.put('already delete socket %d' % fileno)

        try:
            self.clients.get(fileno).close()
            self.clients.pop(fileno)
        except:
            pass

        try:
            self.requests.pop(fileno)
        except:
            pass

    def run(self):
        try:
            while True:
                events = self.epoll.poll(1)
                for fileno,event in events:
                    if fileno == self.srvsocket.fileno():
                        #新的连接
                        try:
                            nsock,addr = self.srvsocket.accept()
                        except:
                            self.errqueue.put(','.join([LOG_ERROR_FILENO,str(sys._getframe().f_lineno)]))
                            continue
                        nf = nsock.fileno()
                        self.statqueue.put(','.join(["new client %s:%d" % addr,"new fileno %d" % nf, 'srv fileno %d'%fileno]))
                        nsock.setblocking(0)
                        self.clients[nf] = nsock
                        try:
                            self.hosts[nf] = nsock.getpeername()
                        except socket.error:
                            self.clients.pop(nf)
                            continue
                        self.responses[nf] = []
                        #self.timer[nf] = time.time()+10
                        self.epoll.register(nf,select.EPOLLIN | select.EPOLLET)
                    elif event & select.EPOLLIN: # 读取socket 的数据
                        try:
                            csock = self.clients[fileno]
                        except KeyError:
                            self.statqueue.put(','.join(['sock %d' % fileno,'not in clients']))
                            self.delete_fileno(fileno)
                            continue

                        try:
                            recvbuf = self.clients[fileno].recv(SOCK_BUFSIZE)
                            if not recvbuf:
                                self.statqueue.put(','.join(['sock %d' % fileno,'recv no buffer']))
                                self.dealwith_peer_hup(fileno)
                                continue
                            hbuf = binascii.hexlify(recvbuf)
                            if cmp(hbuf[:4],HEAD_MAGIC): # 检查JL关键字
                                self.errqueue.put(','.join([LOG_ERROR_PACKET,self.hosts[fileno][0],str(sys._getframe().f_lineno)]))
                                self.delete_fileno(fileno)
                                continue
                            self.process_handle_first((hbuf,fileno))
                        except IOError:
                            self.errqueue.put(','.join(["sock has closed %d,host %s" %(fileno,self.hosts[fileno][0]),\
                                    str(sys._getframe().f_lineno)]))
                            self.sock_recv_fail(fileno)
                    elif event & select.EPOLLOUT:
                        try:
                            sendbuf = self.responses[fileno] #连接命令的时候返回是NULL
                            self.responses.pop(fileno)
                            try:
                                nbyte =  self.clients[fileno].send(\
                                        binascii.unhexlify(''.join(sendbuf)))
                                self.epoll.modify(fileno,select.EPOLLIN | select.EPOLLET)
                            except TypeError:
                                print sendbuf," len ",len(sendbuf)
                            except IOError:
                                self.errqueue.put(','.join(["sock has closed %d,host %s" %(fileno,self.hosts[fileno][0]),\
                                        str(sys._getframe().f_lineno)]))
                                self.sock_send_fail(fileno)
                        except KeyError:
                                self.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d' % fileno,str(sys._getframe().f_lineno)]))
                                #self.epoll.modify(fileno,select.EPOLLWRBAND)
                    elif event & select.EPOLLHUP:
                        self.errqueue.put("sock hup %d" % fileno)
                        self.dealwith_peer_hup(fileno)
                    elif event & select.EPOLLERR:
                        self.errqueue.put("sock error %d" % fileno)
                        self.dealwith_peer_hup(fileno)
    
        finally:
            self.epoll.unregister(self.srvsocket.fileno())
            self.epoll.close()
            self.srvsocket.close()

    def handle_refresh_request(self,res):
        return refresh_sucess(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1])

    def process_handle_first(self,item):
        hbuf = item[0]
        fileno = item[1]
        mlist = []
        if (len(hbuf)/2)  > int(hbuf[8:12],16):
            #print 'hbuf len',len(hbuf),'h len',int(hbuf[8:12],16)
            #读到两个包了
            mplist = [''.join([HEAD_MAGIC,n]) for n in hbuf.split(HEAD_MAGIC) if n ]
            #print "two packet",mplist
            #multiprocessing_handle(handle_requests_buf,[(n,fileno) for n in mplist])
            [self.handle_requests_buf((n,fileno)) for n in mplist]
        else:
            self.handle_requests_buf(item)

    def handle_upload_file(self,res):
        pass

    
                    
    def handle_requests_buf(self,pair): # pair[0] == hbuf, pair[1] == fileno
        hbuf = pair[0]
        fileno = pair[1]
        if not len(hbuf):
            return 
        res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH*2])
        res.eattr = STUN_ERROR_NONE
        res.host= self.hosts.get(fileno)
        res.fileno=fileno

        #通过认证的socket 直接转发了
        if self.appsock.has_key(fileno) or self.devsock.has_key(fileno):
            if (res.method == STUN_METHOD_SEND or res.method == STUN_METHOD_DATA):
                return self.handle_forward_packet(pair,res)

    
        if check_packet_crc32(hbuf):
            self.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d' % fileno,str(sys._getframe().f_lineno)]))
            self.delete_fileno(fileno)
            return 

    
        rbuf = self.handle_client_request(pair,res)
        res = rbuf[1]
        if res.eattr == STUN_ERROR_UNKNOWN_PACKET:
            self.errqueue.put(','.join([LOG_ERROR_IILAGE_CLIENT,'sock %d' % fileno,'method %s' % res.method,str(sys._getframe().f_lineno)]))
            #print 'method', res.method
            self.delete_fileno(fileno)
            return 
    
        if rbuf[0] is None: # 是转发包或者是刷新时间
            return
    
        self.responses[fileno] = rbuf[0]
        self.epoll.modify(fileno,select.EPOLLOUT | select.EPOLLET)

    def handle_forward_packet(self,pair,res):
        buf = pair[0]
        fileno = pair[1]
        #判断如果是转发命令就直接转发了。
        #print "forward packet"
        #print 'dstsock',res.dstsock
        #print 'srcsock',res.srcsock
        dstsock = int(res.dstsock,16)
        srcsock = int(res.srcsock,16)
        #转发的信息不正确
        if dstsock == 0xFFFFFFFF or srcsock == 0xFFFFFFFF:
            res.eattr = STUN_ERROR_UNKNOWN_HEAD
            return  (stun_error_response(res),res)
    
        if self.clients.has_key(dstsock):
            # 转发到时目地
            self.responses[dstsock] = buf
            self.epoll.modify(dstsock,select.EPOLLOUT | select.EPOLLET)
            self.statqueue.put('forward to %d,byte %d' %(dstsock,len(buf)/2))
            return (None,res)
        else: # 目标不存在
            res.eattr = STUN_ERROR_DEVOFFLINE
            #self.epoll.modify(fileno,select.EPOLLOUT)
            #self.responses[fileno] = ''.join(stun_error_response(res))
            tbuf = stun_error_response(res)
            tbuf[3]=res.srcsock
            tbuf[4]=res.dstsock
            tbuf.pop()
            tbuf[2] = '%04x' % (int(tbuf[2],16)-4)
            stun_add_fingerprint(tbuf)
            return (tbuf,res)

    def handle_client_request(self,pair,res): # pair[0] == hbuf, pair[1] == fileno
        """
        -1 CRC 错误的
        -2 非法刷新请求
        0  正常值
        1  APP的连接请求
        2  小机的回复
        3  转发命令
        """
        buf=pair[0]
        fileno = pair[1]

        if not (res.method == STUN_METHOD_ALLOCATE or\
                res.method == STUN_METHOD_BINDING or\
                res.method == STUN_METHOD_CHANNEL_BIND or\
                res.method == STUN_METHOD_REFRESH or\
                res.method == STUN_METHOD_REGISTER):
                    # 非法请求
            self.delete_fileno(fileno)
            #print 'fileno',fileno
            #print 'self.appsock',self.appsock
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            return (None,res)
    
        hexpos = STUN_HEADER_LENGTH*2
        upkg = parser_stun_package(buf[hexpos:-8])
        if upkg is None:
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            return  (stun_error_response(res),res)
    
        res.attrs = upkg
    
        if res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) and int(res.attrs.get(STUN_ATTRIBUTE_MESSAGE_INTEGRITY)[1],16) != 32:
            res.eattr = STUN_ERROR_AUTH
            self.errqueue.put(','.join([LOG_ERROR_AUTH,self.hosts[fileno][0],str(sys._getframe().f_lineno)]))
            return  (stun_error_response(res),res)
    
        if self.func.has_key(res.method):
            return  (self.func[res.method](res),res)
        else:
            res.eattr = STUN_ERROR_UNKNOWN_METHOD
            self.errqueue.put(','.join([LOG_ERROR_METHOD,res.method,self.hosts[fileno][0],str(sys._getframe().f_lineno)]))
            return  (stun_error_response(res),res)

    def handle_app_login_request(self,res):
        if not res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) or  not res.attrs.has_key(STUN_ATTRIBUTE_USERNAME):
           res.eattr = STUN_ERROR_AUTH
           return  stun_error_response(res)# APP端必须带用认证信息才能发起连接.
    
        result = self.app_user_login(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],
                res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1])
        if not result:
            res.eattr = STUN_ERROR_AUTH
            return  stun_error_response(res)
    
        self.appsock[res.fileno] = tcs = ComState()
        tcs.name = result[0][0]
        self.app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],res.host)
    #    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
    #        update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
    #    else:
    #        update_refresh_time(res.fileno,UCLIENT_SESSION_LIFETIME)
        self.statqueue.put('user %s login,socket is %d' % (tcs.name,res.fileno))
        return app_user_auth_success(res)

    def handle_allocate_request(self,res):
        """
        小机登录服务器的命令，必须要有uuid,data
        """
        try:
            chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID][-1])
            if chk:
                res.eattr = chk
                self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
                return stun_error_response(res)
        except KeyError:
            #res.eattr= binascii.hexlify("Not Found UUID")
            res.eattr=STUN_ERROR_UNKNOWN_PACKET
            self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
    
        huid = res.attrs[STUN_ATTRIBUTE_UUID][-1]
        self.device_login_notify_app(huid,res.fileno)
    #    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
    #        update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
    #    else:
    #        update_refresh_time(res.fileno,UCLIENT_SESSION_LIFETIME)
    
        res.vendor = huid[32:40]
        res.tuid = huid[:32]
        self.update_newdevice(res)
        #self.actives[res.fileno] = huid
        self.devsock[res.fileno] = tcs = ComState()
        self.devuuid[huid] = res.fileno
        tcs.uuid = huid
        #print "login devid is",tcs.uuid
        self.statqueue.put('device login uuid is %s,socket is %d' % (huid,res.fileno))
        return device_login_sucess(res)

    def handle_chkuser_request(self,res):
        f = check_user_in_database(res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
        if f != 0:
            self.errqueue.put("User Exist %s" % res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)
        else:
            return check_user_sucess(res)

    def handle_register_request(self,res):
        if self.app_user_register(res.attrs[STUN_ATTRIBUTE_USERNAME][-1],
                res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY][-1]):
            # 用户名已经存了。
            self.errqueue.put("User has Exist!i %s" % res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)
        return register_success(res.attrs[STUN_ATTRIBUTE_USERNAME][-1])
    def handle_add_bind_to_user(self,res):
        atable = QueryDB.get_account_bind_table(res.attrs[USERNAME])
        if not atable.exists(self.engine):
            self.dbcon.execute(atable)

    def handle_app_bind_device(self,res):
        #绑定小机的命的命令包
        if res.attrs.has_key(STUN_ATTRIBUTE_UUID):
            chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID][-1])
            if chk:
                res.eattr = chk
                self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(str(sys._getframe().f_lineno))]))
                return stun_error_response(res)

            self.bind_each_uuid((res.attrs[STUN_ATTRIBUTE_UUID][-1],res.fileno))
        elif res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
            mlist =  split_muuid(res.attrs[STUN_ATTRIBUTE_MUUID][-1])
            ps = multiprocessing.cpu_count()*2
            pl = Pool(ps)
            p = pl.map(check_jluuid,mlist)
            p.close()
            p.join()
            #p = [check_jluuid(n) for n in mlist]
            e = [ x for x in p if x]
            if len(e):
                res.eattr = STUN_ERROR_UNKNOWN_PACKET
                self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
                return stun_error_response(res)
            #multiprocessing_handle(bind_each_uuid,[(res.fileno,n) for n in mlist])
            [self.bind_each_uuid((n,res.fileno)) for n in mlist]
        else:
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
        return self.stun_bind_devices_ok(res)
    

    def dealwith_sock_close_update_db(self,fileno):
        # socket 关闭，更新数据库
        if self.appsock.has_key(fileno): #更新相应的数据库在线状态
            self.statqueue.put('app sock close, %d' % fileno)
            #print "appsock is",self.appsock
            self.app_user_logout(self.appsock[fileno].name)
    #        try:
    #            self.appsock.pop(fileno)
    #        except:
    #            pass
        elif self.devsock.has_key(fileno):
            self.statqueue.put('dev sock close, %d' % fileno)
            self.mirco_devices_logout(self.devsock[fileno].uuid)
    #        try:
    #            self.devsock.pop(fileno)
    #        except:
    #            pass


    def dealwith_peer_hup(self,fileno):
        self.dealwith_sock_close_update_db(fileno)
        self.dealwith_sock_close_update_binds(fileno)
        self.remove_fileno_resources(fileno)
        self.delete_fileno(fileno)

    def notify_peer_is_logout(self,pair): # pair[0] == fileno, pair[1] == dstsock
        fileno = pair[0]
        dstsock = pair[1]
        self.responses[fileno] =  notify_peer(''.join(['%08x' % dstsock,STUN_OFFLINE]))
        self.statqueue.put('socket %d logout send info to socket %d' % (dstsock,fileno))
        try:
            self.epoll.modify(fileno,select.EPOLLOUT | select.EPOLLET)
        except:
            self.errqueue.put(''.join([LOG_ERROR_PACKET,\
                    'socket error %d' % fileno,str(sys._getframe().f_lineno)]))
    
    def clean_timeout_sock(self,fileno): # 清除超时的连接
        if self.timer.has_key(fileno):
            if self.timer[fileno] < time.time():
                self.statqueue.put("Client %d life time is end,close it" % fileno )
                dealwith_peer_hup(fileno)
    
    def mirco_devices_logout(self,devid):
        vendor = devid[32:40]
        #print "update status for tuid",binascii.hexlify(suid[0])
        mtable = QueryDB.get_devices_table(vendor)
        #ss = mtable.update().values(is_online=False).where(mtable.c.devid == binascii.hexlify(suid[0]))
        ss = mtable.update().values(is_online=False).where(mtable.c.devid == devid[:32])
        try:
            res = self.dbcon.execute(ss)
        except IOError:
            self.errqueue.put(','.join([LOG_ERROR_DB,devid,str(sys._getframe().f_lineno)]))
            return 0
    
    
    def notify_uuid_app_logout(self,fileno):
        # app 下线，通知小机
        #binds = [v for k,v in self.appbinds[fileno].iteritems()]
        try:
            binds = self.appbinds[fileno].values()
            self.appsock.pop(fileno) # 回收这个APP的BIND资源
            [self.notify_peer_is_logout((n,fileno)) for n in binds if self.devsock.has_key(n)]
        except KeyError:
            pass
            #nl = [notify_peer_is_logout(n,fileno) for n in binds if self.devsock.has_key(n)]
            #multiprocessing_handle(notify_peer_is_logout,nl)
    
    
    def notify_app_uuid_logout(self,fileno):
        # 小机下线，通知APP
        devid = self.devsock[fileno].uuid
        #print "devid",devid,"has logout"
        binds = [k for k in self.appbinds.keys() if self.appbinds.get(k).has_key(devid)]
        [self.notify_peer_is_logout((n,fileno)) for n in binds if self.appsock.has_key(n)]
        #multiprocessing_handle(notify_peer_is_logout,[(n,fileno) for n in binds if self.appsock.has_key(n)])
        alist = [n for n in binds if self.appsock.has_key(n)]
        for n in alist:
            self.appbinds[n][devid]=0xFFFFFFFF
    
    def app_user_logout(self,uname):
        atable = QueryDB.get_account_status_table()
        ss = atable.update().values(is_login=False).where(atable.c.uname == uname)
        try:
            res = self.dbcon.execute(ss)
        except :
            self.errqueue.put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))
    
    
    def dealwith_sock_close_update_binds(self,fileno):
        if self.appsock.has_key(fileno):
            self.statqueue.put('app logout info dev, %d' % fileno)
            self.notify_uuid_app_logout(fileno)
            # APP 应该下线了
        elif self.devsock.has_key(fileno):
            self.statqueue.put('dev logout info app, %d' % fileno)
            self.notify_app_uuid_logout(fileno)
            # 小机下线，通知APP
    
    def sock_send_fail(self,fileno):
        # 要检查一下是不是转发失败了，要通知发送方
        phead = get_packet_head_class(self.responses[fileno])
        if phead.method == STUN_METHOD_SEND or phead.method == STUN_METHOD_DATA:
            phead.eattr = STUN_ERROR_DEVOFFLINE
            srcsock = int(phead.srcsock,16)
            tbuf = stun_error_response(phead)
            tbuf[3]=phead.srcsock
            tbuf[4]=phead.dstsock
            tbuf.pop()
            tbuf[2] = '%04x' % (int(tbuf[2],16)-4)
            stun_add_fingerprint(tbuf)
            self.responses[srcsock] = ''.join(tbuf)
            self.epoll.modify(srcsock,select.EPOLLOUT | select.EPOLLET)
    
        # sock 关闭时产生的异常处理
        self.dealwith_peer_hup(fileno)
    
    def sock_recv_fail(self,fileno):
        # sock 关闭时产生的异常处理
        self.dealwith_peer_hup(fileno)
    
    def remove_fileno_resources(self,fileno):
        [clean_dict(getattr(self,n),fileno) for n in store]


    def bind_each_uuid(self,pair): # pair[0] == ustr,pair[1] == fileno
        ustr = pair[0]
        fileno = pair[1]
        try:
            self.appbinds[fileno] is dict
        except KeyError:
            self.appbinds[fileno]={}
    
            # 通知在线的小机，有APP要绑定它
        try:
            dstsock = self.devuuid[ustr]
            self.appbinds[fileno][ustr]= dstsock
            b = '%08x' % fileno
            notifybuf = notify_peer(''.join([b,STUN_ONLINE]))
            self.responses[dstsock] = notify_peer(''.join([b,STUN_ONLINE]))
            try:
                self.epoll.modify(dstsock,select.EPOLLOUT | select.EPOLLET )
            except IOError:
                self.errqueue.put(','.join(['dstsock %d has closed' % dstsock,'host is',self.hosts[dstsock][0]]))  
                dealwith_peer_hup(dstsock)
        except KeyError:
            self.appbinds[fileno][ustr]=0xFFFFFFFF
    
    
    
    def stun_bind_devices_ok(self,res):
        """
        绑定成功，回复APP
        """
        buf = []
        stun_init_command_str(stun_make_success_response(res.method),buf)
        if res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
            joint = [''.join([k,'%08x' % self.appbinds[res.fileno][k]]) for k in self.appbinds[res.fileno].keys()]
            stun_attr_append_str(buf,STUN_ATTRIBUTE_MRUUID,''.join(joint))
        else:
            jluid = res.attrs[STUN_ATTRIBUTE_UUID][-1]
            stun_attr_append_str(buf,STUN_ATTRIBUTE_RUUID,\
                     ''.join([jluid,'%08x' %self.appbinds[res.fileno][jluid]]))
        stun_add_fingerprint(buf)
    
        return (buf)

    def noify_app_uuid_just_login(self,sock,uuidstr,devsock):
        self.responses[sock] = notify_app_bind_islogin(''.join([uuidstr,'%08x' % devsock]))
        self.epoll.modify(sock,select.EPOLLOUT | select.EPOLLET)
    
    def device_login_notify_app(self,uuidstr,devsock):
        for fk in self.appbinds.keys():
            try:
                if self.appbinds[fk].has_key(uuidstr):
                    self.noify_app_uuid_just_login(fk,uuidstr,devsock)
                    break
            except KeyError:
                pass
    

    def app_user_register(self,user,pwd):
        account = QueryDB.get_account_table()
        #print "register new account %s,%s" % (user,pwd)
        uname = binascii.unhexlify(user)
        sss = sql.select([account]).where(account.c.uname == uname)
        res = self.dbcon.execute(sss)
        if len(res.fetchall()):
            return True
        else:
            obj = hashlib.sha256()
            obj.update(uname)
            obj.update(pwd)
            ins = account.insert().values(uname=uname,pwd=obj.digest(),is_active=True,reg_time=datetime.now())
            try:
                self.dbcon.execute(ins)
            except:
                self.errqueue.put(','.join([LOG_ERROR_REGISTER,uname,str(sys._getframe().f_lineno)]))
                return True
            return False
    
    def app_user_update_status(self,user,host):
        uname = binascii.unhexlify(user)
        status_tables = QueryDB.get_account_status_table()
        ipadr = int(binascii.hexlify(socket.inet_aton(host[0])),16) & 0xFFFFFFFF
        ipprt = host[1] & 0xFFFF
        s = sql.select([status_tables]).where(status_tables.c.uname == uname)
        result = self.dbcon.execute(s)
        row = result.fetchall()
        #print "row is",row
        sss = 0
        if row:
            sss = status_tables.update().values(last_login_time = datetime.now(),chost=[ipadr,ipprt]).where(status_tables.c.uname == user)
        else:
            sss = status_tables.insert().values(uname=uname,is_login=True,chost=[ipadr,ipprt])
        try:
            result = self.dbcon.execute(sss)
        except:
            self.errqueue.put(','.join([LOG_ERROR_DB,host,str(sys._getframe().f_lineno)]))
    
    
    def app_user_login(self,user,pwd):
        uname = binascii.unhexlify(user)
        account = QueryDB.get_account_table()
        obj = hashlib.sha256()
        obj.update(uname)
        obj.update(pwd)
        s = sql.select([account]).where(and_(account.c.uname == uname,account.c.pwd == obj.digest(),
            account.c.is_active == True))
        try:
            result = self.dbcon.execute(s)
        except:
            self.errqueue.put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))
        return result.fetchall()
    
    
    def check_user_in_database(self,uname):
        account = QueryDB.get_account_table()
        s = sql.select([account.c.uname]).where(account.c.uname == uname)
        try:
            result = self.dbcon.execute(s)
        except:
            self.errqueue.put(','.join([LOG_ERROR_DB,uname,self.clients[fileno],str(sys._getframe().f_lineno)]))
        return result.fetchall()
    
    def find_device_state(self,uid):
        vendor = uid[32:40]
        #print "find uuid is",uid,"vendor is",vendor
        mirco_devices = QueryDB.get_devices_table(vendor)
        s = sql.select([mirco_devices]).where(mirco_devices.c.devid == uid[:32] )
        try:
            result = self.dbcon.execute(s)
            return result.fetchall()
        except:
            self.errqueue.put(','.join([LOG_ERROR_DB,uuid,str(sys._getframe().f_lineno)]))
            return None
    
    
    def update_newdevice(self,res):
        '''添加新的小机到数据库'''
        mirco_devices = QueryDB.get_devices_table(res.vendor)
        if not mirco_devices.exists(engine):
            mirco_devices.create(engine)
        s = sql.select([mirco_devices.c.devid]).where(mirco_devices.c.devid == res.tuid)
        row = ''
        try:
            result = self.dbcon.execute(s)
            row = result.fetchall()
        except:
            self.errqueue.put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
        ipadr = int(binascii.hexlify(socket.inet_aton(res.host[0])),16) & 0xFFFFFFFF
        ipprt = res.host[1] & 0xFFFF
        #print "host %d:%d" % (ipadr,ipprt)
        data = ''
        try:
            data = res.attrs[STUN_ATTRIBUTE_DATA][-1]
        except:
            pass
    
        if not row: # 找不到这个UUID 就插入新的
            ins = mirco_devices.insert().values(devid=res.tuid,is_active=True,
                    is_online=True,chost=[ipadr,ipprt],data=data,last_login_time=datetime.now())
            try:
                result = self.dbcon.execute(ins)
            except:
                self.errqueue.put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
            #print "insert new devices result fetchall"
        else:
            upd = mirco_devices.update().values(is_online=True,chost = [ipadr,ipprt],data=data,
                    last_login_time=datetime.now()).where(mirco_devices.c.devid == res.tuid)
            try:
                result = self.dbcon.execute(upd)
            except:
                self.errqueue.put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))

class WorkerThread(threading.Thread):
    def __init__(self,queue,logger):
        threading.Thread.__init__(self)
        self.queue = queue 
        self.log = logger

    def run(self):
        while True:
            msg = self.queue.get()
            self.log.log(msg)
            time.sleep(0.1)


class EpollServer():
    def __init__(self,port):
        self.srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.srvsocket.setsockopt(socket.SOL_SOCKET,socket.TCP_NODELAY,1)
        self.srvsocket.setsockopt(socket.SOL_SOCKET,socket.TCP_QUICKACK,1)
        #self.srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
        self.srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_DEBUG,0)
        #self.srvsocket.setsockopt(socket.SOL_TCP,socket.TCP_KEEPCNT,2)
        #self.srvsocket.setsockopt(socket.SOL_TCP,socket.TCP_KEEPINTVL,30)
        #self.srvsocket.setsockopt(socket.SOL_TCP,socket.TCP_KEEPIDLE,60)
        self.srvsocket.settimeout(SOCK_TIMEOUT)
        self.srvsocket.bind(('',port))
        self.srvsocket.listen(1024)
        self.srvsocket.setblocking(0)
        self.epoll = select.epoll()
        self.epoll.register(self.srvsocket.fileno(),select.EPOLLIN | select.EPOLLET)
        

    def start(self):
        errqueue = Queue()
        statqueue = Queue()
        errlog = ErrLog('epoll_mt_srv')
        statlog = StatLog('epoll_mt_srv')
        errworker = WorkerThread(errqueue,errlog,)
        errworker.start()
        statworker = WorkerThread(statqueue,statlog)
        statworker.start()

        mt = MTWorker(self.srvsocket,self.epoll,errqueue,statqueue)
        mt.setDaemon(True)
        mt.run()
        #psize = multiprocessing.cpu_count()*2
        #pool = multiprocessing.Pool(psize)
        #res = pool.apply_async(MPrun,(self.srvsocket,self.epoll))
        #handle_proc.apply_async()
        #pool_size = multiprocessing.cpu_count() * 2
        #gpool  = Pool(pool_size) 
    
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

class QueryDB():
    def __init__(self):
        self.engine = create_engine('postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/nath',pool_size=1024,max_overflow=20)

    def check_table(self,table):
        return table.exists(self.engine)

    def get_engine(self):
        return self.engine

    def get_dbconn(self):
        return self.get_engine().connect()

    def create_table(self,sql_txt):
        self.engine.connect().execute(sql_txt)

    @staticmethod
    def get_account_bind_table(name):
        metadata = MetaData()
        table = Table(name,metadata,
                Column('uuid',pgsql.VARCHAR(24),nullable=False,primary_key=True),
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



store = ['clients','hosts','requests','responses','appbinds','appsock','devsock','devuuid']
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

    EpollServer(port).start()


