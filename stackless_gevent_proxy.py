#!/opt/stackless-279/bin/python2 
#-*- coding: utf-8 -*-
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
import uuid
import sys
import os
import unittest
import argparse
import errno
from binascii import unhexlify,hexlify
from datetime import datetime
import hashlib
import gc
from sockbasic import *
from pg_driver import *
from cluster_mod import *
#from sockbasic import MySQLEngine as QueryDB
from pg_driver import PostgresSQLEngine as QueryDB
import threading
import gevent
from gevent.server import StreamServer,_tcp_listener,DatagramServer
from gevent import server,event,socket,monkey
from gevent.pool import Group
from gevent.queue import Queue
from multiprocessing import Process,current_process
import multiprocessing as mp
monkey.patch_all(thread=False)


from sqlalchemy import *
from sqlalchemy.exc import *
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql,and_
from sqlalchemy.dialects import postgresql as pgsql

try:
    import cPickle as pickle
except:
    import pickle

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
    od = stun_init_command_head(stun_make_success_response(STUN_METHOD_INFO))
    stun_attr_append_str(od,STUN_ATTRIBUTE_STATE,state_info)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def notify_app_bind_islogin(bindinfo):
    od = stun_init_command_head(stun_make_success_response(STUN_METHOD_INFO))
    stun_attr_append_str(od,STUN_ATTRIBUTE_RUUID,bindinfo)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def register_success(uname,ftpwd):
    od = stun_init_command_head(stun_make_success_response(STUN_METHOD_REGISTER))
    stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,uname)
    stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,ftpwd)
    stun_add_fingerprint(od)
    return get_list_from_od(od)


def check_user_sucess(res):
    od = stun_init_command_head(stun_make_success_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,res.attrs[STUN_ATTRIBUTE_USERNAME])
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def app_user_auth_success(res,ftpwd):
    od= stun_init_command_head(stun_make_success_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_STATE,struct.pack('!II',res.fileno,STUN_ONLINE))
    stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,res.attrs[STUN_ATTRIBUTE_USERNAME])
    stun_attr_append_str(od,STUN_ATTRIBUTE_MESSAGE_INTEGRITY,str(ftpwd))
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def device_login_sucess(res,apps): # 客服端向服务器绑定自己的IP
    od = stun_init_command_head(stun_make_success_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_STATE, struct.pack('!II',res.fileno,STUN_ONLINE))
    if apps: 
        stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,apps)
    stun_add_fingerprint(od)
    lst = get_list_from_od(od)
    return lst

def app_user_pull_table(res,data):
    buf = []
    od = stun_init_command_head(stun_make_success_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,data)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def refresh_sucess(ntime): # 刷新成功
    buf = []
    od = stun_init_command_head(stun_make_success_response(STUN_METHOD_REFRESH))
    stun_attr_append_str(od,STUN_ATTRIBUTE_LIFETIME,ntime)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def stun_return_same_package(res):
    od = stun_init_command_head(stun_make_success_response(res.method))
    stun_add_fingerprint(od)
    return get_list_from_od(od)


class EpollServer():
    def __init__(self,port,cluster_eth):
        """创建多个engine让它平均到多个进程上，性能问题要进一步调试"""
        self.maxbuffer = ''
        [setattr(self,x,{}) for x in store]
        """取得厂商数量，避免每次去查询"""
        self.db = PostgresSQLEngine()
        self.mcastsqueue = Queue()
        self.mcastrqueue = Queue()
        #self.cluster = ClusterSRV(cluster_eth)
        print "start cluster multicast"
        self.vendors = self.db.get_vendor_to_set()
        self.prefunc= {
              STUN_METHOD_ALLOCATE:self.handle_allocate_request, # 小机登录方法
              STUN_METHOD_CHECK_USER:self.handle_chkuser_request,
              STUN_METHOD_REGISTER:self.handle_register_request,
              STUN_METHOD_APPLOGIN:self.handle_app_login_request  # app端登录方法
              }

        #认证后的处理
        self.postfunc={
                STUN_METHOD_CHANNEL_BIND:self.handle_app_bind_device,  # APP 绑定小机的命令
                #STUN_METHOD_REFRESH:self.handle_refresh_request,
                STUN_METHOD_MODIFY:self.handle_modify_bind_item, #修改绑定的信息
                STUN_METHOD_DELETE:self.handle_delete_bind_item, #删除现有的绑定
                STUN_METHOD_PULL:self.handle_app_pull
                }
        self.listener = _tcp_listener(('0.0.0.0',3478),65536,1)
        self.fwdcounter = None
        self.errqueue =None
        #self.statqueue = {}
        self.fwdqueue = None
        #self.statlog = {}
        self.errlog = None
        self.fwdlog = None
        self.startime = time.time()
        #for i in xrange(mp.cpu_count()-1):
        #for i in xrange(1):
        #    Process(target=self.start_srv).start()
        #self.server.serve_forever()
        Process(target=self.start_srv)

    def report_status(self):
        ltime = time.time()
        lcounter = self.fwdcounter
        while 1:
            rate = 0
            try:
                rate = float(self.fwdcounter-lcounter)/ (time.time() - ltime)
            except ZeroDivisionError:
                pass
            self.fwdqueue.put("time %.5f,fwd counter %d, app online %d, dev online %d, fwd rate avg 30 seconds %.5f,max buffer size %s" \
                    % (time.time(),self.fwdcounter,len(self.appsock),len(self.devsock),rate,self.maxbuffer))
            ltime = time.time()
            #print "20 self.appbinds",self.appbinds.keys()
            gevent.sleep(30)

    def start_srv(self):
        self.fwdcounter = 0
        self.fwdqueue = Queue()
        #self.statqueue[current_process().name] = Queue()
        self.errqueue = Queue()

        #self.statlog[current_process().name] = StatLog('state_%s' % current_process().name)
        self.errlog= StatLog('err')
        self.fwdlog = StatLog('fwd')

        errworker = threading.Thread(target=logger_worker,args=(self.errqueue,self.errlog))
        errworker.start()
        #statworker = threading.Thread(target=logger_worker,args=(self.statqueue[current_process().name],self.statlog[current_process().name]))
        #statworker.start()
        fwdworker= threading.Thread(target=logger_worker,args=(self.fwdqueue,self.fwdlog))
        fwdworker.start()
        #recvworker= threading.Thread(target=logger_worker,args=(recvqueue,recvlog))
        #recvworker.start()
        threading.Thread(target=self.report_status).start()
        server.StreamServer(self.listener,self.handle_new_accept).serve_forever()


    def handle_new_accept(self,nsock,addr):
        fileno = nsock.fileno()
        self.clients[fileno] = nsock
        self.hosts[fileno] = addr
        #print "new accept()",addr
        self.requests[fileno] =''
        #hstr = str(addr)
        #recvqueue.put('new accept %s, sock %d' % (str(addr),fileno))
        n = 5
        while 1:
            try:
                recvbuf = nsock.recv(SOCK_BUFSIZE)
            except IOError:
                self.errqueue.put('sock %d, IOError ,%s' % (fileno,hstr))
                break
            except socket.error:
                self.errqueue.put("%s socket.error,sock %d" % (hstr,fileno))
                break
            else:
                if not recvbuf:
                    if n:
                        n -= 1
                        gevent.sleep(0)
                        continue
                    else:
                        self.errqueue.put("%s no data,sock %d" % (hstr,fileno))
                        break
                n = 5 # 重试读取5次
                try:
                    self.requests[fileno] += recvbuf
                except KeyError:
                    self.errqueue.put("%s requests KeyError,sock %d" % (hstr,fileno))
                    break
                self.process_handle_first(fileno)
            gevent.sleep(0) #让出CPU
        self.dealwith_peer_hup(fileno)
        """退出本线程"""
    

    def handle_modify_bind_item(self,res):
        #btable = QueryDB.get_account_bind_table(self.users[res.fileno])
        uname = self.users.get(res.fileno,None)
        uids = res.attrs.get(STUN_ATTRIBUTE_UUID,None)
        pwd = res.attrs.get(STUN_ATTRIBUTE_MESSAGE_INTEGRITY,None)
        if not uname or not uids or not pwd:
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            return  stun_error_response(res)
        self.db.update_bind_table(user,uids,pwd)
        return stun_return_same_package(res)


    def handle_delete_bind_item(self,res):
        uname = self.users.get(res.fileno,None)
        uids = res.attrs.get(STUN_ATTRIBUTE_UUID,None)
        if not uname or not uids:
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            return  stun_error_response(res)
        try:
            n = [ n for n in self.appbinds.values if n.has_key(uids)]
            popfunc = lambda d,v: d.pop(v)
            k = mcore_handle(popfunc,(n))
        except TypeError:
            self.errqueue.put("TypeError %d,n is none" % res.fileno)

        self.db.delete_bind_table(uname,devid)
        return  stun_return_same_package(res)
        

    def delete_binds_in_db(self,uname,uids):
        try:
            btable = QueryDB.get_account_bind_table(uname)
            QueryDB.select(btable.delete().where(btable.c.uuid == uids))
        except KeyError:
            pass


    def handle_app_pull(self,res):
        """
        用户从服务器拉数据表
        """
        uname = self.users[res.fileno]
        data = self.db.pull_bind_table(uname)
        if not data:
            res.eattr = STUN_ERROR_OBJ_NOT_EXIST
            return  stun_error_response(res)
        return  app_user_pull_table(res,data)

    def delete_fileno(self,fileno):
        try:
            self.clients[fileno].close()
        except KeyError:
            pass
        self.clients.pop(fileno,None)



    def write_to_sock(self,fileno):
        try:
            sock = self.clients[fileno]
        except KeyError:
            self.errqueue.put('sock %d, due to write_to_sock failed' % (fileno,))
            return
        else:
            try:
                #print "srv send buf",hexlify(''.join(self.responses[fileno]))
                sock.send(''.join(self.responses[fileno]))
                self.responses[fileno] = None
            except socket.error:
                self.dealwith_peer_hup(fileno)

    def handle_cluster(self,data,addr):
        pass
        

    def handle_refresh_request(self,res):
        pass

    def process_handle_first(self,fileno):
        l = self.requests[fileno].count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            self.errqueue.put('sock %d, recv no HEAD_MAGIC packet %s' % (fileno,self.requests[fileno]))
            return
        plen = len(self.requests[fileno])
        if l > 1:
            self.maxbuffer = str(plen)
            #hbuf = hbuf[l:] # 从找到标识头开始处理
            mulist = split_requests_buf(self.requests[fileno])
            pos = sum([len(n) for n in mulist])
            self.requests[fileno] = self.requests[fileno][pos:]
            [self.handle_requests_buf(n,fileno) for n in mulist]
            del mulist[:]
            del mulist
            #gevent.sleep(0.1)
        else: # 找到一个标识，还不知在什么位置
            pos = self.requests[fileno].index(HEAD_MAGIC)
            self.requests[fileno] = self.requests[fileno][pos:]
            nlen = unpack16(self.requests[fileno][4:6] )#包头指法的长度
            if len(self.requests[fileno]) < nlen:
                return
            onepack = self.requests[fileno][:nlen]
            self.requests[fileno] = self.requests[fileno][nlen:]
            self.handle_requests_buf(onepack,fileno)
            del onepack
            
                    
    def handle_requests_buf(self,hbuf,fileno): # pair[0] == hbuf, pair[1] == fileno
        if not hbuf:
            return 
        res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not res:
            if fileno in self.appsock:
                self.errqueue.put('get jl head error,appsock ,sock %d,%s,buf %s' % (fileno,self.hosts[fileno],hbuf))
            else:
                self.errqueue.put('get jl head error,devsock,sock %d,%s,buf %s' % (fileno,self.hosts[fileno],hbuf))

            return
        res.eattr = STUN_ERROR_NONE
        try:
            res.host= self.hosts[fileno]
        except KeyError:
            self.errqueue.put('sock %d, not has hostinfo' % (fileno))
            for n in STUN_HEAD_KEY:
                res.__dict__.pop(n,None)
            return 

        res.fileno=fileno
        #通过认证的socket 直接转发了
        try:
            aforward = self.appsock[fileno]
        except KeyError: 
            """如果是多台主机分布式负载，这里要查一下其它主机"""
            #self.cluster.get_user_info(self.users[fileno])
            pass
        else:
            if res.method == STUN_METHOD_REFRESH: # 刷新就可以步过了
                for n in STUN_HEAD_KEY:
                    res.__dict__.pop(n,None)
                res.__dict__.pop('fileno',None)
                return
            elif res.method == STUN_METHOD_SEND: 
                if check_dst_and_src(res):
                    self.responses[fileno] = stun_error_response(res)
                    self.write_to_sock(fileno)
                else:
                    """
                     直接转发了
                    """
                    self.handle_forward_packet(hbuf,res,self.devsock)
            else:
                self.handle_postauth_process(res,hbuf)
            """
            如果是app转发就在这里返回
            """
            res.__dict__.pop('eattr',None)
            res.__dict__.pop('fileno',None)
            res.__dict__.pop('host',None)
            res.__dict__.pop('attrs',None)
            for n in STUN_HEAD_KEY:
                res.__dict__.pop(n,None)
            res.__dict__.pop('fileno',None)
            del res
            return # 一切正常返回


        """是否是dev发出来的包"""
        try:
            dforward = self.devsock[fileno]
        except KeyError:
            pass
        else:
            if res.method == STUN_METHOD_REFRESH:
                for n in STUN_HEAD_KEY:
                    res.__dict__.pop(n,None)
                res.__dict__.pop('fileno',None)
                return
            elif res.method == STUN_METHOD_DATA:
                if check_dst_and_src(res):
                    self.responses[fileno] = stun_error_response(res)
                    self.write_to_sock(fileno)
                else:
                    """
                     直接转发了
                    """
                    self.handle_forward_packet(hbuf,res,self.appsock)
            else:
                self.handle_postauth_process(res,hbuf)
            """
            如果是dev转发就在这里返回
            """
            res.__dict__.pop('eattr',None)
            res.__dict__.pop('fileno',None)
            res.__dict__.pop('host',None)
            res.__dict__.pop('attrs',None)
            for n in STUN_HEAD_KEY:
                res.__dict__.pop(n,None)
            del res
            return # 一切正常返回

        """
        处理要认证的客务端
        """
        self.handle_client_request_preauth(res,hbuf)

        res.__dict__.pop('eattr',None)
        res.__dict__.pop('fileno',None)
        res.__dict__.pop('host',None)
        res.__dict__.pop('attrs',None)
        for n in STUN_HEAD_KEY:
            res.__dict__.pop(n,None)
        del res

    def handle_postauth_process(self,res,hbuf):
        """
        执行认证后的函数
        """
        hexpos = STUN_HEADER_LENGTH
        res.attrs =  parser_stun_package(hbuf[hexpos:-4])
        if res.attrs is None:
            print "postfunc parser_stun_package is None buf: ",hexlify(hbuf),res.__dict__,res.host
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.errqueue.put(','.join([LOG_ERROR_ATTR,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            self.responses[res.fileno] = stun_error_response(res)
            self.write_to_sock(res.fileno)
        else:
            self.responses[res.fileno]=  self.postfunc[res.method](res)
            self.write_to_sock(res.fileno)

            #print "from postauth error to preauth"
            #self.handle_client_request_preauth(res,hbuf)
    
                
    def handle_forward_packet(self,hbuf,res,dst):
        #print "fwd, dstsock",hex(res.dstsock)
        try:
            s = dst[res.dstsock]
            # 转发到时目地
            self.responses[res.dstsock] = hbuf
            fileno = res.fileno
            dstsock = res.dstsock
            #fwdqueue.put(';src:[%s,sock %d]; dst:[%s,sock %d] ; buf:%s' % (str(res.host),fileno,str(self.hosts[dstsock]),dstsock,hbuf))
            self.fwdcounter +=1
            self.write_to_sock(res.dstsock)
        except KeyError: # 目标不存在
            res.eattr = STUN_ERROR_DEVOFFLINE
            #self.epoll.modify(fileno,select.EPOLLOUT)
            #self.responses[fileno] = ''.join(stun_error_response(res))
            #tbuf = stun_error_response(res)
            od = stun_init_command_head(stun_make_success_response(STUN_METHOD_INFO))
            stun_attr_append_str(od,STUN_ATTRIBUTE_STATE, struct.pack('!II',res.dstsock,STUN_OFFLINE))
            od['srcsock'] = pack32(res.srcsock)
            od['dstsock'] = pack32(res.dstsock)
            stun_add_fingerprint(od)
            self.responses[res.fileno] = get_list_from_od(od)
            self.write_to_sock(res.fileno)

    def handle_client_request_preauth(self,res,hbuf): # pair[0] == hbuf, pair[1] == fileno
        if not check_packet_crc32(hbuf):
            self.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d,buf %s' % (res.fileno,hexlify(hbuf)),str(sys._getframe().f_lineno)]))
            self.delete_fileno(res.fileno)
            return 

        if not (res.method == STUN_METHOD_ALLOCATE or\
                res.method == STUN_METHOD_APPLOGIN or\
                res.method == STUN_METHOD_CHECK_USER or\
                res.method == STUN_METHOD_REGISTER):
                    # 非法请求
            #print 'fileno',fileno
            #print 'self.appsock',self.appsock
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            self.errqueue.put(','.join([LOG_ERROR_IILAGE_CLIENT,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            self.delete_fileno(res.fileno)
            return
    
        hexpos = STUN_HEADER_LENGTH
        res.attrs = parser_stun_package(hbuf[hexpos:-4])
        if res.attrs is None:
            #print "preauth hbuf is wrong",hbuf,self.hosts[res.fileno]
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.errqueue.put(','.join([LOG_ERROR_ATTR,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return
    
        #res.reqlst = trip[1]
        if res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) and (len(res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY])) != 32:
            res.eattr = STUN_ERROR_AUTH
            self.errqueue.put(','.join([LOG_ERROR_AUTH,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return
        try:
            self.responses[res.fileno] = self.prefunc[res.method](res)
        except KeyError:
            res.eattr = STUN_ERROR_UNKNOWN_METHOD
            self.errqueue.put(','.join([LOG_ERROR_METHOD,res.method,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        else:
            self.write_to_sock(res.fileno)

    def handle_app_login_request(self,res):
        ftpwd = None
        user = res.attrs.get(STUN_ATTRIBUTE_USERNAME,None)
        pwd = res.attrs.get(STUN_ATTRIBUTE_MESSAGE_INTEGRITY,None)
        if not user or not pwd:
            res.eattr = STUN_ERROR_AUTH
            return  stun_error_response(res)

        obj = hashlib.sha256()
        obj.update(user)
        obj.update(pwd)
        ftpwd = self.db.user_login(user,obj.digest(),'%s:%d' % (res.host[0],res.host[1]))
        if not ftpwd:
            """用户信息不正确所以不能取得ftpwd"""
            res.eattr = STUN_ERROR_AUTH
            """对与同一IP同一用户登录多次失败的记录"""
            uq = "%s:%s" % (res.host[0],user)
            flist = self.logfailed.get(uq,None)
            if not flist:
                self.logfailed[uq] = 1
            else:
                self.logfailed[uq] +=1

            

            return  stun_error_response(res)

    
        self.appsock[res.fileno] = tcs = ComState()
        tcs.name = user
        """disable select db """
        """改用pgsql语言简化处理"""
        self.users[res.fileno] = user
        return app_user_auth_success(res,ftpwd)

    def handle_allocate_request(self,res):
        """
        小机登录服务器的命令，必须要有uuid,data
        """
        uuid = res.attrs.get(STUN_ATTRIBUTE_UUID,None)
        if not uuid:
            res.eattr=STUN_ERROR_UNKNOWN_PACKET
            self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
        chk = check_jluuid(uuid)
        if chk:
            res.eattr = chk
            self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            del chk
            return stun_error_response(res)

        huid =hexlify(uuid)
        apps = self.device_login_notify_app(uuid,res.fileno)+','
        
        res.vendor = hexlify(uuid[16:20])
        res.tuid = uuid[:16]
        """检查是不是新的厂商名"""
        if res.vendor not in self.vendors:
            self.db.insert_vendor_table(res.vendor)
            self.vendors.add(res.vendor)

        data = ''
        try:
            data = res.attrs[STUN_ATTRIBUTE_DATA]
        except KeyError:
            pass
        self.db.insert_devtable(vname=res.vendor,devid=hexlify(res.tuid),chost="%s:%d" % (res.host[0],res.host[1]),data=str(data))

        self.devsock[res.fileno] = tcs = ComState()
        self.devuuid[uuid] = res.fileno
        tcs.uuid = uuid
        del huid
        return device_login_sucess(res,apps)

    def handle_chkuser_request(self,res):
        """disable select db """
        
        user = res.attrs.get(STUN_ATTRIBUTE_USERNAME,None)
        if not user:
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            return stun_error_response(res)
    
        if self.db.check_user_exist(user):
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)
        else:
            return check_user_sucess(res)

    def handle_register_request(self,res):
        """disable select db """
        #if self.app_user_register(res.attrs[STUN_ATTRIBUTE_USERNAME],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]):
        user = res.attrs.get(STUN_ATTRIBUTE_USERNAME,None)
        pwd = res.attrs.get(STUN_ATTRIBUTE_MESSAGE_INTEGRITY,None)
        if not user or not pwd:
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            return stun_error_response(res)

        if self.db.check_user_exist(user):
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)

        obj = hashlib.sha256()
        obj.update(user)
        obj.update(pwd)
        ftpwd = pwd_generator()
        self.db.insert_account_table(user,obj.digest(),ftpwd,"%s:%d" % (res.host[0],res.host[1]))
        #self.statqueue[current_process().name].put('register success %s' % res.attrs[STUN_ATTRIBUTE_USERNAME])
        return register_success(user,ftpwd)

    def handle_app_bind_device(self,res):
        """
        绑定小机的命的命令包
        """   
        uuid = None
        try:
            uuid = res.attrs[STUN_ATTRIBUTE_UUID]
        except KeyError:
            return stun_error_response(res)
        chk = check_jluuid(uuid)
        if chk:
            res.eattr = chk
            del chk
            self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
        #uuid = hexlify(uuid)
        self.bind_each_uuid((uuid,res.fileno))
        try:
            #self.handle_add_bind_to_user(res)
            user = self.users[res.fileno]
            pwd =hexlify(res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY])
            self.db.insert_bind_table(user,hexlify(uuid),pwd)
            del uuid
        except KeyError:
            res.eattr = STUN_ERROR_UNKNOWN_PACKET 
            self.errqueue.put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
        if res.eattr != STUN_ERROR_NONE:
            self.errqueue.put("socket %d,bind error" % res.fileno)
            return stun_error_response(res)
        return self.stun_bind_devices_ok(res)
    


    def notify_peer_is_logout(self,pair): # pair[0] == fileno, pair[1] == dstsock
        fileno = pair[0]
        dstsock = pair[1]
        self.responses[fileno] =  notify_peer(struct.pack('!II',dstsock,STUN_OFFLINE))
        #self.statqueue[current_process().name].put('socket %d logout send info to socket %d' % (dstsock,fileno))
        try:
            self.write_to_sock(fileno)
        except IOError:
            self.errqueue.put(''.join([LOG_ERROR_SOCK,\
                    'socket error %d' % fileno,str(sys._getframe().f_lineno)]))
        del fileno
        del dstsock
    
    
    
    def dealwith_peer_hup(self,fileno):
        self.delete_fileno(fileno)
        """disable select db"""
        self.dealwith_sock_close_update_db(fileno)
        self.dealwith_sock_close_update_binds(fileno)
        self.remove_fileno_resources(fileno)
    
    def notify_app_uuid_logout(self,fileno):
        """
        小机下线，通知APP
        """
        try:
            uuid = self.devsock[fileno].uuid
            self.devsock.pop(fileno,None)
        except KeyError:
            pass
        else:
            binds = [k for k in self.appbinds.keys() if self.appbinds[k].has_key(uuid)]
            [self.notify_peer_is_logout((n,fileno)) for n in binds if self.appsock.has_key(n)]

            alist = [n for n in binds if self.appsock.has_key(n)]
            for n in alist:
                self.appbinds[n][uuid]=0xFFFFFFFF
            del uuid
            del alist[:]
            del alist
    
    def app_user_logout(self,uname):
        atable = QueryDB.get_account_status_table()
        ss = atable.update().values(is_login=False).where(atable.c.uname == uname)
        try:
            #QueryDB.select(ss)
            self.db.nexecute(ss)
        except :
            self.errqueue.put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))

    def dealwith_sock_close_update_db(self,fileno):
        # socket 关闭，更新数据库
        try:
            name = self.appsock[fileno].name
            self.appsock.pop(fileno)
            #self.statqueue[current_process().name].put('app %s logout info dev,self fileno %d' % (name,fileno))
            """disable select db """
            #self.app_user_logout(name)
        except KeyError:
            pass
        else:
            self.db.user_logout(name)
            del name
            return
        """disable select db """

        try:
            uuid = self.devsock[fileno].uuid
        except KeyError:
            pass
        else:
            vendor = hexlify(uuid[16:20])
            self.db.devtable_logout(vendor,hexlify(uuid[:16]))
            #dt = dtclass(devid=uuid[:32],is_online=False)
    
    
    def dealwith_sock_close_update_binds(self,fileno):
        try:
            binds = self.appbinds[fileno].values()
            self.appbinds.pop(fileno,None)
        except KeyError:
            pass
            #nl = [notify_peer_is_logout(n,fileno) for n in binds if self.devsock.has_key(n)]
            #multiprocessing_handle(notify_peer_is_logout,nl)
        else:
            [self.notify_peer_is_logout((n,fileno)) for n in binds if self.devsock.has_key(n)]
            return

        """
        通知APP小机下线
        """
        self.notify_app_uuid_logout(fileno)
    
    def sock_send_fail(self,fileno):
        # 要检查一下是不是转发失败了，要通知发送方
        self.dealwith_peer_hup(fileno)
    
    def sock_recv_fail(self,fileno):
        # sock 关闭时产生的异常处理
        self.dealwith_peer_hup(fileno)
    
    def remove_fileno_resources(self,fileno):
        m = [(getattr(self,n),fileno) for n in store]
        #print "map is",m
        group = Group()
        group.map(clean_dict,m)
        del m[:]
        del m
            


    def bind_each_uuid(self,pair): # pair[0] == ustr,pair[1] == fileno
        ustr = pair[0]
        fileno = pair[1]
        if not self.appbinds.get(fileno,None):
            with self.glock:
                self.appbinds[fileno] = {}
            """
            通知在线的小机，有APP要绑定它
            """
        dstsock = self.devuuid.get(ustr,None)
        #print "uuid keys",self.devuuid.keys()
        if dstsock:
            #print "info dev uuid",ustr,dstsock
            with self.glock:
                self.appbinds[fileno][ustr]= dstsock
            self.responses[dstsock] = notify_peer(struct.pack('!II',fileno,STUN_ONLINE))
            try:
                self.write_to_sock(dstsock)
            except IOError:
                self.errqueue.put(','.join(['dstsock %d has closed' % dstsock,'host is ',str(self.hosts[dstsock])]))  
                self.dealwith_peer_hup(dstsock)
        else:
            with self.glock:
                self.appbinds[fileno][ustr]=0xFFFFFFFF
        #print "self.appbinds",self.appbinds.keys()
        #print "binded keys",self.appbinds.keys()
        del ustr
        del fileno
    
    def stun_bind_devices_ok(self,res):
        """
        绑定成功，回复APP
        """
        buf = []
        #stun_init_command_str(stun_make_success_response(res.method),buf)
        od = stun_init_command_head(stun_make_success_response(res.method))
        #print "res.attrs",hexlify(res.attrs.get(STUN_ATTRIBUTE_UUID,None))
        if res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
            joint = [''.join([k,'%08x' % self.appbinds[res.fileno][k]]) for k in self.appbinds[res.fileno].keys()]
            stun_attr_append_str(od,STUN_ATTRIBUTE_MRUUID,''.join(joint))
        else:
            jluid = res.attrs.get(STUN_ATTRIBUTE_UUID,None)
            if not jluid:
                res.eattr = STUN_ERROR_UNKNOWN_ATTR
                return  stun_error_response(res)
            try:
                sock = pack32(self.appbinds[res.fileno][hexlify(jluid)])
            except KeyError:
                sock = pack32(0xFFFFFFFF)
                stun_attr_append_str(od,STUN_ATTRIBUTE_RUUID,'%s%s' % (jluid,sock))
            else:
                stun_attr_append_str(od,STUN_ATTRIBUTE_RUUID,'%s%s' % (jluid,sock))
        stun_add_fingerprint(od)
        buf = get_list_from_od(od)
        return buf

    def noify_app_uuid_just_login(self,appsock,uuidstr,devsock):
        self.responses[appsock] = notify_app_bind_islogin('%s%s' % (uuidstr,pack32(devsock)))
        #self.statqueue[current_process().name].put("info app  %d , %s , data : %s" % (appsock,str(self.hosts[appsock]),list(self.responses[appsock])))
        self.write_to_sock(appsock)
    
    def device_login_notify_app(self,uuidstr,devsock):
        """
        绑定过的小机现在登录了，通知它的用户群,再收集用户群返回给小机
        """
        apps = []
        #print "appbinds",self.appbinds.keys()
        
        for fk in self.appbinds.keys():
            try:
                if self.appbinds[fk].has_key(uuidstr):
                    apps.append("%s:%d" % (self.users[fk],fk))
                    self.noify_app_uuid_just_login(fk,uuidstr,devsock)
                    break
            except KeyError:
                pass
            
        return ','.join(apps)  # 邦定过这个小机的用户群。

    
def logger_worker(queue,logger):
    while 1:
        try:
            msg = queue.get_nowait()
            logger.log(msg)
            del msg
        except:
            pass
        gevent.sleep(0)

    
def make_argument_parser():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('-p',action='store',dest='srv_port',type=int,help='Set Services Port')
    parser.add_argument('-B',action='store',dest='bind_eth',type=str,help='Set Bind Server on interface')
    parser.add_argument('-I',action='store',dest='cluster_interface',type=str,help='cluster communicate interface')
    parser.add_argument('--version',action='version',version=__version__)
    return parser

#port = options.srv_port if options.srv_port else 3478




store = ['clients','hosts','responses','appbinds','appsock','devsock',
         'devuuid','users','requests','logfaild']
if __name__ == '__main__':
    __version__ = '0.1.2'
    options = make_argument_parser().parse_args()
    port = options.srv_port if options.srv_port else 3478
    cluster_eth = options.cluster_interface if options.cluster_interface else None
    QueryDB.check_boot_tables() # 检查数据库
    EpollServer(port,cluster_eth)
    #srv.run()
