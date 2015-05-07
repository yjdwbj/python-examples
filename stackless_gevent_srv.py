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
import threading
import gevent
from gevent.server import StreamServer,_tcp_listener
from gevent import server,event,socket,monkey
from gevent.pool import Group
from gevent.queue import Queue
monkey.patch_all(thread=False)

from multiprocessing import Process,current_process



from sqlalchemy import *
from sqlalchemy.exc import *
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql,and_
from sqlalchemy.dialects import postgresql as pgsql




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

def register_success(uname):
    buf = []
    #stun_init_command_str(stun_make_success_response(STUN_METHOD_REGISTER),buf)
    od = stun_init_command_head(stun_make_success_response(STUN_METHOD_REGISTER))
    stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,uname)
    stun_add_fingerprint(od)
    return get_list_from_od(od)


def check_user_sucess(res):
    #stun_init_command_str(stun_make_success_response(res.method),buf,)
    od = stun_init_command_head(stun_make_success_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,hexlify(res.attrs[STUN_ATTRIBUTE_USERNAME]))
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def app_user_auth_success(res):
    #stun_init_command_str(stun_make_success_response(res.method),buf)
    od= stun_init_command_head(stun_make_success_response(res.method))
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(od,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_attr_append_str(od,STUN_ATTRIBUTE_USERNAME,res.attrs[STUN_ATTRIBUTE_USERNAME])
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def device_login_sucess(res): # 客服端向服务器绑定自己的IP
    buf = []
    #stun_init_command_str(stun_make_success_response(res.method),buf)
    od = stun_init_command_head(stun_make_success_response(res.method))
    #stun_attr_append_str(buf,STUN_ATTRIBUTE_LIFETIME,'%08x' % UCLIENT_SESSION_LIFETIME)
    stun_attr_append_str(od,STUN_ATTRIBUTE_STATE,''.join(['%08x' % res.fileno,STUN_ONLINE]))
    stun_add_fingerprint(od)
    lst = get_list_from_od(od)
    return lst

def app_user_pull_table(res,data):
    buf = []
    #stun_init_command_str(stun_make_success_response(res.method),buf)
    od = stun_init_command_head(stun_make_success_response(res.method))
    stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,data)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def refresh_sucess(ntime): # 刷新成功
    buf = []
    #stun_init_command_str(stun_make_success_response(STUN_METHOD_REFRESH),buf)
    od = stun_init_command_head(stun_make_success_response(STUN_METHOD_REFRESH))
    stun_attr_append_str(od,STUN_ATTRIBUTE_LIFETIME,ntime)
    stun_add_fingerprint(od)
    return get_list_from_od(od)

def stun_return_same_package(res):
    buf =[]
    #stun_init_command_str(stun_make_success_response(res.method),buf)
    od = stun_init_command_head(stun_make_success_response(res.method))
    t = sum([(od['lst'].extend(v),len(v[-1])+8)[1] for v in res.reqlst])
    od['length']="%04x" % (t/2 +20)
    stun_add_fingerprint(od)
    return get_list_from_od(od)





class EpollServer():
    def __init__(self,port):
        #statqueue = statqueue
        """创建多个engine让它平均到多个进程上，性能问题要进一步调试"""
        self.maxbuffer = ''
        [setattr(self,x,{}) for x in store]

        self.prefunc= {
              STUN_METHOD_ALLOCATE:self.handle_allocate_request, # 小机登录方法
              STUN_METHOD_CHECK_USER:self.handle_chkuser_request,
              STUN_METHOD_REGISTER:self.handle_register_request,
              STUN_METHOD_BINDING:self.handle_app_login_request  # app端登录方法
              }

        #认证后的处理
        self.postfunc={
                STUN_METHOD_CHANNEL_BIND:self.handle_app_bind_device,  # APP 绑定小机的命令
                #STUN_METHOD_REFRESH:self.handle_refresh_request,
                STUN_METHOD_MODIFY:self.handle_modify_bind_item, #修改绑定的信息
                STUN_METHOD_DELETE:self.handle_delete_bind_item, #删除现有的绑定
                STUN_METHOD_PULL:self.handle_app_pull
                }
        #self.server = StreamServer(('0.0.0.0',3478),self.handle_new_accept,backlog = 8192)
        #self.server.serve_forever()
        self.listener = _tcp_listener(('0.0.0.0',3478),32768,1)
        #self.server = StreamServer(('0.0.0.0',3478),self.handle_new_accept,backlog=100000)
        #self.server.start()
        #for i in xrange(1):
        #    Process(target=self.server_forever).start()
        self.fwdcounter = {}
        self.errqueue = {}
        self.statqueue = {}
        self.fwdqueue = {}
        self.statlog = {}
        self.errlog = {}
        self.fwdlog = {}
        self.startime = time.time()
        for i in xrange(7):
            Process(target=self.start_srv).start()
        #self.server.serve_forever()

    def report_status(self):
        ltime = time.time()
        lcounter = self.fwdcounter[current_process().name]
        while 1:
            rate = 0
            try:
                rate = float(self.fwdcounter[current_process().name]-lcounter)/ (time.time() - ltime)
            except ZeroDivisionError:
                pass
            self.fwdqueue[current_process().name].put("time %.5f,fwd counter %d, app online %d, dev online %d, fwd rate avg 30 seconds %.5f,max buffer size %s" \
                    % (time.time(),self.fwdcounter[current_process().name],len(self.appsock),len(self.devsock),rate,self.maxbuffer))
            ltime = time.time()
            gevent.sleep(30)

    def start_srv(self):
        self.fwdcounter[current_process().name] = 0
        self.fwdqueue[current_process().name] = Queue()
        self.statqueue[current_process().name] = Queue()
        self.errqueue[current_process().name] = Queue()

        self.statlog[current_process().name] = StatLog('state_%s' % current_process().name)
        self.errlog[current_process().name]= StatLog('err_%s' % current_process().name)
        self.fwdlog[current_process().name] = StatLog('fwd_%s' % current_process().name)

        errworker = threading.Thread(target=logger_worker,args=(self.errqueue[current_process().name],self.errlog[current_process().name]))
        errworker.start()
        statworker = threading.Thread(target=logger_worker,args=(self.statqueue[current_process().name],self.statlog[current_process().name]))
        statworker.start()
        fwdworker= threading.Thread(target=logger_worker,args=(self.fwdqueue[current_process().name],self.fwdlog[current_process().name]))
        fwdworker.start()
        #recvworker= threading.Thread(target=logger_worker,args=(recvqueue,recvlog))
        #recvworker.start()
        threading.Thread(target=self.report_status).start()
        server.StreamServer(self.listener,self.handle_new_accept).serve_forever()


#    def run(self):
#        while True:
#            try:
#                nsock,addr = self.srvsocket.accept()
#                nf = nsock.fileno()
#                self.clients[nf] = nsock
#                self.hosts[nf] = addr
#                self.requests[nf] =''
#                self.gpool.spawn_n(self.handle_new_accept,nsock)
#            except (SystemExit,KeyboardInterrupt):
#                print "Server exit"
#                break

    def handle_new_accept(self,nsock,addr):
        fileno = nsock.fileno()
        self.clients[fileno] = nsock
        self.hosts[fileno] = addr
        self.requests[fileno] =''
        hstr = str(addr)
        #recvqueue.put('new accept %s, sock %d' % (str(addr),fileno))
        n = 5
        while 1:
            try:
                recvbuf = nsock.recv(SOCK_BUFSIZE)
            except IOError:
                self.errqueue[current_process().name].put('sock %d, IOError ,%s' % (fileno,hstr))
                break
            except socket.error:
                self.errqueue[current_process().name].put("%s socket.error,sock %d" % (hstr,fileno))
                break
            else:
                if not recvbuf:
                    if n:
                        n -= 1
                        gevent.sleep(0.02)
                        continue
                    else:
                        self.errqueue[current_process().name].put("%s no data,sock %d" % (hstr,fileno))
                        break
                n = 5 # 重试读取5次
                hdata = hexlify(recvbuf)
                del recvbuf
                try:
                    self.requests[fileno] += hdata
                except KeyError:
                    self.errqueue[current_process().name].put("%s requests KeyError,sock %d" % (hstr,fileno))
                    break
                self.process_handle_first(fileno)
            gevent.sleep(0) #让出CPU
        self.dealwith_peer_hup(fileno)
        """退出本线程"""
    

    def handle_modify_bind_item(self,res):
        btable = QueryDB.get_account_bind_table(self.users[res.fileno])
        stmt = btable.update().values(pwd=res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]).\
                where(btable.c.uuid == res.attrs[STUN_ATTRIBUTE_UUID])
        try:
            QueryDB.select(stmt)
        except ProgrammingError:
            #print "table not exits"
            res.eattr = STUN_ERROR_OBJ_NOT_EXIST
            return  stun_error_response(res)
        except KeyError:
            res.eattr =STUN_ERROR_UNKNOWN_ATTR
            return stun_error_response(res)
        else:
            return stun_return_same_package(res)


    def handle_delete_bind_item(self,res):
        uname = self.users[res.fileno]
        uids = res.attrs[STUN_ATTRIBUTE_UUID]
        try:
            n = [ n for n in self.appbinds.values if n.has_key(uids)]
            popfunc = lambda d,v: d.pop(v)
            k = mcore_handle(popfunc,(n))
        except TypeError:
            self.errqueue[current_process().name].put("TypeError %d,n is none" % res.fileno)
        self.delete_binds_in_db(uname,uids)
        del uname
        del uids
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
        btable = QueryDB.get_account_bind_table(uname)
        s = sql.select([btable])
        try:
            fall = QueryDB.select(s).fetchall()
        except ProgrammingError:
            #print "table not exits"
            res.eattr = STUN_ERROR_OBJ_NOT_EXIST
            return  stun_error_response(res)
        except KeyError:
            res.eattr =STUN_ERROR_UNKNOWN_PACKET
            return  stun_error_response(res)
        else:
            data = ''.join([ ''.join([r[0],r[1]]) for r in fall])
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
            self.errqueue[current_process().name].put('sock %d, due to write_to_sock failed' % (fileno,))
            return
        else:
            try:
                sock.send(unhexlify(''.join(self.responses[fileno])))
                self.responses[fileno] = None
            except socket.error:
                self.dealwith_peer_hup(fileno)


    def handle_refresh_request(self,res):
        pass
        #return refresh_sucess(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1])

    def process_handle_first(self,fileno):
        l = self.requests[fileno].count(HEAD_MAGIC) #没有找到JL关键字
        if not l:
            self.errqueue[current_process().name].put('sock %d, recv no HEAD_MAGIC packet %s' % (fileno,self.requests[fileno]))
            return
        plen = len(self.requests[fileno])
        if l > 1:
            #self.errqueue[current_process().name].put('sock %d,recv unkown msg %s' % (fileno,self.requests[:l])
            #self.statqueue[current_process().name].put("sock %d,recv multi buf,len %d, buf: %s" % (fileno,plen,self.requests[fileno]))
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
            nlen = int(self.requests[fileno][8:12],16) *2 #包头指法的长度
            if len(self.requests[fileno]) < nlen:
                return
            onepack = self.requests[fileno][:nlen]
            self.requests[fileno] = self.requests[fileno][nlen:]
            self.handle_requests_buf(onepack,fileno)
            del onepack
            
                    
    def handle_requests_buf(self,hbuf,fileno): # pair[0] == hbuf, pair[1] == fileno
        if len(hbuf) % 2:
            return 
        res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not res:
            self.errqueue[current_process().name].put('get jl head error',hbuf)
            return
        res.eattr = STUN_ERROR_NONE
        try:
            res.host= self.hosts[fileno]
        except KeyError:
            self.errqueue[current_process().name].put('sock %d, not has hostinfo' % (fileno))
            for n in STUN_HEAD_KEY:
                res.__dict__.pop(n,None)
            return 

        print hbuf
        print res
        print res.__dict__
        res.fileno=fileno
        #通过认证的socket 直接转发了
        try:
            aforward = self.appsock[fileno]
        except KeyError: 
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
            res.__dict__.pop('reqlst',None)
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
            res.__dict__.pop('reqlst',None)
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
        res.__dict__.pop('reqlst',None)
        res.__dict__.pop('attrs',None)
        for n in STUN_HEAD_KEY:
            res.__dict__.pop(n,None)
        del res
        #gc.set_threshold(0,1,1)
        #gc.collect()

    def handle_postauth_process(self,res,hbuf):
        """
        执行认证后的函数
        """
        hexpos = STUN_HEADER_LENGTH
        trip =  parser_stun_package(hbuf[hexpos:-8])
        if trip is None:
            print "postfunc parser_stun_package is None buf: ",hbuf,res.__dict__,res.host
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_ATTR,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            self.responses[res.fileno] = stun_error_response(res)
            self.write_to_sock(res.fileno)
        else:
            res.attrs = trip[0]
            res.reqlst = trip[1]
            try:
               self.responses[res.fileno]=  self.postfunc[res.method](res)
               self.write_to_sock(res.fileno)
            except KeyError:
                self.handle_client_request_preauth(res,hbuf)
    
                
    def handle_forward_packet(self,hbuf,res,dst):
        try:
            s = dst[res.dstsock]
            # 转发到时目地
            self.responses[res.dstsock] = hbuf
            fileno = res.fileno
            dstsock = res.dstsock
            #fwdqueue.put(';src:[%s,sock %d]; dst:[%s,sock %d] ; buf:%s' % (str(res.host),fileno,str(self.hosts[dstsock]),dstsock,hbuf))
            self.fwdcounter[current_process().name] +=1
            self.write_to_sock(res.dstsock)
        except KeyError: # 目标不存在
            res.eattr = STUN_ERROR_DEVOFFLINE
            #self.epoll.modify(fileno,select.EPOLLOUT)
            #self.responses[fileno] = ''.join(stun_error_response(res))
            #tbuf = stun_error_response(res)
            tbuf =  notify_peer(''.join(['%08x' % res.dstsock,STUN_OFFLINE]))
            tbuf[3]='%08x' % res.srcsock
            tbuf[4]='%08x' % res.dstsock
            tbuf.pop()
            tbuf[2] = '%04x' % (int(tbuf[2],16)-4)
            stun_add_fingerprint(tbuf)
            self.responses[res.fileno] = tbuf
            self.write_to_sock(res.fileno)

    def handle_client_request_preauth(self,res,hbuf): # pair[0] == hbuf, pair[1] == fileno
        if check_packet_crc32(hbuf):
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_PACKET,'sock %d,buf %s' % (res.fileno,hbuf),str(sys._getframe().f_lineno)]))
            self.delete_fileno(res.fileno)
            return 

        if not (res.method == STUN_METHOD_ALLOCATE or\
                res.method == STUN_METHOD_BINDING or\
                res.method == STUN_METHOD_CHECK_USER or\
                res.method == STUN_METHOD_REGISTER):
                    # 非法请求
            #print 'fileno',fileno
            #print 'self.appsock',self.appsock
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_IILAGE_CLIENT,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            self.delete_fileno(res.fileno)
            return
    
        hexpos = STUN_HEADER_LENGTH
        trip = parser_stun_package(hbuf[hexpos:-8])
        if trip is None:
            #print "preauth hbuf is wrong",hbuf,self.hosts[res.fileno]
            print "preauth parser_stun_package is None buf: ",hbuf,res.__dict__
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_ATTR,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return
    
        res.attrs = trip[0]
        res.reqlst = trip[1]
        del trip
        if res.attrs.has_key(STUN_ATTRIBUTE_MESSAGE_INTEGRITY) and (len(res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY])/2) != 32:
            res.eattr = STUN_ERROR_AUTH
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_AUTH,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return
        try:
            self.responses[res.fileno] = self.prefunc[res.method](res)
        except KeyError:
            res.eattr = STUN_ERROR_UNKNOWN_METHOD
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_METHOD,res.method,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
        else:
            self.write_to_sock(res.fileno)

    def handle_app_login_request(self,res):
        user = b''
        pwd = b''
        try:
            pwd = res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]
            user = unhexlify(res.attrs[STUN_ATTRIBUTE_USERNAME])
            """disable select db """
            """
            result = self.app_user_login(user,pwd)
            if not result:
                res.eattr = STUN_ERROR_AUTH
                return  stun_error_response(res)
                """
        except KeyError:
           res.eattr = STUN_ERROR_AUTH
           return  stun_error_response(res)# APP端必须带用认证信息才能发起连接.
    
        self.appsock[res.fileno] = tcs = ComState()
        #tcs.name = result[0][0]
        tcs.name = user
        """disable select db """
        #self.app_user_update_status(res.attrs[STUN_ATTRIBUTE_USERNAME],res.host)
        #self.statqueue[current_process().name].put('user %s login,socket is %d,host %s:%d' % (tcs.name,res.fileno,res.host[0],res.host[1]))
        self.users[res.fileno] = user
        return app_user_auth_success(res)

    def handle_allocate_request(self,res):
        """
        小机登录服务器的命令，必须要有uuid,data
        """
        try:
            chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID])
            if chk:
                res.eattr = chk
                self.errqueue[current_process().name].put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
                del chk
                return stun_error_response(res)
        except KeyError:
            #res.eattr= hexlify("Not Found UUID")
            res.eattr=STUN_ERROR_UNKNOWN_PACKET
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
    
        huid = res.attrs[STUN_ATTRIBUTE_UUID]
        self.device_login_notify_app(huid,res.fileno)
    #    if res.attrs.has_key(STUN_ATTRIBUTE_LIFETIME):
    #        update_refresh_time(res.fileno,int(res.attrs[STUN_ATTRIBUTE_LIFETIME][-1],16))
    #    else:
    #        update_refresh_time(res.fileno,UCLIENT_SESSION_LIFETIME)
    
        res.vendor = huid[32:40]
        res.tuid = huid[:32]
        """disable select db """
        #self.update_newdevice(res)
        #self.actives[res.fileno] = huid
        self.devsock[res.fileno] = tcs = ComState()
        self.devuuid[huid] = res.fileno
        tcs.uuid = huid
        #print "login devid is",tcs.uuid
        #self.statqueue[current_process().name].put('device login uuid is %s,socket is %d, host %s:%d' % (huid,res.fileno,res.host[0],res.host[1]))
        del huid
        return device_login_sucess(res)

    def handle_chkuser_request(self,res):
        """disable select db """
        return check_user_sucess(res)
        f = check_user_in_database(res.attrs[STUN_ATTRIBUTE_USERNAME])
        if f != 0:
            #self.errqueue[current_process().name].put("User Exist %s" % res.attrs[STUN_ATTRIBUTE_USERNAME])
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)
        else:
            return check_user_sucess(res)

    def handle_register_request(self,res):
        """disable select db """
        return register_success(res.attrs[STUN_ATTRIBUTE_USERNAME])
        if self.app_user_register(res.attrs[STUN_ATTRIBUTE_USERNAME],res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]):
            # 用户名已经存了。
            #self.errqueue[current_process().name].put("User has Exist! %s" % res.attrs[STUN_ATTRIBUTE_USERNAME])
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)
    
        self.statqueue[current_process().name].put('register success %s' % res.attrs[STUN_ATTRIBUTE_USERNAME])
        return register_success(res.attrs[STUN_ATTRIBUTE_USERNAME])

    def handle_add_bind_to_user(self,res):
        """
        绑定小机到用户表里
        """
        table  = QueryDB.get_account_bind_table(self.users[res.fileno])
        conn = QueryDB().get_dbconn()
        try:
            table.create(QueryDB().get_engine())
        except ProgrammingError:
            pass
        #添加新绑定的小机用户表下面
        try:
            ins = table.insert().values(uuid=res.attrs[STUN_ATTRIBUTE_UUID],\
                    pwd=res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY],reg_time=datetime.now())
        except KeyError:
            self.errqueue[current_process().name].put(','.join(['sock %d' % res.fileno,'no uuid attr to bind']))
            res.eattr = STUN_ERROR_UNKNOWN_PACKET
            return 
        except TypeError:
            p = res.attrs[STUN_ATTRIBUTE_MESSAGE_INTEGRITY]
            return

        try:
            conn.execute(ins)
        except IntegrityError:
            stmt = table.update().values(reg_time = datetime.now()).where(table.c.uuid == res.attrs[STUN_ATTRIBUTE_UUID])
            conn.execute(stmt)
        except ProgrammingError:
            stmt = table.update().values(reg_time = datetime.now()).where(table.c.uuid == res.attrs[STUN_ATTRIBUTE_UUID])
            conn.execute(stmt)
        conn.close()

    def handle_app_bind_device(self,res):
        """
        绑定小机的命的命令包
        """
        try:
            chk = check_jluuid(res.attrs[STUN_ATTRIBUTE_UUID])
            if chk:
                res.eattr = chk
                del chk
                self.errqueue[current_process().name].put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(str(sys._getframe().f_lineno))]))
                return stun_error_response(res)
            self.bind_each_uuid((res.attrs[STUN_ATTRIBUTE_UUID],res.fileno))
            """disable select db """
            #self.handle_add_bind_to_user(res)
#        elif res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
#            mlist =  split_muuid(res.attrs[STUN_ATTRIBUTE_MUUID])
#            p = mcore_handle(check_jluuid,mlist)
#            #p = [check_jluuid(n) for n in mlist]
#            e = [ x for x in p if x]
#            if len(e):
#                res.eattr = STUN_ERROR_UNKNOWN_PACKET
#                self.errqueue[current_process().name].put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
#                return stun_error_response(res)
#            #multiprocessing_handle(bind_each_uuid,[(res.fileno,n) for n in mlist])
#            [self.bind_each_uuid((n,res.fileno)) for n in mlist]
        except KeyError:
            res.eattr = STUN_ERROR_UNKNOWN_PACKET 
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_UUID,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return stun_error_response(res)
        if res.eattr != STUN_ERROR_NONE:
            self.errqueue[current_process().name].put("socket %d,bind error" % res.fileno)
            return stun_error_response(res)
        return self.stun_bind_devices_ok(res)
    


    def notify_peer_is_logout(self,pair): # pair[0] == fileno, pair[1] == dstsock
        fileno = pair[0]
        dstsock = pair[1]
        self.responses[fileno] =  notify_peer(''.join(['%08x' % dstsock,STUN_OFFLINE]))
        #self.statqueue[current_process().name].put('socket %d logout send info to socket %d' % (dstsock,fileno))
        try:
            self.write_to_sock(fileno)
        except IOError:
            self.errqueue[current_process().name].put(''.join([LOG_ERROR_SOCK,\
                    'socket error %d' % fileno,str(sys._getframe().f_lineno)]))
        del fileno
        del dstsock
    
    def clean_timeout_sock(self,fileno): # 清除超时的连接
        if self.timer.has_key(fileno):
            if self.timer[fileno] < time.time():
                #self.statqueue[current_process().name].put("Client %d life time is end,close it" % fileno )
                self.dealwith_peer_hup(fileno)
    
    def mirco_devices_logout(self,devid):
        vendor = devid[32:40]
        #print "update status for tuid",hexlify(suid[0])
        mtable = QueryDB.get_devices_table(vendor)
        #ss = mtable.update().values(is_online=False).where(mtable.c.devid == hexlify(suid[0]))
        ss = mtable.update().values(is_online=False).where(mtable.c.devid == devid[:32])
        vendor = None
        try:
            QueryDB.select(ss)
        except IOError:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,devid,str(sys._getframe().f_lineno)]))
            return 0

    
    
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
            #self.statqueue[current_process().name].put('dev %s logout info app,self fileno %d' % (uuid,fileno))
        #print "devid",devid,"has logout"
            binds = [k for k in self.appbinds.keys() if self.appbinds[k].has_key(uuid)]
            [self.notify_peer_is_logout((n,fileno)) for n in binds if self.appsock.has_key(n)]

        #multiprocessing_handle(notify_peer_is_logout,[(n,fileno) for n in binds if self.appsock.has_key(n)])
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
            QueryDB.select(ss)
        except :
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))

    def dealwith_sock_close_update_db(self,fileno):
        # socket 关闭，更新数据库
        try:
            name = self.appsock[fileno].name
            del self.appsock[fileno]
            #self.statqueue[current_process().name].put('app %s logout info dev,self fileno %d' % (name,fileno))
            """disable select db """
            #self.app_user_logout(name)
            del name
        except KeyError:
            pass
        else:
            return
        """disable select db """
        return

        try:
            self.mirco_devices_logout(self.devsock[fileno].uuid)
        except KeyError:
            pass
    
    
    def dealwith_sock_close_update_binds(self,fileno):
        try:
            binds = self.appbinds[fileno].values()
            self.appbinds.pop(fileno,None)
            [self.notify_peer_is_logout((n,fileno)) for n in binds if self.devsock.has_key(n)]
        except KeyError:
            pass
            #nl = [notify_peer_is_logout(n,fileno) for n in binds if self.devsock.has_key(n)]
            #multiprocessing_handle(notify_peer_is_logout,nl)
        else:
            return

        """
        通知APP小机下线
        """
        self.notify_app_uuid_logout(fileno)
    
    def sock_send_fail(self,fileno):
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
#            self.responses[srcsock] = ''.join(tbuf)
#            self.epoll.modify(srcsock,select.EPOLLOUT | select.EPOLLET)
#    
        # sock 关闭时产生的异常处理
        self.dealwith_peer_hup(fileno)
    
    def sock_recv_fail(self,fileno):
        # sock 关闭时产生的异常处理
        self.dealwith_peer_hup(fileno)
    
    def remove_fileno_resources(self,fileno):
        m = [(getattr(self,n),fileno) for n in store]
        group = Group()
        group.map(clean_dict,m)
        del m[:]
        del m
            


    def bind_each_uuid(self,pair): # pair[0] == ustr,pair[1] == fileno
        ustr = pair[0]
        fileno = pair[1]
        try:
            self.appbinds[fileno] is dict
        except KeyError:
            self.appbinds[fileno]={}
    
            """
            通知在线的小机，有APP要绑定它
            """
        try:
            dstsock = self.devuuid[ustr]
            self.appbinds[fileno][ustr]= dstsock
            b = '%08x' % fileno
            self.responses[dstsock] = notify_peer(''.join([b,STUN_ONLINE]))
            #self.statqueue[current_process().name].put("info dev %d , %s, data : %s" % (dstsock,str(self.hosts[dstsock]),list(self.responses[dstsock])))
            try:
                self.write_to_sock(dstsock)
            except IOError:
                self.errqueue[current_process().name].put(','.join(['dstsock %d has closed' % dstsock,'host is ',str(self.hosts[dstsock])]))  
                self.dealwith_peer_hup(dstsock)
        except KeyError:
            self.appbinds[fileno][ustr]=0xFFFFFFFF
        del ustr
        fileno = None
    
    
    
    def stun_bind_devices_ok(self,res):
        """
        绑定成功，回复APP
        """
        buf = []
        #stun_init_command_str(stun_make_success_response(res.method),buf)
        od = stun_init_command_head(stun_make_success_response(res.method))
        if res.attrs.has_key(STUN_ATTRIBUTE_MUUID):
            joint = [''.join([k,'%08x' % self.appbinds[res.fileno][k]]) for k in self.appbinds[res.fileno].keys()]
            stun_attr_append_str(od,STUN_ATTRIBUTE_MRUUID,''.join(joint))
        else:
            jluid = res.attrs[STUN_ATTRIBUTE_UUID]
            stun_attr_append_str(od,STUN_ATTRIBUTE_RUUID,\
                     ''.join([jluid,'%08x' %self.appbinds[res.fileno][jluid]]))
        stun_add_fingerprint(od)
        return (get_list_from_od(od))
        return (buf)

    def noify_app_uuid_just_login(self,appsock,uuidstr,devsock):
        self.responses[appsock] = notify_app_bind_islogin(''.join([uuidstr,'%08x' % devsock]))
        #self.statqueue[current_process().name].put("info app  %d , %s , data : %s" % (appsock,str(self.hosts[appsock]),list(self.responses[appsock])))
        self.write_to_sock(appsock)
    
    def device_login_notify_app(self,uuidstr,devsock):
        """
        绑定过的小机现在登录了，通知它的用户群
        """
        for fk in self.appbinds.keys():
            try:
                if self.appbinds[fk].has_key(uuidstr):
                    self.noify_app_uuid_just_login(fk,uuidstr,devsock)
                    break
            except KeyError:
                pass
    

    def app_user_register(self,user,pwd):
        account = QueryDB.get_account_table()
        uname = unhexlify(user)
        obj = hashlib.sha256()
        obj.update(uname)
        obj.update(pwd)
        ins = account.insert().values(uname=uname,pwd=obj.digest(),is_active=True,reg_time=datetime.now())
        try:
            QueryDB.select(ins)
        except IntegrityError:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_REGISTER,uname,str(sys._getframe().f_lineno)]))
            del uname
            return True
        except DataError:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_REGISTER,uname,str(sys._getframe().f_lineno)]))
            del uname
            return True
        else:
            del account
            del uname
            del obj
            del ins
            return False

    
    def app_user_update_status(self,user,host):
        """更新用户的状态,这里有优化表结构与流程的可能性"""
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
            QueryDB.select(sss)
        except DataError:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,host[0],str(sys._getframe().f_lineno)]))
        del uname
        del ipadr
        del ipprt
        del sss
    
    
    def app_user_login(self,uname,pwd):
        account = QueryDB.get_account_table()
        obj = hashlib.sha256()
        obj.update(uname)
        obj.update(pwd)
        s = sql.select([account]).where(and_(account.c.uname == uname,account.c.pwd == obj.digest(),
            account.c.is_active == True))
        try:
            result = QueryDB.select(s)
            return result.fetchall()
        except:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,uname,str(sys._getframe().f_lineno)]))
        del s
        del obj
    
    
    def check_user_in_database(self,uname):
        """
        检查用户是否注册过
        """
        account = QueryDB.get_account_table()
        s = sql.select([account.c.uname]).where(account.c.uname == uname)
        try:
            result = QueryDB.select(s)
        except:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,uname,self.clients[fileno],str(sys._getframe().f_lineno)]))
        else:
            return result.fetchall()
    
    def find_device_state(self,uid):
        vendor = uid[32:40]
        #print "find uuid is",uid,"vendor is",vendor
        mirco_devices = QueryDB.get_devices_table(vendor)
        s = sql.select([mirco_devices]).where(mirco_devices.c.devid == uid[:32] )
        try:
            #result = self.execute(s)
            result = QueryDB.select(s)
        except:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,uuid,str(sys._getframe().f_lineno)]))
            return None
        else:
            return result.fetchall()
    
    
    def update_newdevice(self,res):
        '''添加新的小机到数据库'''
        eng = QueryDB().get_engine()
        mirco_devices = QueryDB.get_devices_table(res.vendor)
        if not mirco_devices.exists(eng):
            mirco_devices.create(eng)
        ipadr = int(hexlify(socket.inet_aton(res.host[0])),16) & 0xFFFFFFFF
        ipprt = res.host[1] & 0xFFFF
        #print "host %d:%d" % (ipadr,ipprt)
        data = ''
        try:
            data = res.attrs[STUN_ATTRIBUTE_DATA]
        except KeyError:
            pass
        upd = mirco_devices.update().values(is_online=True,chost = [ipadr,ipprt],data=data,
                last_login_time=datetime.now()).where(mirco_devices.c.devid == res.tuid)

        try:
            result = QueryDB.select(upd)
        except IOError:
            self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
        except DataError: 
            ins = mirco_devices.insert().values(devid=res.tuid,is_active=True,
                    is_online=True,chost=[ipadr,ipprt],data=data,last_login_time=datetime.now())
            try:
                result = QueryDB.select(ins)
            except:
                self.errqueue[current_process().name].put(','.join([LOG_ERROR_DB,res.tuid,str(sys._getframe().f_lineno)]))
            #print "insert new devices result fetchall"
        ipadr = None
        ipprt = None
        data = None





def logger_worker(queue,logger):
    while 1:
        for x in xrange(60):
            try:
                msg = queue.get_nowait()
                logger.log(msg)
                del msg
            except:
                break
        gevent.sleep(0)

    
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
#options = make_argument_parser().parse_args()
#port = options.srv_port if options.srv_port else 3478




store = ['clients','hosts','responses','appbinds','appsock','devsock','devuuid','users','requests']
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

    srv = EpollServer(3478)
    #srv.run()
