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
import signal
import unittest
import argparse
import errno
import string
import redis
from redis import ResponseError
import random
import json
from binascii import unhexlify,hexlify
from datetime import datetime
from sockbasic import *
from pg_driver import *

from sqlalchemy import *
from sqlalchemy.exc import *
from sqlalchemy import Table,Column,BigInteger,Integer,String,ForeignKey,Date,MetaData,DateTime,Boolean,SmallInteger,VARCHAR
from sqlalchemy import sql,and_
from sqlalchemy.dialects import postgresql as pgsql



import threading
import gevent
from gevent.server import StreamServer,_tcp_listener,DatagramServer
from gevent import server,event,socket,monkey
from gevent.pool import Group
from gevent.queue import Queue
from multiprocessing import Process,current_process
import multiprocessing as mp
monkey.patch_all(thread=False)


import urllib2,urllib
import httplib
from collections import OrderedDict

try:
    import cPickle as pickle
except:
    import pickle

#ACCESS_TOKEN='3d1d7056b8f3161ad3ab2b9f1fbe24911440571748479'
ACCESS_TOKEN=u'd32f2e2abc10ffbef473f57c8e568bf91441105375390'
RAND_LEN = 6
SMS_EXPIRE=10
DENY_TIME=86400
LOGIN_TIME=7200

def get_timestamp():
    return str(datetime.now())[:19].encode('utf-8')

def get_base64_encode(appsecret,data):
    import hmac
    import hashlib
    sign = hmac.new(appsecret,data,hashlib.sha1).digest()
    return urllib.base64.b64encode(sign)

def get_token(appid,appsecret):
    uri = 'http://api.189.cn/v2/dm/randcode/token'
    d = u"access_token=%s&app_id=%s&timestamp=%s" % (ACCESS_TOKEN,appid,get_timestamp())
    reqdata =  d + "&sign=%s" % get_base64_encode(appsecret,d)
    try:
        req = urllib2.urlopen(uri,reqdata,timeout=10)
    except (IOError,httplib.HTTPException):
        return None
    else:
        jdata = json.loads(req.readlines()[0])
    return jdata.get('token',None)

def get_access_token(appid,appsecret):
    #uri = 'https://oauth.api.189.cn/emp/oauth2/v3/access_token'
    uri = 'oauth.api.189.cn'
    post  = '/emp/oauth2/v3/access_token/?'
    
    sslhttp = httplib.HTTPSConnection(uri)
    data = urllib.urlencode({'app_id':appid,'grant_type':'client_credentials',\
            'app_secret':appsecret,'code':'123456789'})
    #req = urllib2.urlopen(uri,data)
    sslhttp.request("POST",post+data)
    response = sslhttp.getresponse()

    #jdata = json.loads(req.readlines()[0])
    jdata = json.loads(response.read())
    sslhttp.close()
    
    return jdata.get('access_token',None)

def send_sms(phone,sms,appid,appsecret):
    if len(sms) < 6:
        print "sms string must be set 6 charater"
        return 1
    uri = 'http://api.189.cn/v2/dm/randcode/sendSms'
    req = urllib2.Request(uri)
    req.add_header('Content-Type','application/x-www-form-urlencoded')
    req.add_header('Host','app.com')
    token = get_token(appid,appsecret)
    if not token:
        print "not token"
        return 1
    signdata = u'access_token=%s&app_id=%s&exp_time=%d&phone=%s&randcode=%s&srvname=wifi_test&timestamp=%s&token=%s' % \
            (ACCESS_TOKEN,appid,SMS_EXPIRE,phone,sms,get_timestamp(),token)
    reqdata = signdata + "&sign=%s" % get_base64_encode(appsecret,signdata)
    req.add_data(reqdata)
    post = None
    try:
        post = urllib2.urlopen(req,timeout=10)
    except (IOError,httplib.HTTPException):
        return 1
    jdata = json.loads(post.readlines()[0])
    s =  jdata.get('res_code',None)
    print "send sms data",jdata,s,type(s)
    if s == 0:
        with open('sms.log','a+') as fd:
            fd.write("token=%s,phone=%s,rand_code=%s,return=%s,time=%s\n" % \
                (token,phone,sms,str(jdata),time.ctime()))
    return 0 if s == 0 else 1

def send_template_sms(phone,sms,appid):
    if len(sms) < 6:
        print "sms string must be set 6 charater"
        return None
    uri = "http://api.189.cn/v2/emp/templateSms/sendSms"
    template_id = u"91548825"
    template_arg = {u"phone":phone,u"srvname":u'wifi_test',u"exp_time": "%d" % SMS_EXPIRE,u"randcode":sms}

    req = urllib2.Request(uri)
    signdata = u'acceptor_tel=%s&template_id=%s&template_param=%s&app_id=%s&access_token=%s&timestamp=%s' %\
            (phone,template_id,json.dumps(template_arg),appid,ACCESS_TOKEN,get_timestamp())
    reqdata = {u'acceptor_tel':phone,
            u'template_id':template_id,
            u'template_param':json.dumps(template_arg),
            u'app_id':appid,
            u'access_token':ACCESS_TOKEN,
            u'timestamp':get_timestamp()}
    req.add_data(urllib.urlencode(reqdata))
    jdata = json.loads(urllib2.urlopen(req).readlines()[0])
    print "send sms data",jdata
    s =  jdata.get('res_code',None)
    if s == 0:
        with open('template_sms.log','a+') as fd:
            fd.write("template_id=%s,template_arg=%s,phone=%s,rand_code=%s,return=%s,time=%s\n" %\
                (template_id,template_arg,phone,sms,str(jdata),time.ctime()))


def rand_code():
    return ''.join(random.SystemRandom().choice(string.digits) for _ in xrange(RAND_LEN))


def handle_argments():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('--secret',action='store',dest='app_secret',\
            type=str,help=u'APP secret')
    
    parser.add_argument('--appid',action='store',dest='app_id',\
            type=str,help=u'app id')
    parser.add_argument('--redis_ip',action='store',dest='redis_ip',\
            type=str,help=u'redis server address'.encode('utf8'))
    parser.add_argument('--redis_port',action='store',dest='redis_port',\
            type=int,default=6379,help=u'redis servre port'.encode('utf8'))
    parser.add_argument('--redis_pass',action='store',dest='redis_pass',\
            type=str,default=None,help=u'redis auth password'.encode('utf8'))
    parser.add_argument('--version',action='version',version='0.1.0')

    args = parser.parse_args()
    if not args.app_secret:
        print  u'缺少运行必须参数 --secret'.encode('utf8')
        parser.parse_args(['-h'])
        sys.exit(1);

    if not args.app_id:
        print u'缺少运行必须参数 --appid'.encode('utf-8')
        parser.parse_args(['-h'])
        sys.exit(1);

    if not args.redis_ip:
        print u'缺少运行必须参数 --redis_ip'.encode('utf-8')
        parser.parse_args(['-h'])
        sys.exit(1);
    return args


def logger_worker(queue,logger):
    while 1:
        try:
            msg = queue.get_nowait()
            logger.log(msg)
            del msg
        except:
            pass
        gevent.sleep(0)

class SMSServer(StreamServer):
    def __init__(self,appid,secret,redis_ip,redis_port=6379,redis_pass=None):
        self.listener = _tcp_listener(('0.0.0.0',8743),65536,1)
        StreamServer.__init__(self,self.listener,handle=self.handle_new_accept)
        self.db = PostgresSQLEngine()
        self.redis = redis.Redis(host=redis_ip,port=redis_port,db=0,\
                password=redis_pass)
        try:
            type(self.redis.info())
        except ResponseError:
            print u"连接Redis服务器出错,不能连接程".encode('utf8')
            return
        self.app_secret = secret
        self.app_id = appid
        self.errqueue = Queue()
        self.errlog= StatLog('err')
        errworker = threading.Thread(target=logger_worker,args=(self.errqueue,self.errlog))
        errworker.start()
        #server.StreamServer(self.listener,self.handle_new_accept).serve_forever()

    def close(self):
        if self.closed:
            sys.exit('multiple exit signals received - aborting.')
        else:
            print "sms server exiting"
            StreamServer.close(self)
        

    def handle_new_accept(self,nsock,addr):
        """新建连接"""
        fileno = nsock.fileno()
        denyhost = self.redis.get("deny:%s" %  addr[0])
        if denyhost:
            """检查到该在禁止连接集合里"""
            return

        loghost = "login:%s" % addr[0]
        loghostnum = self.redis.get(loghost)
        if not loghostnum:
            self.redis.setex(loghost,1,LOGIN_TIME)
        else:
            #print "%s login coutd %s" % (addr[0],loghostnum)
            if int(loghostnum) == 15:
                """超过有效登录次数，可能恶意攻击"""
                self.redis.setex("deny:%s" % addr[0],15,DENY_TIME)
                self.redis.delete(loghost)
                return 
            self.redis.incr(loghost)

        try:
            hbuf = nsock.recv(SOCK_BUFSIZE)
        except:
            return
        else:
            if not hbuf:
                return 

        if not check_packet_crc32(hbuf):
            self.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d,buf %s' % (fileno,hexlify(hbuf)),str(sys._getframe().f_lineno)]))
            return 

        res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not res:
            self.errqueue.put('get jl head error,devsock,sock %d,%s,buf %s' % (fileno,addr,hbuf))
            return

        res.eattr = STUN_ERROR_NONE
        if res.method != STUN_METHOD_SMS: #只接受这一个命令
            res.eattr = STUN_ERROR_METHOD
            self.write_to_client(nsock,stun_error_response(res))
            return
    
        hexpos = STUN_HEADER_LENGTH
        res.attrs = parser_stun_package(hbuf[hexpos:-4])
        if res.attrs is None:
            #print "preauth hbuf is wrong",hbuf,self.hosts[res.fileno]
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.errqueue.put(','.join([LOG_ERROR_ATTR,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            self.write_to_client(nsock,stun_error_response(res))
            return
        telnumber = res.attrs.get(STUN_ATTRIBUTE_DATA,None)
        if not telnumber:
            """没有请求的属性"""
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.write_to_client(nsock,stun_error_response(res))
            return 

        """继续判断发送条件"""
        l = len(telnumber)
        if l < 11 or telnumber[0] != '1':
            """手机号格式错误"""
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.write_to_client(nsock,stun_error_response(res))
            return
        """查询数据库，是否注册过该号码"""
        if self.db.check_user_exist(telnumber):
            res.eattr = STUN_ERROR_USER_EXIST
            self.write_to_client(nsock,stun_error_response(res))
            return 


        denytel = "deny:%s" % telnumber
        if self.redis.exists(denytel):
            """该号码超过今天最大的发送数，明天再试"""
            res.eattr = STUN_ERROR_OVER_CONUT
            self.write_to_client(nsock,stun_error_response(res))
            return

        sendnow = "now:%s" % telnumber
        if self.redis.get(sendnow):
            """在一定时间不能请求发再发短信"""
            res.eattr = STUN_ERROR_OVER_TIME
            self.write_to_client(nsock,stun_error_response(res))
            return 

        sendtel = "send:%s" % telnumber
        sendcounts = self.redis.get(sendtel)
        if not sendcounts:
            self.redis.set(sendtel,1)
        else:
            if int(sendcounts) == 3:
                """设置24小时禁止该号码的请求发送短信息"""
                self.redis.setex(denytel,3,DENY_TIME)
                self.redis.delete(sendtel)
                res.eattr = STUN_ERROR_OVER_CONUT
                self.write_to_client(nsock,stun_error_response(res))
                return
            self.redis.incr(sendtel,1)

        rcode = rand_code()
        n = 5
        sendok = 0
        
        while n:
            if 0 == send_sms(telnumber,rcode,self.app_id,self.app_secret):
                n-=1
                gevent.sleep(1)
                continue
            sendok = 1
            """ send ok,在redis中插入记录"""
            pcode = "%s:%s" % (telnumber,rcode)
            self.redis.setex(addr[0],pcode,60 * SMS_EXPIRE)
            self.redis.set(loghost,1) # 把这一状态置1，还可以注册其它的手机.
            break

        if sendok == 0:
            """发送系统错误，连续五次请求发短信不成功，联系ISP"""
            res.eattr = STUN_ERROR_SRV_ERROR
            self.write_to_client(nsock,stun_error_response(res))
            return 

        self.redis.setex(sendnow,SMS_EXPIRE,60 * SMS_EXPIRE)
        self.write_to_client(nsock,self.return_client_smscode(res,rcode))


    def write_to_client(self,sock,buf):
        print "ack client",buf
        sock.send(''.join(buf))



    def return_client_smscode(self,res,smscode):
        od = stun_init_command_head(stun_make_success_response(res.method))
        stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,"%s:%d" % (smscode,SMS_EXPIRE))
        stun_add_fingerprint(od)
        return get_list_from_od(od)
                


def serve_forever(smssrv):
    smssrv.start()
    gevent.wait()



if __name__ == "__main__":
    _version_='0.0.1'
    _author_='liuchunyang'
    args = handle_argments()
    smssrv = SMSServer(args.app_id,args.app_secret,args.redis_ip,args.redis_port,args.redis_pass)
    gevent.signal(signal.SIGTERM,smssrv.close)
    gevent.signal(signal.SIGINT,smssrv.close)
    serve_forever(smssrv)

    

