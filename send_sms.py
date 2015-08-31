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
import string
import redis
import random
from binascii import unhexlify,hexlify
from datetime import datetime

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


import hashlib
import urllib2,urllib
from collections import OrderDict

try:
    import cPickle as pickle
except:
    import pickle

ACCESS_TOKEN='3d1d7056b8f3161ad3ab2b9f1fbe24911440571748479'
RAND_LEN = 6
SMS_EXPIRE=10

def get_timestamp():
    return str(datetime.now())[:19]

def get_base64_encode(appsecret,data):
    sign = hmac.new(appsecret,data,hashlib.sha1).digest()
    return urllib.base64.b64encode(sign)

def get_token(appid,appsecret):
    uri = 'http://api.189.cn/v2/dm/randcode/token'
    d = u"access_token=%s&app_id=%s&timestamp=%s" % (ACCESS_TOKEN,appid,get_timestamp())
    reqdata =  d + "&sign=%s" % get_base64_encode(appsecret,d)
    req = urllib2.urlopen(uri,reqdata)
    jdata = json.loads(req.readlines()[0])
    return jdata.get('token',None)

def get_access_token(appid,appsecret):
    uri = 'https://oauth.api.189.cn/emp/oauth2/v3/access_token'
    data = urllib.urlencode({'app_id':appid,'grant_type':'client_credentials',\
            'app_secret':appsecret,'code':'123456789'})
    req = urllib2.urlopen(uri,data)
    jdata = json.loads(req.readlines()[0])
    return jdata.get('access_token',None)

def send_sms(phone,sms,appid,appsecret):
    if len(sms) < 6:
        print "sms string must be set 6 charater"
        return None
    uri = 'http://api.189.cn/v2/dm/randcode/sendSms'
    req = urllib2.Request(uri)
    req.add_header('Content-Type','application/x-www-form-urlencoded')
    req.add_header('Host','app.com')
    token = get_token(appid,appsecret)
    if not token:
        return None
    signdata = u'access_token=%s&app_id=%s&exp_time=%d&phone=%s&randcode=%s&timestamp=%s&token=%s' % \
            (ACCESS_TOKEN,appid,SMS_EXPIRE,phone,sms,get_timestamp(),token)
    reqdata = signdata + "&sign=%s" % get_base64_encode(appsecret,signdata)
    req.add_data(reqdata)
    jdata = json.loads(urllib2.urlopen(req).readlines()[0])
    print "send sms data",jdata
    return jdata.get('res_code',None)

def send_custom_sms(phone,sms,appid,appsecret):
    if len(sms) < 6:
        print "sms string must be set 6 charater"
        return None
    uri = 'http://api.189.cn/v2/dm/randcode/sendSms'
    req = urllib2.Request(uri)
    req.add_header('Content-Type','application/x-www-form-urlencoded')
    req.add_header('Host','app.com')
    token = get_token(appid,appsecret)
    if not token:
        return None
    signdata = u'access_token=%s&app_id=%s&exp_time=%d&phone=%s&randcode=%s&srvname=%s&timestamp=%s&token=%s' % \
            (ACCESS_TOKEN,appid,SMS_EXPIRE,phone,sms,u'wifi音箱',get_timestamp(),token)
    reqdata = signdata + "&sign=%s" % get_base64_encode(appsecret,signdata)
    req.add_data(reqdata)
    jdata = json.loads(urllib2.urlopen(req).readlines()[0])
    print "send sms data",jdata
    return jdata.get('res_code',None)

def rand_code():
    return ''.join(random.SystemRandom().choice(string.digits) for _ in xrange(RAND_LEN))


def handle_argments():
    parser = argparse.ArgumentParser(
        formatter_class = argparse.ArgumentDefaultsHelpFormatter
        )
    parser.add_argument('--secret',action='store',dest='app_secret',type=str,help=u'APP 密钥')
    parser.add_argument('--appid',action='store',dest='app_id',type=str,help=u'app id')
    parser.add_argument('--redis_ip',action='store',dest='redis_ip',\
            type=str,help=u'redis 服务器地址')
    parser.add_argument('--redis_port',action='store',dest='redis_port',\
            type=int,default=6379,help=u'redis 服务器端口')
    parser.add_argument('--redis_pass',action='store',dest='redis_pass',\
            type=str,default=None,help=u'redis 连接认证密码')

    args = parser.parse_args()
    if not args.app_secret:
        print u'缺少运行必须参数 --secret',
        sys.exit(1);

    if not args.app_id:
        print u'缺少运行必须参数 --appid',
        sys.exit(1);

    if not args.redis_ip:
        print u'缺少运行必须参数 --redis_ip',
        sys.exit(1);
    return args

class SMSServer():
    def __init__(self,appid,secret,redis_ip,redis_port=6379,redis_pass=None):
        self.listener = _tcp_listener('0.0.0.0',65536,1)
        [setattr(self,x,{}) for x in method]
        self.db = PostgresSQLEngine()
        self.redis = redis.Redis(host=redis_ip,port=redis_port,db=0,\
                password=redis_pass)
        self.app_secret = secret
        self.app_id = appid
        server.StreamServer(self.listener,self.handle_new_accept).serve_forever()
        

    def handle_new_accept(self,nsock,addr):
        """新建连接"""
        fileno = nsock.fileno()

        denyhost = self.redis.get("deny:%s",addr[0])
        if denyhost:
            """检查到该在禁止连接集合里"""
            return

        loghost = "login:%s" % addr[0]
        loghostnum = self.redis.get(loghost)
        if not loghostnum:
            self.redis.set(loghost,1)
        else:
            if loghostnum == 15:
                """超过有效登录次数，可能恶意攻击"""
                self.redis.setex("deny:%s" % addr[0],15,86400)
                self.redis.delete(loghostnum)
                return 
            self.redis.incr(loghost)

        self.clients[fileno] = nsock
        try:
            hbuf = nsock.recv(SOCK_BUFSIZE)
        except:
            return
        else:
            if not hbuf:
                return 

        if not check_packet_crc32(hbuf):
            self.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d,buf %s' % (res.fileno,hexlify(hbuf)),str(sys._getframe().f_lineno)]))
            return 

        res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not res:
            self.errqueue.put('get jl head error,devsock,sock %d,%s,buf %s' % (fileno,self.hosts[fileno],hbuf))
            return

        res.eattr = STUN_ERROR_NONE
        if res.method != STUN_METHOD_SMS: #只接受这一个命令
            res.eattr = STUN_ERROR_METHOD
            return
    
        hexpos = STUN_HEADER_LENGTH
        res.attrs = parser_stun_package(hbuf[hexpos:-4])
        if res.attrs is None:
            #print "preauth hbuf is wrong",hbuf,self.hosts[res.fileno]
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            self.errqueue.put(','.join([LOG_ERROR_ATTR,self.hosts[res.fileno][0],str(sys._getframe().f_lineno)]))
            return
        data = res.attrs.get(STUN_ATTRIBUTE_DATA,None)
        if not data:
            """没有请求的属性"""
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            return 

        """继续判断发送条件"""
        telnumber = unhexlify(data)
        l = len(telnumber)
        if l < 11 or telnumber[0] != '1':
            """手机号格式错误"""
            res.eattr = STUN_ERROR_UNKNOWN_ATTR
            return
        """查询数据库，是否注册过该号码"""
        if self.db.check_user_exist(telnumber):
            res.eattr = STUN_ERROR_USER_EXIST
            return stun_error_response(res)


        sendtel = "send:%s" % telnumber
        denytel = "deny:%s" % telnumber
        if self.redis.exists(denytel):
            """该号码超过今天最大的发送数，明天再试"""
            res.eattr = STUN_ERROR_OVER_TIME
            return

        sendnow = "now:%s" % telnumber
        if self.redis.get(sendnow):
            """在一定时间不能请求发再发短信"""
            res.eattr = STUN_ERROR_OVER_TIME
            return 

        sendcounts = self.redis.get(sendtel)
        if not sendcounts:
            self.redis.set(sendtel,1)
        else:
            if sendcounts == 3:
                """设置24小时禁止该号码的请求发送短信息"""
                self.redis.setex(denytel,3,86400)
                self.redis.delete(sendtel)
                return
            self.redis.incr(sendtel,1)

        rcode = rand_code()
        n = 5
        sendok = 0
        
        while n:
            if not send_sms(telnumber,rcode):
                sendok = 1
                """ send ok,在redis中插入记录"""
                d = {'code':rcode,'host':addr[0],'expire':None}
                self.redis.set(telnumber,json.dumps(d))
                self.redis.set(loghost,1) # 把这一状态置1，还可以注册其它的手机.
                break
            else:
                time.sleep(1)
                n -=1
        if sendok == 0:
            """发送系统错误，连续五次请求发短信不成功，联系ISP"""
            res.eattr = STUN_ERROR_SRV_ERROR
            return 
        self.redis.setex(sendnow,SMS_EXPIRE,60 * SMS_EXPIRE)
        nsock.send(''.join(return_client_smscode(res,rcode)))


    def return_client_smscode(self,res,smscode):
        od = stun_init_command_head(stun_make_success_response(res.method))
        stun_attr_append_str(od,STUN_ATTRIBUTE_DATA,smscode)
        stun_add_fingerprint(od)
        return get_list_from_od(od)
                

if __name__ == "__main__":
    _version_='0.0.1'
    _author_='liuchunyang'
    args = handle_argments()
    SMSServer(args.app_id,args.app_secret,args.redis_ip,args.redis_port,args.redis_pass)


