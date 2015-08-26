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

def get_timestamp():
    return str(datetime.now())[:19]

def get_base64_encode(data):
    sign = hmac.new(APP_SECRET,data,hashlib.sha1).digest()
    return urllib.base64.b64encode(sign)

def get_token():
    uri = 'http://api.189.cn/v2/dm/randcode/token'
    d = u"access_token=%s&app_id=%s&timestamp=%s" % (ACCESS_TOKEN,APP_ID,get_timestamp())
    reqdata =  d + "&sign=%s" % get_base64_encode(d)
    req = urllib2.urlopen(uri,reqdata)
    jdata = json.loads(req.readlines()[0])
    return jdata.get('token',None)

def get_access_token():
    uri = 'https://oauth.api.189.cn/emp/oauth2/v3/access_token'
    data = urllib.urlencode({'app_id':APP_ID,'grant_type':'client_credentials','app_secret':APP_SECRET,'code':'123456789'})
    req = urllib2.urlopen(uri,data)
    jdata = json.loads(req.readlines()[0])
    return jdata.get('access_token',None)


def send_sms(phone,sms):
    if len(sms) < 6:
        print "sms string must be set 6 charater"
        return None
    uri = 'http://api.189.cn/v2/dm/randcode/sendSms'
    req = urllib2.Request(uri)
    req.add_header('Content-Type','application/x-www-form-urlencoded')
    req.add_header('Host','app.com')
    token = get_token()
    if not token:
        return None
    signdata = u'access_token=%s&app_id=%s&phone=%s&randcode=%s&timestamp=%s&token=%s' % \
            (ACCESS_TOKEN,APP_ID,phone,sms,get_timestamp(),token)
    reqdata = signdata + "&sign=%s" % get_base64_encode(signdata)
    req.add_data(reqdata)
    jdata = json.loads(urllib2.urlopen(req).readlines()[0])
    return jdata.get('res_code',None)

method = ['sendcount','errcount','clients','crcerrcout','phonenum']

class SMSServer():
    def __init__(self,addr):
        self.listener = _tcp_listener(addr,65536,1)
        server.StreamServer(self.listener,self.handle_new_accept).serve_forever()

    def handle_new_accept(self,nsock,addr):
        fileno = nsock.fileno()
        self.clients[fileno] = nsock
        self.hosts[fileno] = addr
        nhost = self.hosts.get(addr[0],None)
        if not nhost:
            self.hosts[addr[0]] = 1
        else:
            if nhost > 5:
                """判定是恶意攻击"""
                pass
            else:
                self.hosts[addr[0]] +=1
                """继续下一步处理"""

    def process_packet(self,nsock):
        try:
            recvbuf = nsock.recv(SOCK_BUFSIZE)
        except:
            return
        else:
            if not recvbuf:
                return
            self.handle_requests_buf(recvbuf)
                    
    def handle_requests_buf(self,hbuf,fileno): # pair[0] == hbuf, pair[1] == fileno
        if not hbuf:
            return 
        res = get_packet_head_class(hbuf[:STUN_HEADER_LENGTH])
        if not res:
            self.errqueue.put('get jl head error,devsock,sock %d,%s,buf %s' % (fileno,self.hosts[fileno],hbuf))
            return
        res.eattr = STUN_ERROR_NONE
        if res.method != STUN_METHOD_SMS: #只接受这一个命令
            return

    def handle_client_request_preauth(self,res,hbuf): # pair[0] == hbuf, pair[1] == fileno
        if not check_packet_crc32(hbuf):
            self.errqueue.put(','.join([LOG_ERROR_PACKET,'sock %d,buf %s' % (res.fileno,hexlify(hbuf)),str(sys._getframe().f_lineno)]))
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
            """没有请求的属于"""
            return 
        """继续判断发送条件"""
        telnumber = unhexlify(data)
        l = len(telnumber)
        if l < 11 or telnumber[0] != '1':
            """手机号格式错误"""
            return

        precord = self.phonenum.get(telnumber,None)
        if not precord:
            self.phonenum[telnumber] = 1
        """查询今天发了多少次"""





