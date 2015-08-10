#!/opt/stackless-279/bin/python
#-*- coding:utf-8 -*-

import os
import binascii
#import socket
import struct
import time
import threading
import fcntl
import netifaces as ni
import netifaces
from netifaces import AF_INET,AF_INET6,AF_LINK,AF_PACKET,AF_BRIDGE
#from Queue import Queue,Empty
import gevent
from gevent.queue import Queue,Empty
from gevent import monkey,socket
from gevent.server import DatagramServer,_udp_socket
from multiprocessing import Process
monkey.patch_all(thread=False)

try:
    import cPickle as pickle
except:
    import pickle

GRP_ADDR= '224.0.0.1'
GRP_PORT= 7878

class CastClass():
    def __init__(self,opt,typ,addr,uname,fileno):
        self.opt = opt
        self.typ = typ
        self.addr = addr
        self.uname = uname
        self.fileno = fileno



class ClusterSRV(object):
    def __init__(self,bind_interface):
        self.sendsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        self.sendsock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,5)
        self.sendsock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_LOOP,0) # 禁止发给自己

        self.localips = [ni.ifaddresses(n)[AF_INET][0]['addr'] for n in ni.interfaces()]
        self.ClustUserDict = {} #其它服务器的上的用户
        self.ClustDevDict = {}  #其它服务器的上的小机

        self.recvsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        self.recvsock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_LOOP,0) # 禁止发给自己
        self.recvsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.recvsock.bind(('',GRP_PORT))
        mreq = struct.pack("4sl",
                socket.inet_aton(GRP_ADDR),socket.INADDR_ANY)
        self.recvsock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
        if bind_interface: # 指定网卡发送多播。这里服务器的内部网络
            ipaddr = ni.ifaddresses(bind_interface)[AF_INET][0]['addr']
            self.sendsock.setsockopt(socket.SOL_IP,socket.IP_MULTICAST_IF,socket.inet_aton(ipaddr))
            self.recvsock.setsockopt(socket.SOL_IP,socket.IP_MULTICAST_IF,socket.inet_aton(ipaddr))
        Process(target=self.run_srv).start()

    def run_srv(self):
        #RecvServer(self.recvsock,self.ClustUserDict,self.ClustDevDict).serve_forever()
        DatagramServer(self.recvsock,self.handle).serve_forever()

    def handle(self,data,addr):
        obj = pickle.loads(data)
        if obj.opt:  # 登录 1 , 登出 0
            if obj.typ: #用户 1,小机 0
                self.ClustUserDict[obj.uname] = obj
            else:
                self.ClustDevDict[obj.uname] = obj
        else: #删除记录
            if obj.typ:
                tmp = self.ClustUserDict[obj.uname]
                tmp.__dict__.pop('opt',None)
                tmp.__dict__.pop('typ',None)
                tmp.__dict__.pop('uname',None)
                tmp.__dict__.pop('addr',None)
                tmp.__dict__.pop('fileno',None)
                self.ClustUserDict.pop(obj.uname,None)
                del tmp
            else:
                tmp = self.ClustDevDict[obj.uname]
                tmp.__dict__.pop('opt',None)
                tmp.__dict__.pop('typ',None)
                tmp.__dict__.pop('uname',None)
                tmp.__dict__.pop('addr',None)
                tmp.__dict__.pop('fileno',None)
                self.ClustDevDict.pop(obj.uname,None)
                del tmp


    def send_to_mcast(self,opt,typ,addr,uname,fileno):
        obj = CastClass(opt,typ,addr,uname,fileno)
        self.sendsock.sendto(pickle.dumps(obj),(GRP_ADDR,GRP_PORT))

    def check_user_in_cluster(self,uname):
        return self.ClustUserDict.has_key(uname)

    def check_dev_in_cluster(self,uname):
        return self.ClustDevDict.has_key(uname)

    def get_user_info(self,uname):
        return self.ClustUserDict.get(uname,None)

    def get_dev_info(self,uname):
        return self.ClustDevDict.get(uname,None)



