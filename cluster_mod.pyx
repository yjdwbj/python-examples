#!/opt/stackless-279/bin/python

import os
import binascii
#import socket
import struct
import time
import threading
import fcntl
from netifaces import AF_INET,AF_INET6,AF_LINK,AF_PACKET,AF_BRIDGE
import netifaces as ni
#from Queue import Queue,Empty
import gevent
from gevent.queue import Queue,Empty
from gevent import monkey,socket
from gevent.server import DatagramServer
monkey.patch_all(thread=False)

try:
    import cPickle as pickle
except:
    import pickle



GRP_ADDR= '224.1.1.1'
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
        if bind_interface: # 指定网卡发送多播。这里服务器的内部网络
            ipaddr = ni.ifaddresses(bind_interface)[AF_INET][0]['addr']
            self.sendsock.setsockopt(socket.SOL_IP,socket.IP_MULTICAST_IF,socket.aton(ipaddr))

        self.localips = [ni.ifaddresses(n)[AF_INET][0]['addr'] for n in ni.interfaces()]
        self.ClustUserDict = {} #其它服务器的上的用户
        self.ClustDevDict = {}  #其它服务器的上的小机

        self.recvsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        self.recvsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.recvsock.bind((GRP_ADDR,GRP_PORT))
        mreq = struct.pack("4sl",
                socket.inet_aton(GRP_ADDR),socket.INADDR_ANY)
        self.recvsock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
        DatagramServer(self.recvsock,self.handle_mcast).serve_forever()


    def send_run(self,bind_interface):
        print "send run"
        while 1:
            try:
                self.sendsock.sendto(pickle.dumps(self.squeue.get_nowait()),(GRP_ADDR,GRP_PORT))
            except Empty:
                continue
            time.sleep(0.001)

    def handle_mcast(self,data,addr):
        print "recv data",data,addr
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
            
    def recv_daemon(self):     
        print 'test'
        while 1:
            data,addr = self.recvsock.recvfrom(8192)
            #self.rqueue.put_nowait(pickle.loads(data))
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
            time.sleep(0.001)

    def send_to_mcast(self,opt,typ,addr,uname,fileno):
        obj = CastClass(self,opt,typ,addr,uname,fileno)
        self.sendsock.sendto(pickle.dumps(obj),(GRP_ADDR,GRP_PORT))

    def check_user_in_cluster(self,uname):
        return self.ClustUserDict.has_key(uname)

    def check_dev_in_cluster(self,uname):
        return self.ClustDevDict.has_key(uname)

    def get_user_info(self,uname):
        return self.ClustUserDict.get(uname,None)

    def get_dev_info(self,uname):
        return self.ClustDevDict.get(uname,None)



