#!/opt/stackless-279/bin/python

import os
import binascii
import socket
import struct
import time
import threading
import fcntl
from netifaces import AF_INET,AF_INET6,AF_LINK,AF_PACKET,AF_BRIDGE
import netifaces as ni
from Queue import Queue,Empty
import gevent
from gevent.queue import Queue



GRP_ADDR= '224.1.1.1'
GRP_PORT= 7878

class ClusterSRV():
    def __init__(self,squeue,rqueue):
        self.squeue = squeue  # 本机煤发给多播组的队列
        self.rqueue = rqueue  # 本机从多播组里读的队列
        self.sendsock = socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        self.sendsock.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,5)

        self.recvsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        self.recvsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.recvsock.bind((RECV_GRP,RECV_PORT))
        mreq = struct.pack("4sl",
                socket.inet_aton(RECV_GRP),socket.INADDR_ANY)
        self.recvsock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
        self.localips = [ni.ifaddresses(n)[AF_INET][0]['addr'] for n in ni.interfaces()]


    def send_to_mcast(self):
        while 1:
            try:
                self.sendsock.sendto(self.squeue.get_nowait(),(GRP_ADDR,GRP_PORT))
            except Empty:
                continue
            gevent.sleep(0)
            
    def recv_daemon(self):     
        while 1:
            data,addr = self.recvsock.recvfrom(8192)
            if addr[0] not in self.localips:
                self.rqueue.put_nowait(data)
            gevent.sleep(0)

    def make_mcast_package(self):
        pass

    def parse_mcast_package(self):
        pass


