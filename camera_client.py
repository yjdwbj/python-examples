#coding: utf-8
import struct
import time
import json
import socket
import ssl
import sys
from Crypto.PublicKey import RSA
from random import randint
#from multiprocessing import Queue
from gevent.queue import Queue
from gevent.pool import Group
import threading
import gevent
import ast
import argparse


SOCK_BUFSIZE = 8192
#CHUNK_FLAG  = '5916203772'.decode('hex')
CHUNK_FLAG  = '\r\n\r\n'
CHUNK_SIZE = len(CHUNK_FLAG)
DEBUG_FLAG = True
CMD = 'cmd'
LOGIN = 'login'
KEP = 'keep'
PWD = 'pwd'
CONN = 'conn'
UUID = 'uuid'
ADDR = 'addr'
RESP = 'resp'
HOST = 'host'
MSG = 'msg'

TIMEOUT = 5
run_time = time.time()
run_count = 0
dev_count = 0
tmp_num = 0

def debug_print(msg):
    if DEBUG_FLAG:
        print msg

def unpack16(data):
    return struct.unpack('!H',data)[0]

def pack16(data):
    return struct.pack('!H',data)


def split_packet(data):
    mlist = filter(None,rbuf.split(CHUNK_FLAG))
    rlist = [x for x in mlist if unpack16(x[:2]) == len(x)]


class Client(object):
    def __init__(self,server,udp_srv = None):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #sock.settimeout(30)
        self.sock = sock
        #self.sock = ssl.wrap_socket(self.sock)
        self.server = server
        self.udp_srv =udp_srv
        self.local_addr  = None
        self.remote_addr = None
        self.udpsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.udpsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        #self.udpsock.setblocking(0)

    def connect(self):
        self.sock.connect(self.server)
        #self.udpsock.connect(self.udp_srv)
        
    def close(self):
        self.sock.close()
        self.udpsock.close()

    def write_sock(self,data):
        if data:
            slen = len(data)
            f = '!H%ds%ds' % (slen,CHUNK_SIZE)
            self.sock.send(struct.pack(f,slen+2,data,CHUNK_FLAG))

    def read_sock(self):
        data = self.sock.recv(SOCK_BUFSIZE)
        if data and CHUNK_FLAG in data:
            slen = unpack16(data[:2])
            xdata = data[2:-4][:slen]
            #debug_print('data is %s' % xdata)
            return json.loads(xdata)
        return None


    def get_remote_addr(self):
        #self.udpsock.sendto('ok',self.udp_srv)
        self.udpsock.sendto('ok',self.udp_srv)
        self.local_addr =  self.udpsock.getsockname()
        data,addr = self.udpsock.recvfrom(128)
        #self.udpsock.close()
        return data
        #    print "got remote addr",data
        #    if ':' in data:
        #        return data
        #    else:
        #        return "|".join(data.split(','))
        #    """
        #    try:
        #        data,addr = self.udpsock.recvfrom(128)
        #    except socket.error:
        #        print "wait for recv my remote addr"
        #        gevent.sleep(1)
        #        continue
        #    else:
        #        print "got remote addr",data
        #        if ':' in data:
        #            return data
        #        else:
        #            return "|".join(data.split(','))
        #    """
            



class AppClient(Client):
    def __init__(self,server,uuid,pwd,udp_srv=None):
        Client.__init__(self,server,udp_srv)
        self.uuid = uuid
        self.pwd = pwd
            
        
    def start(self):
        #gevent.sleep(randint(1,10))
        try:
            self.connect()
        except:
            return
        #addr = "127.0.0.1:5678"
        addr = self.get_remote_addr()
        #debug_print("my remote addr is %s" % str(addr))
        cmd = {CMD:CONN,ADDR:addr,UUID:self.uuid,PWD:self.pwd}
        self.write_sock(json.dumps(cmd))
        jdata = self.read_sock()
        if not jdata:
            debug_print("read from None")
        else:
            try:
                a = jdata.get(ADDR,None)
            except :
                pass
                print "get remote failed"
            else:
                global run_count
                run_count += 1
                #debug_print("addr data %s" % a)
                
                """
                if isinstance(a,list):
                    debug_print('got remote ip %s ' % str(a))
                else:
                    remoteaddr = jdata[ADDR].split(':')
                    debug_print('got remote ip %s ' % str(remoteaddr))
                """

        

def keepalive(func,queue):
    n = time.time()+TIMEOUT
    while 1:
        time.sleep(TIMEOUT)
        try:
            t = queue.get_nowait()
        except:
            pass
        else:
            if t == 'q':
                break
            n = time.time()+TIMEOUT
            
        


class DevClient(Client):
    def __init__(self,server,uuid,pwd,udp_srv=None):
        Client.__init__(self,server,udp_srv)
        self.uuid = uuid
        self.pwd = pwd
        self.last_time = time.time()
        

    def send_keepalive(self):
        while 1:
            time.sleep(TIMEOUT)
            self.write_sock(json.dumps({CMD:KEP}))


    def start(self):
        try:
            self.connect()
        except:
            return
        
        cmd = {CMD:LOGIN,UUID:self.uuid,PWD:self.pwd}
        self.write_sock(json.dumps(cmd))
        self.last_time = time.time()
        #jdata = self.read_sock()
        th =threading.Thread(target=self.send_keepalive)
        th.Daemon = True
        th.start()

        global dev_count
        global tmp_num
        dev_count += 1
        if dev_count > tmp_num:
            print "sucess connect time",time.time() - run_time
        n = 10
        data = None
        while 1:
            try:
                data = self.read_sock()
            except IOError:
                print "IOError"
                break
            if data: 
                n = 10
                #print "recv data is",data
                cmd = data.get(MSG,None)
                if cmd == CONN:
                    #debug_print('recv connect request %s' % data)
                    addr = self.get_remote_addr()
                    #debug_print('my remote addr is %s' % str(addr))
                    remoteaddr = data.get(ADDR)
                    data[ADDR] = addr
                    data.pop(MSG)
                    data[CMD] = CONN
                    d = json.dumps(data)
                    #print "send conn to srv",d
                    self.write_sock(d)

            else:
                print "no data"
                if n < 10:
                    break
                else:
                    n -= 1
            gevent.sleep(0)
                


def argument_parser():
    parser = argparse.ArgumentParser(
            formatter_class = argparse.ArgumentDefaultsHelpFormatter
            )
    subparsers = parser.add_subparsers(help ='commands')
    app_parser =subparsers.add_parser('app',help='app simulator')
    app_parser.add_argument('-H',action='store',dest='srv_host',type=str,help='server host')
    app_parser.add_argument('-u',action='store',dest='uuid',type=str,help='uuid')
    app_parser.add_argument('-p',action='store',dest='pwd',type=str,help='pwd ')
    app_parser.add_argument('-P',action='store',dest='port',type=int,help='server port')
    app_parser.add_argument('-f',action='store',dest='infile',type=str,help='user file')
    app_parser.set_defaults(func=AppDemo)
    dev_parser = subparsers.add_parser('dev',help='dev simulator')
    dev_parser.add_argument('-H',action='store',dest='srv_host',type=str,help='server host')
    dev_parser.add_argument('-u',action='store',dest='uuid',type=str,help='uuid')
    dev_parser.add_argument('-p',action='store',dest='pwd',type=str,help='pwd ')
    dev_parser.add_argument('-P',action='store',dest='port',type=int,help='server port')
    dev_parser.add_argument('-f',action='store',dest='infile',type=str,help='user file')
    dev_parser.set_defaults(func=DevDemo)
    return parser

UDP_SRV=(socket.gethostbyname('cam.jieli.net'),8999)
def read_file(fname):
    lst = None
    with open(fname,'r') as fd:
        lst = fd.readlines()
    return [x.strip() for x in lst]

def g_func(func,addr,u,p):
    o = func(addr,u,p,UDP_SRV)
    o.start()
    

def AppDemo(args):
    if args.uuid:
        AppClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd,UDP_SRV).start()
    else:
        if not args.infile:
            print "please pointer a input file"
            sys.exit(0)
        lst = read_file(args.infile)
        
        g_lst = [gevent.spawn(g_func,AppClient,(socket.gethostbyname(args.srv_host),args.port),x,x) for x in lst]
        gevent.joinall(g_lst)

    #app = AppClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd)
    #app.start()

def DevDemo(args):
    global tmp_num
    if args.uuid:
        DevClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd,UDP_SRV).start()
    else:
        if not args.infile:
            print "please pointer a input file"
            sys.exit(0)
        lst = read_file(args.infile)
        tmp_num = len(lst)
        print "num of users ",tmp_num
        g_lst = [gevent.spawn(g_func,DevClient,(socket.gethostbyname(args.srv_host),args.port),x,x) for x in lst]
        gevent.joinall(g_lst)
    #dev = DevClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd)
    #dev.start()


if __name__ == '__main__':
    args = argument_parser().parse_args()
    run_time = time.time()
    args.func(args)
    print "run time is ",time.time() - run_time
    print "success connect is ",run_count



