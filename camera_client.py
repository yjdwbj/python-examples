#coding: utf-8
import struct
import time
import json
import socket
import ssl
from Crypto.PublicKey import RSA
from multiprocessing import Queue
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

TIMEOUT = 6

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
        self.udp_srv = server
        if udp_srv:
            self.udp_srv =udp_srv
        self.local_addr  = None
        self.remote_addr = None
        self.udpsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.udpsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.udpsock.setblocking(0)

    def connect(self):
        self.sock.connect(self.server)
        self.udpsock.connect(self.udp_srv)
        
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
            debug_print('data is %s' % xdata)
            return json.loads(xdata)
        return None


    def get_remote_addr(self):
        self.udpsock.sendto('ok',self.udp_srv)
        self.local_addr =  self.udpsock.getsockname()
        while 1:
            try:
                data,addr = self.udpsock.recvfrom(128)
            except socket.error:
                print "wait for recv my remote addr"
                gevent.sleep(1)
                continue
            else:
                return data
            



class AppClient(Client):
    def __init__(self,server,uuid,pwd,udp_srv=None):
        Client.__init__(self,server)
        self.udp_srv =server
        if udp_srv:
            self.udp_srv = udp_srv
        self.uuid = uuid
        self.pwd = pwd
            
        
    def start(self):
        self.connect()
        #addr = ('127.0.0.1',5554)
        addr = self.get_remote_addr()
        debug_print("my remote addr is %s" % str(addr))
        cmd = {CMD:CONN,ADDR:addr,UUID:self.uuid,PWD:self.pwd}
        self.write_sock(json.dumps(cmd))
        jdata = self.read_sock()
        if not jdata:
            debug_print("read from None")
        else:
            remoteaddr = ast.literal_eval(jdata[ADDR])
            debug_print('got remote ip %s ' % str(remoteaddr))

        

def keepalive(func,queue):
    n = time.time()+TIMEOUT
    while 1:
        if time.time() > n:
            print "send keep alive"
            func()
        time.sleep(1)
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
        Client.__init__(self,server)
        self.udp_srv =server
        if udp_srv:
            self.udp_srv = udp_srv
        self.uuid = uuid
        self.pwd = pwd
        self.cq = Queue()
        self.keepth = threading.Thread(target=keepalive,args=(self.send_keepalive,self.cq))
        self.keepth.start()

    def send_keepalive(self):
        self.write_sock(json.dumps({CMD:KEP}))
        self.cq.put_nowait('')


    def start(self):
        self.connect()
        
        cmd = {CMD:LOGIN,UUID:self.uuid,PWD:self.pwd}
        self.write_sock(json.dumps(cmd))
        self.cq.put_nowait('')

        #jdata = self.read_sock()
        #resp = jdata.get(RESP,None)
        n = 10
        data = None
        print "sended login"
        while 1:
            try:
                data = self.read_sock()
            except IOError:
                print "IOError"
                break
            if data: 
                print "recv data"
                n = 10
                cmd = data.get(CMD,None)
                if cmd == KEP:
                    time.sleep(1)
                    continue
                elif cmd == CONN:
                    debug_print('recv connect request %s' % data)
                    addr = self.get_remote_addr()
                    debug_print('my remote addr is %s' % str(addr))
                    remoteaddr = data.get(ADDR)
                    data[ADDR] = addr
                    d = json.dumps(data)
                    print "send conn to srv",d
                    self.write_sock(d)
                    self.cq.put_nowait('')
                elif data.has_key(RESP):
                    debug_print("%s" % str(data))

            else:
                print "no data"
                if n < 10:
                    break
                else:
                    n -= 1
            time.sleep(1)
                


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
    app_parser.set_defaults(func=AppDemo)
    dev_parser = subparsers.add_parser('dev',help='dev simulator')
    dev_parser.add_argument('-H',action='store',dest='srv_host',type=str,help='server host')
    dev_parser.add_argument('-u',action='store',dest='uuid',type=str,help='uuid')
    dev_parser.add_argument('-p',action='store',dest='pwd',type=str,help='pwd ')
    dev_parser.add_argument('-P',action='store',dest='port',type=int,help='server port')
    dev_parser.set_defaults(func=DevDemo)
    return parser
UDP_SRV = ('120.24.239.199',8999)
def AppDemo(args):
    app = AppClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd)
    app.start()

def DevDemo(args):
    dev = DevClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd)
    dev.start()

if __name__ == '__main__':
    args = argument_parser().parse_args()
    args.func(args)



