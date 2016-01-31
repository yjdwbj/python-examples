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
from gevent.pool import Pool
CONCURRENCY = 100


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
global run_time 
run_count = 0
dev_count = 0
import logging

logger = logging.getLogger()
#handler = logging.StreamHandler()
#formatter = logging.Formatter(
#                '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
#handler.setFormatter(formatter)
fHandler = logging.FileHandler("camera.log")
logger.addHandler(fHandler)
logger.setLevel(logging.DEBUG)

#logger.debug('often makes a very good meal of %s', 'visiting tourists')


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
    def __init__(self,server,is_ssl=False):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        #sock.setsockopt( socket.SOL_SOCKET, socket.TCP_NODELAY, 1)
        sock.setsockopt( socket.SOL_SOCKET, socket.TCP_QUICKACK, 1)
        saddr = server[0].split('.')[:-1]
        saddr.append('10')
        baddr = ('.'.join(saddr),0)
        self.udpsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        if saddr[0] == '172':
            self.udpsock.bind(baddr)
            sock.bind(baddr)

        #sock.settimeout(10)
        self.sock = sock
        if is_ssl:
            self.sock = ssl.wrap_socket(self.sock)
        self.server = server
        self.local_addr  = None
        self.remote_addr = None
        #self.udpsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
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
            #f = '!H%ds%ds' % (slen,CHUNK_SIZE)
            f = '!H%ds%ds' % (slen,CHUNK_SIZE)
            buf = struct.pack(f,slen+2,data,CHUNK_FLAG)
            self.sock.send(buf)

    def read_sock(self):
        data = self.sock.recv(SOCK_BUFSIZE)
        if data and CHUNK_FLAG in data:
            #print "recv data",data.encode('hex')
            slen = unpack16(data[:2])
            xdata = data[2:-4][:slen]
            #debug_print('data is %s' % xdata)
            return json.loads(xdata)
        return None


    def get_remote_addr(self):
        #self.udpsock.sendto('ok',self.udp_srv)
        udp_srv = (self.server[0],8999)
        self.udpsock.sendto('ok',udp_srv)
        #gevent.sleep(0)
        self.local_addr =  self.udpsock.getsockname()
        self.udpsock.settimeout(2)
        data = None
        while 1:
            try:
                data,addr = self.udpsock.recvfrom(128)
            except socket.timeout:
                self.udpsock.sendto('ok',udp_srv)
                #gevent.sleep(0)
                continue
            else:
                break
                
        self.udpsock.close()
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
    def __init__(self,server,uuid,pwd,is_ssl=False):
        Client.__init__(self,server,is_ssl)
        self.uuid = uuid
        self.pwd = pwd
        self.sock.settimeout(30)
            
        
    def start(self):
        #gevent.sleep(randint(1,10))
        global run_count
        try:
            self.connect()
        except:
            print "connected failed"
            return
        #addr = "127.0.0.1:5678"
        addr = self.get_remote_addr()
        #debug_print("my remote addr is %s" % str(addr))
        cmd = {CMD:CONN,ADDR:addr,UUID:self.uuid,PWD:self.pwd}

        global avg_time
        t = time.time()
        self.write_sock(json.dumps(cmd))
        #gevent.sleep(0)
        jdata = None
        try:
            jdata = self.read_sock()
        except socket.timeout:
            print "time get local addr",self.sock.getsockname()
            return

        remoteaddr = None
        if not jdata:
            debug_print("read from None")
        else:
            try:
                remoteaddr = jdata.get(ADDR,None)
            except :
                pass
            else:
                run_count += 1
                avg_time += (time.time() - t)
                #debug_print("addr data %s" % a)
                
                """
                if isinstance(a,list):
                    debug_print('got remote ip %s ' % str(a))
                else:
                    remoteaddr = jdata[ADDR].split(':')
                    debug_print('got remote ip %s ' % str(remoteaddr))
                """
        th = threading.Thread(target=connect_remote,args=(self.local_addr,
            remoteaddr,'send to dev %s' % str(time.time())))
        th.setDaemon(True)
        th.start()
        th.join()
        


class DevClient(Client):
    def __init__(self,server,uuid,pwd,is_ssl):
        Client.__init__(self,server,is_ssl)
        self.uuid = uuid
        self.pwd = pwd
        self.last_time = time.time()

    def keeplive(self):
        n = 5
        while n > 0:
            try:
                self.write_sock(json.dumps({CMD:KEP}))  
            except:
                gevent.sleep(0)
            else:
                break
            n -=1

        

    def start(self):
        global avg_time
        global tmp_num
        try:
            self.connect()
        except:
            tmp_num -=1
            print "connected failed"
            return
        
        cmd = {CMD:LOGIN,UUID:self.uuid,PWD:self.pwd}
        
        t = time.time()
        self.write_sock(json.dumps(cmd))
        #gevent.sleep(0)
        jdata = self.read_sock()
        print "recv data",jdata
        avg_time += (time.time() - t)
        self.write_sock(json.dumps({CMD:KEP}))  
        global dev_count
        global run_time
        dev_count += 1
        #print "dev_count",dev_count,tmp_num
        if dev_count == tmp_num:
            
            logger.debug("DEV success  Connected %d" % dev_count)
            logger.debug("DEV Run Time: %f" % (time.time() - run_time))
            #print "DEV Run Time:",time.time() - run_time
            #print "DEV Sum Time:",avg_time
            logger.debug("DEV Avg Time: %f" % (avg_time / float(tmp_num)))
            #print "DEV Avg Time:",avg_time / float(tmp_num)
            #print "done>"
            logger.debug("done>")
        n = 10
        data = None
        
        is_break = False
        while 1:
            try:
                data = self.read_sock()
            except IOError:
                if is_break:
                    print "IOError"
                    break
                else:
                    try:
                        self.write_sock(json.dumps({CMD:KEP}))  
                        #print "send keep"
                    except :
                        break

                    is_break = True
                    continue


            if data: 
                is_break = False
                cmd = data.get(MSG,None)
                if cmd == CONN:
                    #logger.debug("recv conn %s" % data)
                    addr = self.get_remote_addr()
                    remoteaddr = data.get(ADDR)
                    data[ADDR] = addr
                    th = threading.Thread(target=connect_remote,args=(self.local_addr,
                        remoteaddr,'send to app %s' % str(time.time())))
                    th.setDaemon(True)
                    th.start()
                    data.pop(MSG)
                    data[CMD] = CONN
                    d = json.dumps(data)
                    #logger.debug("response conn %s"  % d)
                    self.write_sock(d)
                cmd = data.get('err',None)
                if cmd:
                    break
            gevent.sleep(0)

        # error exit
        tmp_num -= 1


def connect_remote(laddr,raddr,msg):
    udpsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udpsock.bind(laddr)
    t = raddr.split(':')
    r_peer = (t[0],int(t[1]))
    
    while 1:
        try:
            udpsock.sendto(msg,r_peer)
        except:
            gevent.sleep(0)
            continue
        else:
            gevent.sleep(1)
            data = udpsock.recvfrom(1024)
            if data:
                print "recv remote data",data
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
    app_parser.add_argument('-P',action='store',dest='port',type=int,help='server port',default=5561)
    app_parser.add_argument('-f',action='store',dest='infile',type=str,help='user file')
    app_parser.add_argument('-s',action='store',dest='is_ssl',type=bool,help='toggle ssl listen')
    app_parser.set_defaults(func=AppDemo)
    dev_parser = subparsers.add_parser('dev',help='dev simulator')
    dev_parser.add_argument('-H',action='store',dest='srv_host',type=str,help='server host')
    dev_parser.add_argument('-u',action='store',dest='uuid',type=str,help='uuid')
    dev_parser.add_argument('-p',action='store',dest='pwd',type=str,help='pwd ')
    dev_parser.add_argument('-P',action='store',dest='port',type=int,help='server port',default=5560)
    dev_parser.add_argument('-f',action='store',dest='infile',type=str,help='user file')
    dev_parser.add_argument('-t',action='store',dest='dev_only',type=bool,help='test device login only')
    dev_parser.add_argument('-s',action='store',dest='is_ssl',type=bool,help='toggle ssl listen')
    dev_parser.set_defaults(func=DevDemo)
    return parser

#UDP_SRV=(socket.gethostbyname('cam.jieli.net'),8999)
#UDP_SRV=('192.168.25.100',8999)
#UDP_SRV=('120.24.12.160',8999)
def read_file(fname):
    lst = None
    with open(fname,'r') as fd:
        lst = fd.readlines()
    return [x.strip() for x in lst]

def g_func(glist,func,addr,u,p,s):
    
    o = func(addr,u,p,s)
    o.start()
    

def AppDemo(args):
    if args.uuid:
        AppClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd,args.is_ssl).start()
    else:
        n = len(args.flist)
        pool = Pool(n)
        logger.debug("APP Start  Connect number %d" % n)
        for n in args.flist:
            pool.spawn(g_func,None,AppClient,(args.srv_host,args.port),n,n,args.is_ssl)
        pool.join()
        #g_lst = [gevent.spawn(g_func,AppClient,(args.srv_host,args.port),x,x,args.is_ssl) for x in args.flist]
        #gevent.joinall(g_lst)


def DevDemo(args):
    glist = []
    if args.uuid:
        glist.append(gevent.spawn(g_func,glist,DevClient,(args.srv_host,args.port),args.uuid,args.pwd,args.is_ssl))
    else:
        n = len(args.flist)
        logger.debug("DEV Start  Connect number %d" % n)
        for n in args.flist:
            glist.append(gevent.spawn(g_func,glist,DevClient,(args.srv_host,args.port),n,n,args.is_ssl))
            #pool.spawn(g_func,glist,DevClient,(args.srv_host,args.port),n,n,args.is_ssl)
        #pool.join()
    gevent.joinall(glist)
        #g_lst = [gevent.spawn(g_func,DevClient,(args.srv_host,args.port),x,x,args.is_ssl) for x in args.flist]
        #gevent.joinall(g_lst)
    #dev = DevClient((socket.gethostbyname(args.srv_host),args.port),args.uuid,args.pwd)
    #dev.start()


if __name__ == '__main__':
    args = argument_parser().parse_args()
    args.srv_host = socket.gethostbyname(args.srv_host)
    print args.port
    global run_time
    avg_time = 0
    run_time = time.time()
    global tmp_num
    if not args.uuid:
        if not args.infile:
            print "please pointer a input file"
            sys.exit(0)
        lst = read_file(args.infile)
        setattr(args,'flist',lst)
        tmp_num = len(args.flist)
        print "start num of users ",tmp_num
    else:
        tmp_num = 1

    args.func(args)
    if args.func == AppDemo:
        logger.debug("APP success  Connected %d" % run_count)
        logger.debug("APP Run Time: %f" % (time.time() - run_time))
        #print "APP Run Time:",time.time() - run_time
        #print "APP Sum Time:",avg_time
        logger.debug("APP Avg Time: %f" % (avg_time / float(tmp_num)))
        #print "APP Avg Time:",avg_time / float(tmp_num)
        logger.debug("done>")
    



