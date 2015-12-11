#coding: utf-8
import ssl
from Crypto.PublicKey import RSA
import struct
import time
import ast
import socket
import json
import threading
import redis
from multiprocessing import Process,Queue,Pool
from Queue import Full,Empty

from tornado.tcpserver import TCPServer
from tornado.ioloop import IOLoop
from gevent.server import DatagramServer

SOCK_BUFSIZE = 8192
#CHUNK_FLAG  = '5916203772'.decode('hex')
CHUNK_FLAG  = '\r\n\r\n'
CHUNK_SIZE = len(CHUNK_FLAG)
DEBUG_FLAG = True


ssl = {
        'certfile':'camera_srv_key.pem',
        'keyfile': 'camera_srv_key.pem',
        'ssl_version': ssl.PROTOCOL_SSLv23,
        }

CMD = 'cmd'
LOGIN = 'login'
KEP = 'keepalive'
PWD = 'pwd'
USER = 'user'
CONN = 'conn'
UUID = 'uuid'
SOCK = 'sock'
RESP = 'resp'
ADDR = 'addr'
HOST = 'host'
MSG = 'msg'
OBJ = 'obj'

dev_uuid_map_sock = {}
app_queue_in = Queue()
app_queue_out = Queue()
dev_queue_in = Queue()
dev_queue_out = Queue()

def debug_print(msg):
    if DEBUG_FLAG:
        print msg

def unpack16(data):
    return struct.unpack('!H',data)[0]

def pack16(data):
    return struct.pack('!H',data)


def split_packet(data):
    mlist = filter(None,data.split(CHUNK_FLAG))
    rlist = [x for x in mlist if unpack16(x[:2]) == len(x)]
    return rlist


def parser_packet(data):
    data = data[:-CHUNK_SIZE]
    if unpack16(data[:2]) != len(data):
        return None

    jdata = {}
    try:
        jdata = json.loads(data[2:])
    except:
        raise ("loads json occur error")
    return jdata


class NewConnection(object):
    def __init__(self,stream,address,send_queue):
        self._stream = stream 
        self._address = address
        self._stream.set_close_callback(self.on_close)
        #self.read_message()
        self.send_queue = send_queue
        print "init  conn",str(self)

    def read_message(self):
        #self._stream.read_until(CHUNK_FLAG,self.process_cmd)
        self._stream.read_until(CHUNK_FLAG,self.process_cmd)

    def send_message(self,data):
        slen = len(data)
        f = "!H%ds%ds" % (slen,CHUNK_SIZE)
        self._stream.write(struct.pack(f,slen+2,data,CHUNK_FLAG))


    def get_json(self,data):
        debug_print('data is %s' % data.encode('hex'))
        jdata = {}
        try:
            jdata = parser_packet(data)
        except:
            raise 'parser json occuer error, sock data is'
        return jdata

    def process_cmd(self):
        raise NotImplementedError()


    def on_close(self):
        debug_print("on close accept")
        print "exit conn",str(self)
        """
        Key = None
        for k,v in dev_map_socks.items():
            if v == self:
                Key = k
                break
        dev_map_socks.pop(Key)
        for k,v in app_map_socks.items():
            if v[1] == self:
                Key = k
                break
        app_map_socks.pop(Key)
        """

    def write_sock(self,data,sock):
        slen = len(data)
        f = "!H%ds%ds" % (slen,CHUNK_SIZE)
        sock.send(struct.pack(f,slen+2,data,CHUNK_FLAG))

    def work_dict(self):
        raise NotImplementedError()

    
class AppConn(NewConnection):
    devdict = {}
    def __init__(self,*args):
        NewConnection.__init__(self,*args)

    def process_cmd(self,data):
        jdata = self.get_json(data)
        if jdata == {} or not jdata:
            debug_print("json is empty ,not found cmd key")
            time.sleep(0.5)
            self.on_close()
            return self.read_message()


        cmd = jdata.get(CMD,None)
        debug_print("json is %s" % str(jdata))
        if not cmd:
            debug_print("not found cmd key")
            return self.read_message()

        if cmd == CONN:
            uuid = jdata.get(UUID,None)
            pwd = jdata.get(PWD,None)
            addr = jdata.get(ADDR,None)
            if uuid and pwd and addr:
                devpair = ast.literal_eval(rdb.get(uuid))
                print "pair is type", type(devpair)
                print "pair is sss",devpair
                if not devpair:
                    self.send_message(json.dumps({'err':'device offline'}))
                elif devpair[0] != pwd:
                    print "passwd wrong",devpair[0],pwd
                    self.send_message(json.dumps({'err':'auth failed'}))
                else:
                    jdata.pop(PWD)
                    # 把json 通过队列发给小端服务器
                    print "send conn to dev"
                    jdata[OBJ] = id(self)
                    #self.outqueue.put_nowait((devpair[1],json.dumps(jdata)))
                    self.send_queue((devpair[1],json.dumps(jdata)))
                    #devpair[1].send_message(json.dumps(jdata))
            else:
                json.dumps({'err':'format wrong!!!'})
            # 这里假定对方在这个时里会回应
        """
        elif cmd == MSG:
            uuid = jdata.get(UUID,None)
            appobj = app_map_socks.get_item(uuid)
            if appobj:
                appobj.send_message(json.dumps(jdata))
        """
        return self.read_message()


class DevConn(NewConnection):
    def __init__(self,*args):
        NewConnection.__init__(self,*args)
        

    def process_cmd(self,data):
        #debug_print('parser json occuer error, sock %d,data is %s' % (fileno,data))
        jdata = self.get_json(data)
        if jdata == {} or not jdata:
            debug_print("json is empty ,not found cmd key")
            return self.read_message()
        debug_print('get json data is %s' % str(jdata))
        cmd = jdata.get(CMD,None)
        if cmd == LOGIN:
            uuid = jdata.get(UUID,None)
            pwd = jdata.get(PWD,None)
            rdb.set(uuid,(pwd,id(self)))
            self.send_message(json.dumps({RESP:'login success'}))
        elif cmd == CONN:
            #fileno = jdata.get(SOCK,None)
            #addr = jdata.get(ADDR,None)
            # 这里还要添加校验机制
            debug_print('put data  %s to worker' % str(jdata))
            objid = jdata.get(OBJ,None)
            if objid:
                # 把收到的回答通过队列传给APP服务端
                #self.outqueue.put_nowait((objid,json.dumps(jdata)))
                self.send_queue((objid,json.dumps(jdata)))
                #appobj.send_message(json.dumps(jdata))
        elif cmd == KEP:
            self.send_message(json.dumps(jdata))
        else:
            pass
        return self.read_message()
        



class DevSrv(TCPServer):
    def __init__(self,inqueue,outqueue):
        print 'inqueue id',inqueue,'outqueue id',outqueue
        TCPServer.__init__(self)
        self.inqueue = inqueue
        self.outqueue = outqueue
        self.clients= {}
        print "dev dict id ",id(self.clients)
        threading.Thread(target=self.work_for_app).start()

    def handle_stream(self,stream,address):
        debug_print("New connection: %s,%s" % (str(address),str(stream)))
        obj = DevConn(stream,address,self.send_to_queue)
        self.clients[id(obj)] = obj
        obj.read_message()

    def send_to_queue(self,data):
        print "outqueue put",self.outqueue
        self.outqueue.put_nowait(data)

    def work_for_app(self):
        print "dev dict id in thread ------------- ",id(self.clients)
        while 1:
            try:
                idv,jdata = self.inqueue.get_nowait()
            except Empty:
                pass
            else:
                print "recv from app srv",idv
                print "out clients ",self.clients
                obj = self.clients.get(idv,None)
                if obj:
                    print 'dev found object',obj
                    obj.send_message(jdata)

            time.sleep(0.05)



class AppSrv(TCPServer):
    def __init__(self,inqueue,outqueue):
        print 'inqueue id',inqueue,'outqueue id',outqueue
        TCPServer.__init__(self)
        self.inqueue = inqueue
        self.outqueue = outqueue
        self.clients = {}
        th = threading.Thread(target=self.work_for_app)
        th.start()

    def handle_stream(self,stream,address):
        #debug_print("New connection:" % (address,stream))
        obj = AppConn(stream,address,self.send_to_queue)
        self.clients[id(obj)] = obj
        obj.read_message()

    def send_to_queue(self,data):
        self.outqueue.put_nowait(data)

    def work_for_app(self):
        while 1:
            try:
                idv,jdata = self.inqueue.get_nowait()
            except Empty:
                pass
            else:
                print "recv from dev"
                obj = self.clients.get(idv,None)
                if obj:
                    obj.send_message(jdata)

            time.sleep(0.05)


def AppInstance(inqueue,outqueue):
    app_srv = AppSrv(inqueue,outqueue)
    app_srv.bind(5561)
    app_srv.start(0)
    IOLoop.instance().start()

def DevInstance(inqueue,outqueue):
    dev_srv = DevSrv(inqueue,outqueue)
    dev_srv.bind(5560)
    dev_srv.start(0)
    IOLoop.instance().start()


def MapInstance(*arg):
    srv = arg[0]()
    srv.bind(arg[1])
    IOLoop.instance().start()


class EchoAddrSrv(DatagramServer):
    def handle(self,data,address):
        debug_print('via udp got addrees %s' % str(address))
        self.socket.sendto(str(address),address)

if __name__ == '__main__':
    appin = Queue()
    appout = Queue()

    rdb = redis.Redis(db=6,unix_socket_path='/tmp/redis.sock',password='21d01ffdc28154f2670dca9e9129c53b')
    dev = Process(target=DevInstance,args=(appout,appin))
    dev.start()
    app = Process(target=AppInstance,args=(appin,appout))
    app.start()
    

    #workerproc = Process(target=worker,args=(app_queue_out,app_queue_in,dev_queue_out,dev_queue_in))
    #workerproc = gevent.spawn(worker,app_queue_out,app_queue_in,dev_queue_out,dev_queue_in)
    #workerproc.start()

    devudp = EchoAddrSrv(('',5560))
    Process(target=devudp.serve_forever).start()
    appudp = EchoAddrSrv(('',5561))
    Process(target=appudp.serve_forever).start()
    









