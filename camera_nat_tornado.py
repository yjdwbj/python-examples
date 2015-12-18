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
import re
from multiprocessing import Process,Queue,Pool,Manager
from Queue import Full,Empty
import gevent


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
ERR = 'err'



DEVCLIENTS = 'devclients'
APPCLIENTS = 'appclients'
devs = {}
apps = {}
alock = threading.Lock()
dlock = threading.Lock()

class NewConnection(object):
    def __init__(self,stream,address):
        self._stream = stream 
        self._address = address
        self._stream.set_close_callback(self.on_close)
        self.idv = None
        self.read_message()

    def parser_packet(self,data):
        data = data[:-CHUNK_SIZE]
        if self.unpack16(data[:2]) != len(data):
            return None
    
        jdata = {}
        try:
            jdata = json.loads(data[2:])
        except:
            raise ("loads json occur error")
        return jdata

    def split_packet(self,data):
        mlist = filter(None,data.split(CHUNK_FLAG))
        rlist = [x for x in mlist if self.unpack16(x[:2]) == len(x)]
        return rlist

    def unpack16(self,data):
        return struct.unpack('!H',data)[0]

    def pack16(self,data):
        return struct.pack('!H',data)

    def read_message(self):
        #self._stream.read_until(CHUNK_FLAG,self.process_cmd)
        self._stream.read_until(CHUNK_FLAG,self.process_cmd)
                

    def send_message(self,data):
        slen = len(data)
        f = "!H%ds%ds" % (slen,CHUNK_SIZE)
        self._stream.write(struct.pack(f,slen+2,data,CHUNK_FLAG))


    def get_json(self,data):
        jdata = {}
        try:
            jdata = self.parser_packet(data)
        except:
            raise 'parser json occuer error, sock data is'
        return jdata



    def on_close(self):
        idv = id(self)
        print "exit conn",idv,"it's idv",self.idv
        if self.idv == DEVCLIENTS:
            with dlock:
                print "now devs dict",devs
                print ""
                item = [k for k,v in devs.items() if v[1] == self]
                devs.pop(k,None)
                print "pop now devs dict",devs
                print ""
        elif self.idv == APPCLIENTS:
            with alock:
                apps.pop(id(self),None)
                print "now apps store",apps
        else:
            pass

    def write_sock(self,data,sock):
        slen = len(data)
        f = "!H%ds%ds" % (slen,CHUNK_SIZE)
        sock.send(struct.pack(f,slen+2,data,CHUNK_FLAG))

    def process_cmd(self,data):
        #raise NotImplementedError()
        jdata = self.get_json(data)
        if jdata == {} or not jdata:
            self.on_close()
            return 
        cmd = jdata.get(CMD,None)
        if not cmd:
            return self.read_message()
        

        if cmd == CONN:
            idv = jdata.get(OBJ,None)
            if idv:
                #发给APP,
                print "recv conn from dev ",idv,str(jdata)
                with alock:
                    obj = apps.get(idv,None)
                    if obj:
                        obj.send_message(json.dumps(jdata))
            else:
                print "app login to connect"
                print ""
                uuid = jdata.get(UUID,None)
                pwd = jdata.get(PWD,None)
                addr = jdata.get(ADDR,None)
                if uuid and pwd and addr:
                    with dlock:
                        pair = devs.get(uuid,None)
                        print "get pair is",pair,"devs ",devs
                        print "type it", type(pair)
                        if not pair:
                            self.send_message(json.dumps({ERR:'device offline'}))
                        elif pair[0] != pwd:
                            print "passwd wrong",pair[0],pwd
                            self.send_message(json.dumps({ERR:'auth failed'}))
                        else:
                            jdata.pop(PWD)
                            jdata[OBJ] = id(self)
                            self.idv = APPCLIENTS
                            with alock:
                                apps[id(self)] = self
                            print "send request to dev "
                            pair[1].send_message(json.dumps(jdata))

                else:
                    self.send_message({ERR:'format wrong'})
        elif cmd == LOGIN:
            uuid = jdata.get(UUID,None)
            pwd = jdata.get(PWD,None)
            self.idv = DEVCLIENTS
            with dlock:
                devs[uuid]= (pwd,self)
                print "dev dict is",devs
            print "dev login",self,uuid
            print ""
            self.send_message(json.dumps({RESP:'login success'}))
        elif cmd == KEP:
            self.send_message(json.dumps(jdata))
        else:
            pass

        return self.read_message()


class SRV(TCPServer):
    def __init__(self):
        TCPServer.__init__(self)

    def handle_stream(self,stream,address):
        obj = NewConnection(stream,address)

def SRVInstance():
    s = SRV()
    s.bind(5560)
    s.start()
    IOLoop.instance().start()



class EchoAddrSrv(DatagramServer):
    def handle(self,data,address):
        self.socket.sendto(str(address),address)

if __name__ == '__main__':

    #rdb = redis.Redis(db=6,unix_socket_path='/tmp/redis.sock',password='21d01ffdc28154f2670dca9e9129c53b')
    #rdb.delete(APPCLIENTS)
    #rdb.delete(DEVCLIENTS)


    #workerproc = Process(target=worker,args=(app_queue_out,app_queue_in,dev_queue_out,dev_queue_in))
    #workerproc = gevent.spawn(worker,app_queue_out,app_queue_in,dev_queue_out,dev_queue_in)
    #workerproc.start()
    Process(target=SRVInstance).start()

    devudp = EchoAddrSrv(('',5560))
    Process(target=devudp.serve_forever).start()
    appudp = EchoAddrSrv(('',5561))
    Process(target=appudp.serve_forever).start()
    









