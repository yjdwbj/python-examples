#coding: utf-8
import ssl
from Crypto.PublicKey import RSA
import struct
import time
import gevent
import socket
import json
import threading
from gevent import monkey
from gevent.server import StreamServer,DatagramServer
from multiprocessing import Process,Queue
from Queue import Full,Empty

monkey.patch_all(thread=False)

SOCK_BUFSIZE = 8192
CHUNK_FLAG  = '5916203772'.decode('hex')
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
    if unpack16(data[:2]) != len(data):
        return None

    jdata = {}
    try:
        jdata = json.loads(data[2:])
    except:
        raise ("loads json occur error")
        
    return jdata

def worker(app_input,app_output,dev_input,dev_output):
    while 1:
        try:
            # 轮询app端
            sock,uuid,pwd,addr = app_input.get_nowait()
            debug_print('we get four %d, %s,%s,%s' % (sock,uuid,pwd,addr))
        except Empty:
            pass
        else:
            obj = dev_uuid_map_sock.get(uuid.decode('utf-8'),None)
            print "obj is ",obj
            debug_print("dev uuid map socks %s" % str(dev_uuid_map_sock))
            if not obj:
                app_output.put(json.dumps({'err':'devices offline'}))
            else:
                if pwd != obj[1]:
                    app_output(json.dumps({'err':'autherr'}))
                else:
                    # 认证通过，把APP端的IP发给小机
                    debug_print('info dev ,some one want to connect it')
                    dev_output.put( (obj[0],json.dumps({CMD:CONN,HOST:[sock,addr]})))

        gevent.sleep(0.01)
        try:
            d = dev_input.get_nowait()
        except Empty:
            pass
        else:
            debug_print('dev ack is %s' % type(d))
            if isinstance(d,dict):
                # 返回的是地址与SOCKET
                debug_print('put dev ack to app %s' % str(d))

                app_output.put_nowait(json.dumps(d))
            elif isinstance(d,tuple):
                # will get  (uuid,fileno,pwd)
                debug_print('insert new user %s' % str(d))
                dev_uuid_map_sock[d[0]] = d[1:]
            else:
                pass
        gevent.sleep(0.01)
        

class BaseSrv(StreamServer):
    def __init__(self,address,handle=None):
        StreamServer.__init__(self,address,handle=self.handle_new_accept,backlog=65535,)
        #self.srv = StreamServer(address,handle=self.handle_new_accept,backlog=65535,**ssl)
        #self.srv.init_socket()
        self.socks = {}
        self.recvbuf = {}
        self.responses = {}
        



    def spawn_newsocket(self,sock):
        fileno = sock.fileno()
        n = 10
        while 1:
            recvbuf = sock.recv(SOCK_BUFSIZE)
            if not recvbuf:
                if n < 1:
                    break
                else:
                    n -=1
            else:
                n = 10
                debug_print('recv data %s' % recvbuf.encode('hex'))
                self.recvbuf[fileno] += recvbuf
                self.process_requests(fileno)
            gevent.sleep(1)
        self.close_sock(fileno)

    def handle_new_accept(self,nsock,addr):
        fileno = nsock.fileno()
        #nsock.setblocking(0)
        self.socks[fileno] = nsock
        self.recvbuf[fileno] = ''
        debug_print('new accept on %s' % str(addr))
        #gevent.spawn(self.spawn_newsocket,nsock).join()
        n = 10
        while 1:
            recvbuf = nsock.recv(SOCK_BUFSIZE)
            if not recvbuf:
                if n < 1:
                    break
                else:
                    n -=1
            else:
                n = 10
                debug_print('recv data %s' % recvbuf.encode('hex'))
                self.recvbuf[fileno] += recvbuf
                self.process_requests(fileno)
            gevent.sleep(1)
        self.close_sock(fileno)
        # exit this threading

    def process_requests(self,fileno):
        l = self.recvbuf[fileno].count(CHUNK_FLAG)
        if not l:
            debug_print("not found chunk flags %d " % fileno)
            return

        #plen = len(self.recvbuf[fileno])
        rbuf = self.recvbuf[fileno]
        plen = len(rbuf)
        mlist = split_packet(rbuf)
        pos = sum([len(n)+ CHUNK_SIZE for n in mlist])
        self.recvbuf[fileno] = rbuf[pos:]
        [self.process_cmd(n,fileno) for n in mlist]

    def get_json(self,data):
        jdata = {}
        try:
            jdata = parser_packet(data)
        except:
            raise 'parser json occuer error, sock %d,data is'
            return
        return jdata

    def write_sock(self,fileno):
        sbuf = self.responses.get(fileno,None)
        if sbuf:
            slen = len(sbuf)
            pformat = '!5sH%ds' % slen
            self.socks[fileno].send(struct.pack(pformat,CHUNK_FLAG,slen+2,sbuf))


    def serve_forever(self):
        #self.srv.start_accepting()
        #self.srv._stop_event.wait()
        #self.srv.start()
        self.start()


    def close_sock(self,fileno):
        n = self.socks.pop(fileno)
        debug_print('close socket of %d ' % fileno)
        n.close()



class AppSrv(BaseSrv):
    def __init__(self,address = ('',5561)):
        BaseSrv.__init__(self,address)
        self.sessions  = {}
        self.q_input = app_queue_in
        self.q_output = app_queue_out
        print "start App Server",address

    def process_cmd(self,data,fileno):
        jdata = self.get_json(data)
        cmd = jdata.get(CMD,None)
        if not cmd:
            debug_print("not found cmd key")
            
            return

        if cmd == CONN:
            uuid = jdata.get(UUID,None)
            pwd = jdata.get(PWD,None)
            addr = jdata.get(ADDR,None)
            if uuid and pwd and addr:
                self.q_output.put((fileno,uuid,pwd,addr))
            else:
                self.responses[fileno] = json.dumps({'err':'format wrong!!!'})
                self.write_sock(fileno)
            # 这里假定对方在这个时里会回应

            while 1:
                try:
                    self.responses[fileno]  =  self.q_input.get_nowait()
                except Empty:
                    gevent.sleep(0.5)
                    continue
                    #self.responses[fileno] = json.dumps({'err':'devices offline!!!'})
                debug_print('recv from worker %s' % str(self.responses[fileno]))
                self.write_sock(fileno)
                break
            debug_print('got info from devices ,exit')


                



class CameraSrv(BaseSrv):
    def __init__(self,address = ('',5560)):
        BaseSrv.__init__(self,address)
        self.q_input = dev_queue_in
        self.q_output = dev_queue_out
        print "start CameraSrv",address
        self.ltc = gevent.spawn(self.listening_to_conn)
        #self.th  = threading.Thread(target=self.listening_to_conn)
        #self.th.start()
        

    def process_cmd(self,data,fileno):
        #debug_print('parser json occuer error, sock %d,data is %s' % (fileno,data))
        jdata = self.get_json(data)
        debug_print('get json data is %s' % str(jdata))
        cmd = jdata.get(CMD,None)
        if cmd == LOGIN:
            uuid = jdata.get(UUID,None)
            pwd = jdata.get(PWD,None)
            self.q_output.put((uuid,fileno,pwd))
            self.responses[fileno] = json.dumps({RESP:'login success'})
            self.write_sock(fileno)
        elif cmd == CONN:
            #fileno = jdata.get(SOCK,None)
            #addr = jdata.get(ADDR,None)
            # 这里还要添加校验机制
            debug_print('put data  %s to worker' % str(jdata))
            self.q_output.put_nowait(jdata)
        elif cmd == KEP:
            self.responses[fileno] = json.dumps(jdata)
            self.write_sock(fileno)
        else:
            pass

    def listening_to_conn(self):
        while 1:
            try:
                d = self.q_input.get_nowait()
            except Empty:
                gevent.sleep(1)
                continue
            debug_print("get from worker %s" % str(d))
            self.responses[d[0]] = d[1]
            self.write_sock(d[0])
            gevent.sleep(0)


class EchoAddrSrv(DatagramServer):
    def handle(self,data,address):
        debug_print('via udp got addrees %s' % str(address))
        self.socket.sendto(str(address),address)

if __name__ == '__main__':
    mlist = []
    #workerproc = Process(target=worker,args=(app_queue_out,app_queue_in,dev_queue_out,dev_queue_in))
    workerproc = gevent.spawn(worker,app_queue_out,app_queue_in,dev_queue_out,dev_queue_in)
    #workerproc.start()
    app_srv = AppSrv()
    dev_srv = CameraSrv()
    devudp = EchoAddrSrv(('',5560))
    appudp = EchoAddrSrv(('',5561))
    """
    ath = threading.Thread(target=app_srv.serve_forever)
    dth = threading.Thread(target=dev_srv.serve_forever)
    duth = threading.Thread(target=devudp.serve_forever)
    auth = threading.Thread(target=appudp.serve_forever)

    mlist = [workerproc,ath,dth,duth,auth]
    [n.start() for n in mlist]


    """
    gevent.joinall([
                    workerproc,\
                    gevent.spawn(app_srv.serve_forever),\
                    gevent.spawn(dev_srv.serve_forever),\
                    gevent.spawn(devudp.serve_forever),\
                    gevent.spawn(appudp.serve_forever)
                    ])
    """
    appproc = Process(target=app_srv.serve_forever,args=())
    appproc.start()
    devproc = Process(target=dev_srv.serve_forever,args=())
    devproc.start()
    devudpp = Process(target=devudp.serve_forever,args=())
    devudpp.start()
    appudpp = Process(target=appudp.serve_forever,args=())
    appudpp.start()
    """

    print "gevent wait"
    gevent.wait()
    

    









