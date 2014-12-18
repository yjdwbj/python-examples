import socket
import select
import time

def Client(self):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(('',port))
    try:
        print "Trying  connect to %s:%s" % self
        sock.connect(self)
        while True:
            sock.send("hi %s" % time.time())
            data = sock.recv(1024)
            if not data:
                print "Not data from recv"
                break
            else:
                print data,("I got your msg at %s" % time.time())
            time.sleep(1)
    except:
        print "Can't connect to",self
        pass
    #print "time is",time.time()
    sock.close()
    
def Server():
    srvsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srvsocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srvsocket.bind(('',port))
    srvsocket.listen(1)
    srvsocket.setblocking(0)
    
    print "Start Server",srvsocket.getsockname()
    epoll = select.epoll()
    epoll.register(srvsocket.fileno(),select.EPOLLIN)
    response = b'Welcomei\r\n'
    
    try:
        clients = {}; requests = {} ; responses= {}
        while True:
            events = epoll.poll(1)
            for fileno,event in events:
                if fileno == srvsocket.fileno():
                    conn,addr = srvsocket.accept()
                    print "new incoming ",addr
                    conn.setblocking(0)
                    epoll.register(conn.fileno(),select.EPOLLIN)
                    clients[conn.fileno()] = conn
                    requests[conn.fileno()] = b''
                    responses[conn.fileno()] = response
                elif event & select.EPOLLIN:
                    requests[fileno] += clients[fileno].recv(1024)
                    epoll.modify(fileno,select.EPOLLOUT)
                    print(time.time())
                elif event & select.EPOLLOUT:
                    byteswritten = clients[fileno].send(responses[fileno])
                elif event & select.EPOLLHUP:
                    epoll.unregister(fileno)
                    clients[fileno].close()
                    del clients[fileno]
    finally:
        epoll.unregister(srvsocket.fileno())
        epoll.close()
        srvsocket.close()


def ConRelay(self):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    sock.bind(('',port))
    sock.connect(self)
    sock.send("Client")
    while True:
            data = sock.recv(1024)
            if not data:
                 break
            elif ":" in data:
                print data
                l = data.split(':')
                if len(l) == 2:
                    sock.send("delme")
                    sock.close()
                    time.sleep(5)
                    Client((l[0],int(l[1])))
                    break
       

port = 56789
ConRelay(('192.168.8.9',9999))
#Server()

