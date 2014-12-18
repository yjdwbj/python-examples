import asyncore,socket
import logging

class Server(asyncore.dispatcher):
    def __init__(self,localAddri,bufsize = 8192):
        asyncore.dispatcher.__init__(self)
        self.Clients ={}
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.bind(localAddr)
        self.listen(1)
        self.pendingPacket = []
        self.conns = {}
        self.bufsize = bufsize

        print "Start Server %s:%s" % localAddr

    def send(self,packet):
        self.pendingPacket.append(packet)

    def writeable(self):
        return True

    def handle_write(self,data):
        print "Will Sendto" ,self.rip
        self.send()

    def handle_accept(self):
        ncon,addr = self.accept()
        self.conns[ncon] = addr
        

    def handle_read(self):
        data = self.recv(8192)
        print (data)
        self.Clients[addr] = data
        if "Server" in data:
            print "Handle Server"
            for c in self.Clients:
                if 'Client' in self.Clients[c]:
                    print "Replay",addr
                    self
                    self.sendto("%s:%s" % c,addr)
                    print "Replay",c
                    self.rip = c
                    self.sendto("%s:%s" % addr,c)
                    #handle_write("%s:%s" % addr)
                    
    def handle_close(self):
        print "Stop Server"
        self.close()

    def handle_error(self):
        return
        logging.error("bad")
        logging.error(self.Clients)
        logging.error(self.pendingPacket)

    def handle_connect(self):
        pass

class HandleConns(asyncore.dispatcher):
    def __init__(self,sock,bufsize=1024):
        asyncore.dispatcher.__init__(self,sock)
        self.bufsize = bufsize
        return 
    def handle_read(self):
        data = self.recv(self.bufsize)
        if ''

Server(('',9999))
asyncore.loop(timeout=60)
