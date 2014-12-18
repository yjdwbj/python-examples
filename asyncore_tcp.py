import asyncore,socket
import logging

class Server(asyncore.dispatcher):
    def __init__(self,localAddr):
        asyncore.dispatcher.__init__(self)
        self.Clients ={}
        self.create_socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.bind(localAddr)
        self.pendingPacket = []
        self.rip = ()
        print "Start Server %s:%s" % localAddr

    def send(self,packet):
        self.pendingPacket.append(packet)

    def writeable(self):
        return True

    def handle_write(self,data):
        print "Will Sendto" ,self.rip
        self.sendto(data,self.rip)

    def handle_read(self):
        data,addr = self.recvfrom(8192)
        print (data),(addr)
        self.Clients[addr] = data
        if "Server" in data:
            print "Handle Server"
            for c in self.Clients:
                if 'Client' in self.Clients[c]:
                    print "Replay",addr
                    self.rip = addr
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

Server(('',9999))
asyncore.loop(timeout=60)
