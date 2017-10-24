import binascii
import socket as syssock
import struct
import sys

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

socket = None
UDPportTx = None
UDPportRx = None
def init(UDPportTx,UDPportsRx):   # initialize your UDP socket here 
    socket = syssock.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPportTx = UDPportTx 
    UDPportRx = UDPportRx
class socket:
    def __init__(self):  # fill in your code here 
#TODO discuss fields we need in our class so it doesn't become a mess 
        if not socket:
            print "Please run Sock352.init(UDPportTx, UDPportRx)"
        self.address = None
        self.backlog = 0

    def bind(self,address):
        self.address = address
        socket.bind(address)

#TODO Connection handshake
    def connect(self,address):  # fill in your code here 
#TODO MAKE HEADERS using like the struct library
        sock.sendto("", address)
#TODO HANDSHAKE 
        return 
    
    def listen(self,backlog):
#TODO learn what we should do in this method
        self.backlog = backlog
        socket.listen(backlog)

    def accept(self):
        (clientsocket, address) = socket.accept()  # change this to your code 
#TODO Connection handshake
        return (clientsocket,address)
    
    
    def close(self):   # fill in your code here 
#TODO TEAR DOWN
        return 
#TODO
#-window size
#-time outs
#-handle whether somethings been acked
#-receive acks 
    def send(self,buffer):
        bytes_sent = 0     # fill in your code here 
        # not sure what to do about self.sock, part of init
        while bytes_sent < buffer:
            sent = self.sock.send(msg[bytes_sent:])  
            if sent == 0:
                raise RuntimeError("socket connection broken")
            bytes_sent = bytes_sent + sent

        return bytes_sent 

#TODO
#-window size
#-time outs
#-handle whether somethings been acked
#-receive acks 
#python struct unpack
    def recv(self,nbytes):
        bytes_rec= 0     # fill in your code here
        
        chunks = []
        
        while bytes_rec < nbytes:
            chunk = self.sock.recv(min(nbytes - bytes_recd, 2048))
            if chunk == '':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_rec = bytes_rec + len(chunk)
        return ''.join(chunks)
