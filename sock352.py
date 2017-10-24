
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
def init(UDPportTx,UDPportRx):   # initialize your UDP socket here 
    socket = syssock.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDPportTx = UDPportTx 
    UDPportRx = UDPportRx
class socket:
    def __init__(self):  # fill in your code here 
        if not socket:
            print "Please run Sock352.init(UDPportTx, UDPportRx)"
        self.address = None
        self.backlog = 0

    def bind(self,address):
        self.address = address
        socket.bind(address)

#TODO Connection handshake
    def connect(self,address):  # fill in your code here 
        return 
    
    def listen(self,backlog):
        self.backlog = backlog
        socket.listen(backlog)

#TODO Connection handshake
    def accept(self):
        (clientsocket, address) = socket.accept()  # change this to your code 
        return (clientsocket,address)
    
    def close(self):   # fill in your code here 
        return 

    def send(self,buffer):
        bytessent = 0     # fill in your code here 
        return bytesent 

    def recv(self,nbytes):
        bytesreceived = 0     # fill in your code here
        return bytesreceived 
