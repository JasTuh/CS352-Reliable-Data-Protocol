import binascii
import socket as syssock
import struct
import sys
import random

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

sock = None
UDPportT = None
UDPportR = None

class Flags:
    SYN, FIN, ACK, RESET, HAS_OPT = [0x01, 0x02, 0x04, 0x08, 0xA0]

def init(UDPportTx,UDPportsRx):   # initialize your UDP socket here 
    global UDPportT
    global UDPportR 
    global sock
    UDPportT = int(UDPportTx)
    UDPportR = int(UDPportsRx)
    sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    sock.settimeout(0.2)

def make_header(flags, sequence_no, ack_no, window, payload_len, checksum=0, version=0x1, protocol=0, opt_ptr=0, source_port = 0, dest_port=0):
    udpPkt_hdr_data = struct.Struct('!BBBBHHLLQQLL')
    print (version, flags, opt_ptr, protocol, 40, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len)
    return udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol, 40, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len)

def unpack_header(header):
    udpPkt_hdr_data = struct.Struct('!BBBBHHLLQQLL')
    return udpPkt_hdr_data.unpack(header)


class socket:
    def __init__(self):
#TODO discuss fields we need in our class so it doesn't become a mess 
        if not sock:
            print "Please run Sock352.init(UDPportTx, UDPportRx)"
        self.address = None
        self.backlog = 0
        self.first_sequence_no = None

    def bind(self,address):
        newAddress = (address[0], int(address[1])) #Port sent in as str so convert it
        self.address = newAddress
        sock.bind(newAddress)

    def get_header(self):
        flags = Flags.SYN
        self.first_sequence_no = random.randint(0,9999)
        ack_no = 0
        window = 20
        payload_len = 40
        header = make_header(flags, self.first_sequence_no, ack_no, window, payload_len)
        return header

    def connect_handshake(self):
        data = None
        tries = 0
        while tries < 20:
            try: 
                data = sock.recv(1024)
                break;
            except syssock.timeout:
                tries += 1
                sock.sendto(header, newAddress)
        if (tries == 20):
            return False
        (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(data)
        if (flags == (Flags.SYN | Flags.ACK)):
            print "Connection Established!"
            return True
        return False

    def connect(self,address):
        header = self.get_header()
        self.address = (address[0], int(address[1])) 
        sock.sendto(header, self.address)
        return self.connect_handshake()

    def listen(self,backlog):
        self.backlog = backlog

    def accept(self):
        sock.setblocking(1)
        (header, addr) = sock.recvfrom(1024)  # change this to your code 
        (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(header)
        self.sequence_no = random.randint(0,99999)
        replyHeader = make_header(Flags.SYN | Flags.ACK, self.sequence_no, sequence_no+1, window, 40) 
        sock.sendto(replyHeader, addr)
        return (sock, addr)
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
