import binascii
import socket as syssock
import struct
import sys
import random
import math

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
        self.sequence_no = None
        self.expected_sequence_no = None
        self.info_remaining = 0
        self.internal_buffer = None

    def bind(self,address):
        newAddress = (address[0], int(address[1])) #Port sent in as str so convert it
        self.address = newAddress
        sock.bind(newAddress)

    def get_con_header(self):
        flags = Flags.SYN
        self.sequence_no = random.randint(0,9999)
        ack_no = 0
        window = 20
        payload_len = 40
        header = make_header(flags, self.sequence_no, ack_no, window, payload_len)
        return header

    def connect_handshake(self, header):
        data = None
        tries = 0
        while tries < 20:
            try: 
                data = sock.recv(1024)
                break;
            except syssock.timeout:
                tries += 1
                sock.sendto(header, self.address)
        if (tries == 20):
            return False
        (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(data)
        if (flags == (Flags.SYN | Flags.ACK)):
            print "Connection Established!"
            return True
        return False

    def connect(self,address):
        header = self.get_con_header()
        self.address = (address[0], int(address[1])) 
        sock.sendto(header, self.address)
        if not self.connect_handshake(header):
            raise Exception("Could not establish a connection with the server.")
        return True 
    def listen(self,backlog):
        self.backlog = backlog

    def accept(self):
        sock.setblocking(1)
        (header, addr) = sock.recvfrom(1024)
        (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(header)
        self.sequence_no = random.randint(0,99999)
        replyHeader = make_header(Flags.SYN | Flags.ACK, self.sequence_no, sequence_no+1, window, 40) 
        self.expected_sequence_no = sequence_no + 1
        sock.sendto(replyHeader, addr)
        return (self, addr)
    def close(self):   # fill in your code here 
#TODO TEAR DOWN
        return 
#TODO
#-window size
#-time outs
#-handle whether somethings been acked
#-receive acks 
    def make_send_headers(self, num_packets, leftover):
        headers = []
        for x in range(1,num_packets+1):
            self.sequence_no += 1
            if (x != num_packets):
                headers.append(make_header(0, self.sequence_no, 0, 0, 63960)) 
            else:
                headers.append(make_header(0, self.sequence_no, 0, 0, leftover)) 
        return headers
    def send(self,buffer):
        buffer_len = len(buffer)
        number_packets = int(math.ceil(buffer_len/63960.0))
        lowest_unacked = self.sequence_no
        headers = self.make_send_headers(number_packets, (buffer_len % 63960))
        window_size = 10
        bytes_sent = 0
        unacked = 0
        for i in range(number_packets):
            data = headers[i]
            message = None
            if i != (number_packets - 1):
                message = data + buffer[63960*i: 63960*(i+1)]
                bytes_sent += 63960
            else:
                message = data + buffer[63960*i:]
                bytes_sent += buffer_len % 63960
            sock.sendto(message, self.address)
            while True:
                try:
                    reply_header_bin = sock.recv(40) 
                    (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(reply_header_bin)
                    if (ack_no == (self.sequence_no - number_packets + i + 2)):
                        break
                except syssock.timeout:
                    sock.sendto(data, self.address)
        return bytes_sent 

    def send_ack(self, seq_no, addr):
        replyHeader = make_header(Flags.ACK, self.sequence_no, seq_no, 20, 40) 
        sock.sendto(replyHeader, addr)

    def recv(self,nbytes):
        bytes_rec = 0     # fill in your code here
        buffer = ""
        if (self.info_remaining > 0):
            toRead = min(self.info_remaining, nbytes)
            buffer += self.internal_buffer[:toRead] 
            nbytes -= toRead
            bytes_rec += toRead
            self.info_remaining -= toRead
            self.internal_buffer = self.internal_buffer[toRead:]
        while (bytes_rec < nbytes):
            (recvBuf, addr) = sock.recvfrom(16384)
            (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(recvBuf[:40])
            if (sequence_no != self.expected_sequence_no):
                continue
            self.expected_sequence_no += 1
            if (nbytes < payload_len):
                self.info_remaining = payload_len - nbytes
                self.internal_buffer = recvBuf[nbytes:payload_len]
            buffer += recvBuf[40:40+min(nbytes,payload_len)]
            bytes_rec += min(payload_len, nbytes)
            self.send_ack(self.expected_sequence_no, addr)
        return buffer
