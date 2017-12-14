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

    '''
    get_con_header returns a correctly formatted header for initiating connections
    '''
    def get_con_header(self):
        flags = Flags.SYN
        self.sequence_no = random.randint(0,9999)
        ack_no = 0
        payload_len = 40
        header = make_header(flags, self.sequence_no, ack_no, 0, payload_len)
        return header

    '''
    connect_handshake tries to receive a response from the server
    in regards to the connection request that was sent.
    It will try to connect to the server up to 20 times and if it succeeds
    it will return true otherwise it will return false
    '''
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

    def close(self):
        closeHeader = make_header(Flags.FIN, self.sequence_no, self.sequence_no+1, 0, 40) 
        sock.sendto(closeHeader, self.address)
        return 
    
    '''
    make_send_headers takes in the amount of packets to be sent, and the amount of data 
    in the last packet since that may be less than the max UDP packet size and returns a list
    containing tuples which are of the form (header for the nth packet, expected return sequence no)
    '''
    def make_send_headers(self, num_packets, leftover):
        headers = []
        for x in range(1,num_packets+1):
            self.sequence_no += 1
            if (x != num_packets):
                headers.append((make_header(0, self.sequence_no, 0, 0, 30000), self.sequence_no+1)) 
            else:
                headers.append((make_header(0, self.sequence_no, 0, 0, leftover), self.sequence_no + 1)) 
        return headers

    def make_message_packets(self, headers, buffer, number_packets):
        messages = []
        for i in range(number_packets): #Construct all the packets we wish to send
            data = headers[i][0]
            message = None
            if i != (number_packets - 1):
                message = data + buffer[30000*i: 30000*(i+1)]
            else:
                message = data + buffer[30000*i:]
            messages.append(message)
        return messages

    def resend_window(self, messages, messages_sent, lowest_unacked):
        sock.sendto(messages[lowest_unacked], self.address)
        if lowest_unacked + 1 < len(messages) and messages_sent[lowest_unacked + 1]:
            sock.sendto(messages[lowest_unacked + 1], self.address)
        if lowest_unacked + 2 < len(messages) and messages_sent[lowest_unacked + 2]:
            sock.sendto(messages[lowest_unacked + 2], self.address)

    def send(self,buffer):
        #First we must construct the message packets to send
        buffer_len = len(buffer)
        number_packets = int(math.ceil(buffer_len/30000.0))
        headers = self.make_send_headers(number_packets, (buffer_len % 30000))
        messages = self.make_message_packets(headers, buffer, number_packets)
        messages_sent = [False] * len(messages)
        
        #Now we must start to send the packets we constructed
        bytes_sent= 0
        unacked = 0
        lowest_unacked = 0
        window_size = 3 
        for i in range(len(messages)):
            sock.sendto(messages[i], self.address)
            messages_sent[i] = True
            unacked += 1
            if unacked > window_size or i == len(messages) - 1:
                while unacked != 0:
                    try:
                        sock.settimeout(0.2)
                        reply_header_bin = sock.recv(40) 
                        (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(reply_header_bin)
                        if (flags == Flags.FIN):
                            break
                        if (ack_no == headers[lowest_unacked][1]):
                            bytes_sent += 30000 if lowest_unacked < len(messages) - 1 else buffer_len % 30000
                            lowest_unacked += 1
                            unacked -= 1
                        else:
                            self.resend_window(messages, messages_sent, lowest_unacked)
                    except syssock.timeout:
                        self.resend_window(messages, messages_sent,  lowest_unacked)
                        
        return bytes_sent

    def send_ack(self, seq_no, addr):
        replyHeader = make_header(Flags.ACK, self.sequence_no, seq_no, 20, 40) 
        sock.sendto(replyHeader, addr)
    def recv(self,nbytes):
        bytes_rec = 0
        buffer = ""
        if (self.info_remaining > 0):
            toRead = min(self.info_remaining, nbytes)
            buffer += self.internal_buffer[:toRead] 
            bytes_rec += toRead
            self.info_remaining -= toRead
            self.internal_buffer = self.internal_buffer[toRead:]
        while (bytes_rec < nbytes):
            (recvBuf, addr) = sock.recvfrom(32768)
            (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len) = unpack_header(recvBuf[:40])
            if (sequence_no > self.expected_sequence_no):
                continue
            if (sequence_no < self.expected_sequence_no):
                self.send_ack(sequence_no + 1, addr)
                continue
            if (flags == Flags.FIN):
                closeHeader = make_header(Flags.FIN, self.sequence_no, self.sequence_no+1, 0, 40) 
                sock.sendto(closeHeader, addr)
                return None 
            if not recvBuf:
                resetHeader = make_header(Flags.reset, self.sequence_no, 0, 0, 40) 
                sock.sendto(resetHeader, addr)
                
            self.expected_sequence_no += 1
            leftToRead = nbytes - bytes_rec
            if (leftToRead < payload_len):
                buffer += recvBuf[40:40+leftToRead]
                self.info_remaining = payload_len - leftToRead 
                self.internal_buffer = recvBuf[leftToRead+40:]
                self.send_ack(self.expected_sequence_no, addr)
                return buffer
            buffer += recvBuf[40:]
            bytes_rec += payload_len
            self.send_ack(self.expected_sequence_no, addr)
        return buffer
