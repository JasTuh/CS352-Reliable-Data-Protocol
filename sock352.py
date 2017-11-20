import binascii
import socket as syssock
import struct
import sys
import random
import math

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from
# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box


# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
#not sure why 236, represents 0xEC
global ENCRYPT = 236


publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

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

def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex 
    global publicKeys
    global privateKeys 
    
    if (filename):
        try:
            keyfile_fd = open(filename,"r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ( (len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host,port)] = keyInHex
                        privateKeys[(host,port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host,port)] = keyInHex
                        publicKeys[(host,port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception,e:
            print ( "error: opening keychain file: %s %s" % (filename,repr(e)))
    else:
            print ("error: No filename presented")             

    return (publicKeys,privateKeys)


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
        self.encrypt = False
        self.encryption = False


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
        #if sending encrypted header, should it decrpyt first?
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

    def connect(self,*args):
        header = self.get_con_header()
        if (len(args) >= 1): 
            #not quite sure if this correctly gets the host and port num
            self.address = (args[0][0], int(args[0][1])) 
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True
        if(self.encrypt):
            private_server_K = PrivateKey[(self.address[0],self.address[1])]
            public_server_K  = PublicKey(self.address[0],self.address[1])]
            
            #not sure if this is how to get the client keys, also may need to check UDPportR if UDPportT is empty
            public_client_k = PublicKey(UDPportT,self.address[1])]
            private_client_k = PrivateKey(UDPportT,self.address[1])]
            if not private_client_k:
                raise Exception("No private key found for the host and port number")

            if not public_serverK:
                raise Exception("No public key found for the host and port number")
            socket_box = Box(private_client_k, public_server_K)
            nonce = nacl.utils.random(Box.NONCE_SIZE) 

            encrypted_payload= socket_box.encrypt(header, nonce)
            
            sock.sendto(encrypted_payload, self.address)
            if not self.connect_handshake(header):
                raise Exception("Could not establish a connection with the server.")
            return True

        sock.sendto(header, self.address)
        if not self.connect_handshake(header):
            raise Exception("Could not establish a connection with the server.")
        return True 

    def listen(self,backlog):
        self.backlog = backlog

    #check if its encrypted or not
    def accept(self,*args):
        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True

        if(self.encryption):
            plaintext = sock_box.decrypt(encrypted_payload)
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
                headers.append((make_header(0, self.sequence_no, 0, 0, 63960), self.sequence_no+1)) 
            else:
                headers.append((make_header(0, self.sequence_no, 0, 0, leftover), self.sequence_no + 1)) 
        return headers

    def make_message_packets(self, headers, buffer, number_packets):
        messages = []
        for i in range(number_packets): #Construct all the packets we wish to send
            data = headers[i][0]
            message = None
            if i != (number_packets - 1):
                message = data + buffer[63960*i: 63960*(i+1)]
            else:
                message = data + buffer[63960*i:]
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
        number_packets = int(math.ceil(buffer_len/63960.0))
        headers = self.make_send_headers(number_packets, (buffer_len % 63960))
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
                        if (ack_no == headers[lowest_unacked][1]):
                            bytes_sent += 63960 if lowest_unacked < len(messages) - 1 else buffer_len % 63960
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
            if (sequence_no > self.expected_sequence_no):
                continue
            if (sequence_no < self.expected_sequence_no):
                self.expected_sequence_no = sequence_no + 1
                self.send_ack(self.expected_sequence_no, addr)
                continue
            if(flags ==Flags.FIN):
                closeHeader = make_header(Flags.FIN, self.sequence_no, self.sequence_no+1, 0, 40) 
                sock.sendto(closeHeader, addr)
                return None 
            if not recvBuf:
                resetHeader = make_header(Flags.reset, self.sequence_no, 0, 0, 40) 
                sock.sendto(resetHeader, addr)
                
            self.expected_sequence_no += 1
            if (nbytes < payload_len):
                self.info_remaining = payload_len - nbytes
                self.internal_buffer = recvBuf[nbytes:payload_len]
            buffer += recvBuf[40:40+min(nbytes,payload_len)]
            bytes_rec += min(payload_len, nbytes)
            self.send_ack(self.expected_sequence_no, addr)
        return buffer
