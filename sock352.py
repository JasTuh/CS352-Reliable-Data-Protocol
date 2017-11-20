#RIGHT CODE

import binascii
import socket as syssock
import struct
import sys

import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

import time
from Queue import *
from random import *

PROTOCOL_VERSION = 1

SYN = 0x01
FIN = 0x02
ACK = 0x04
RESET = 0x08
HAS_OPT = 0xA0

HEADER_PKT_FORMAT = "!BBBBHHLLQQLL"
STRUCT_TYPE = struct.Struct(HEADER_PKT_FORMAT)
HEADER_SIZE = 40
RECV_SIZE = 4096
WINDOW_SIZE = 5
TIMEOUT = .2

global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {} 
privateKeysHex = {} 
publicKeys = {} 
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236 

ATTRIBUTES = {'version': 0, 'flags': 1,'option':2, 'header_len': 4, 'sequence_no': 8, 'ack_no': 9, 'payload_len': 11}

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

# We initialize our underlying UDP socket here to be used in the rest of the program.
#
# @param two ports, the first being a transmitting and the second being a receiving port, for this project, they are not being used
# @return none
def init(UDPportTx,UDPportRx):

    global global_socket
    global send_port
    global recv_port

    global_socket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

    send_port = int(UDPportTx)
    recv_port = int(UDPportRx)

    if send_port < 1 or send_port > 65535:
        send_port = 27182

    if recv_port < 1 or recv_port > 65535:
        recv_port = 27182

    global_socket.bind(('', recv_port))

# read the keyfile. The result should be a private key and a keychain of
# public keys
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

# This is the class which are sending back to the client and server.
class socket:

    # Checks to see if the socket has been initialized and then defines the fields
    #
    # @param None
    # @param None
    def __init__(self):  # fill in your code here

        self.socket_open = False
        self.is_listening = False
        self.destination_hostname = None
        self.destination_port = None
        self.backlogged_connections = None
        self.outbound_queue = Queue(maxsize=WINDOW_SIZE)
        self.recv_ack_no = []
        self.sent_ack_no = []
        self.start_seq_no = 0
        self.resending_flag = False
        self.previous_seq_no = 0
        self.encrypt = False
        self.box = None

        self.binding_address = ''
        self.binding_port = recv_port

        return

    # This binds the underlying UDP socket.
    #
    # @param address of the binding, we accept a tuple which [0] has the address, [1] has the
    # @return none
    def bind(self,address):
        # NULL for Part 1
        return

    # This initiates the Two-Way handshaking system of our protocol.
    #
    # @param address is a tuple, [0] is the address we wish to connect to and [1] is the port number we want to connect to
    # @return none
    def connect(self,address, *args):
        if len(args) > 0:
            if args[0] == ENCRYPT:
                self.encrypt = True
                privateKey = privateKeys[("*", "*")]
                publicKey = publicKeys[(address[0], send_port)]
                if privateKey == None or publicKey == None:
                    print "Could not locate appropriate public and private keys."
                self.box = Box(privateKey, publicKey)
                 
 
        # Make sure self is open and global socket is initialized
        if self.socket_open or not global_socket:
            return
            
        data, sender = (None, (None, None))
        self.destination_hostname = address[0]
        self.destination_port = send_port
        options = 0
        if self.encrypt:
            options = 1
        syn_pack = STRUCT_TYPE.pack(PROTOCOL_VERSION, SYN, options, 0, HEADER_SIZE, 0, 0, 0, 0, 0, 0, 0)

        # Now we wait for a response back from the user
        while True:
            
            # We resend the packet if we have a timeout
            global_socket.sendto(syn_pack, (self.destination_hostname, self.destination_port))

            try:
                global_socket.settimeout(TIMEOUT)
                data, sender = global_socket.recvfrom(RECV_SIZE)
                # We received an ACK
                break
            except syssock.timeout:
                continue
            finally:
                global_socket.settimeout(None)

        syn_pack = STRUCT_TYPE.unpack(data)

        self.socket_open = True

        return

    # Calls receive on the underlying UDP socket and waits for a connection request from the client.
    #
    # @param backlog which is the number of connections we wish to queue. We do not worry about that for this assignment
    # @return none
    def listen(self,backlog):

        if not global_socket:
            return

        data, sender = (None, (None, None))
        self.is_listening = True
        self.backlogged_connections = Queue(maxsize=backlog)

        # Receive data from global socket
        while True:
            try:
                global_socket.settimeout(TIMEOUT)
                data, sender = global_socket.recvfrom(HEADER_SIZE)
            except syssock.timeout:
                continue
            finally:
                global_socket.settimeout(None)

            # Check the packet received
            syn_pack = STRUCT_TYPE.unpack(data)
            sender_address = sender[0]
            sender_port = sender[1]
            sender_seqno = syn_pack[8]

            # We know that this is a connection request. Add to queue
            if syn_pack[1] == SYN:
                self.backlogged_connections.put((sender, sender_seqno))

            break

        return

    # We dequeue the first connection we received then we send them a connection accept message and return a new socket object to the server
    #
    # @param none
    # @return a new socket object which the server uses to communicate to the client
    def accept(self):

        if not self.is_listening or not global_socket:
            return

        # Now that we've accepted a connection, we are no longer listening
        self.socket_open = False
        # Check backlog for pending connection requests
        this_connection = self.backlogged_connections.get()
        if this_connection is None:
            return

        self.accepted_connection = this_connection[0]
        sequence_no = randint(0, 1000)
        ack_no = this_connection[1]

        # Complete connection setup handshake
        syn_pack = STRUCT_TYPE.pack(PROTOCOL_VERSION, (SYN & ACK), 0, 0, HEADER_SIZE, 0, 0, 0, sequence_no, ack_no, 0, 0)
        global_socket.sendto(syn_pack, self.accepted_connection)

        # Create new sock352 socket, initialize it, and return it
        return_socket = socket()
        return_socket.socket_open = True
        return_socket.destination_hostname = self.accepted_connection[0]
        return_socket.destination_port = self.accepted_connection[1]
        address = (self.accepted_connection[0], self.accepted_connection[1])

        return (return_socket, address)

    # Sends FIN packets to any connection which might be inside of the queue and sets the necessary member variables false.
    #
    # @param none
    # @return none
    def close(self):   # fill in your code here

        if not global_socket:

            self.socket_open = False
            self.is_listening = False
            return

        # Close any open connections
        if self.socket_open:

            closing_connection = (self.destination_hostname, self.destination_port)
            fin_pack = STRUCT_TYPE.pack(PROTOCOL_VERSION, FIN, 0, 0, HEADER_SIZE, 0, 0, 0, 0, 0, 0, 0)
            global_socket.sendto(fin_pack, closing_connection)

            self.socket_open = False

        # Reject any pending connection requests
        while self.backlogged_connections and not self.backlogged_connections.empty():

            closing_connection = self.backlogged_connections.get()[0]

            syn_pack = STRUCT_TYPE.pack(PROTOCOL_VERSION, FIN, 0, 0, HEADER_SIZE, 0, 0, 0, 0, 0, 0, 0)
            global_socket.sendto(fin_pack, closing_connection)

        return

    # This method we accept a certain amount of bytes from the buffer we are sent and then return that back to the sender
    # so they know to resend any bytes which we might not have acceptd.
    #
    # @param
    def send(self,buffer):

        # We get a byte-stream buffer
        if not self.socket_open or not global_socket:
            return

        new_data_to_send = buffer[:4000]
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        encrypted_payload = socket_box.encrypt(new_data_to_send, nonce)
        self.start_seq_no += 1

        while True:

            data, sender = None, (None, None)
            sending_packet_type = struct.Struct("!BBBBHHLLQQLL")
            options = 1 if self.encrypt else 0
            syn_pack = STRUCT_TYPE.pack(PROTOCOL_VERSION, ACK, options, 0, HEADER_SIZE, 0, 0, 0, self.start_seq_no, 0, 0, len(encrypted_payload))

            # Append buffer data to our byte struct
            syn_pack += encrypted_payload

            bytessent = global_socket.sendto(syn_pack, (self.destination_hostname, self.destination_port))

            # Data has been sent, now we wait for an ACK
            try:
                global_socket.settimeout(1.0)
                data, sender = global_socket.recvfrom(RECV_SIZE)

                # We know we have received the ACK
                self.resending_flag = False
                self.sent_ack_no.append(self.start_seq_no)
            except syssock.timeout:
                # We did not get the ACK
                self.resending_flag = True
                continue
            finally:
                global_socket.settimeout(None)

            unpacked = STRUCT_TYPE.unpack(data)
            version_num = unpacked[ATTRIBUTES['version']]
            flag = unpacked[ATTRIBUTES['flags']]
            ack_no = unpacked[8]

            # check for ACK in recv already
            self.recv_ack_no.append(ack_no)

            if ack_no == self.start_seq_no:
                break

        return len(new_data_to_send)

    # The method which we use to handle receiving packets and directing them which come into the underlying UDP socket.
    #
    # @param the number of bytes we wish to receive.
    # @return the bytes which we receive from the UDP socket once striped of the header.
    def recv(self,nbytes):

        resend = False

        if not self.socket_open or not global_socket:
            return

        data, sender = (None, (None, None))

        try:
            # This means we got a packet.
            global_socket.settimeout(TIMEOUT)
            data, sender = global_socket.recvfrom(RECV_SIZE)
        except syssock.timeout:
                # We timed out on getting a packet from the client.
            return ""
        finally:
            global_socket.settimeout(None)

        # Get header from data received and check it to make sure
        # it is of the proper format
        header = data[:HEADER_SIZE]
        syn_pack = STRUCT_TYPE.unpack(header)
        version_num = syn_pack[ATTRIBUTES['version']]
        header_len = syn_pack[ATTRIBUTES['header_len']]
        flag = syn_pack[ATTRIBUTES['flags']]
        sequence_no = syn_pack[ATTRIBUTES['sequence_no']]
        payload_len = syn_pack[ATTRIBUTES['payload_len']]

        if sequence_no in self.recv_ack_no:
            resend = True
        else:
            self.recv_ack_no.append(sequence_no)

        data_to_return = data[HEADER_SIZE:]

        ack_no = sequence_no

        syn_pack = STRUCT_TYPE.pack(PROTOCOL_VERSION, ACK, 0, 0, HEADER_SIZE, 0, 0, 0, ack_no, 0, 0, 0)

        # Sending ACK back
        bytessent = global_socket.sendto(syn_pack, (sender[0], sender[1]))

        self.sent_ack_no.append(ack_no)
        if resend:
            return ""

        return data_to_return
