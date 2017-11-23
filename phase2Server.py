import socket
import time
import sys
import pb_example_pb2   # import the module created by protobuf
                        # for creating messages
import subprocess       # module for executing commands from python
                        # and retrieving stdout
from thread import *    # import thread module
import argparse
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fcrypt import CommonMethod, Encrypt, Decrypt
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import *

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number of server to connect to")

args = parser.parse_args() 

IP_ADDR = '127.0.0.1'   # use loopback interface
TCP_PORT = args.server_port         # TCP port of server
BUFFER_SIZE = 1024

rqst = pb_example_pb2.Request() # create protobuf Request message
rply = pb_example_pb2.Reply()   # create protobuf Reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#reuse the address even if it is in the TIME_WAIT state
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
sock.bind((IP_ADDR, TCP_PORT))  # bind to port

sock.listen(100)            # listen with one pending connection

def encrypt_plaintext(symm_key,plaintext,cipher):
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)+ encryptor.finalize()
    ciphertext = base64.b64encode(ciphertext)
    return ciphertext


def decrypt_ciphertext(cipher, ciphertext):
    decryptor = cipher.decryptor()
    output_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print 'Decrypting ciphertext...'
    return output_plaintext

def start_connection(conn,addr):
    shared_key = '1234567890123456'
    iv = '2345678901234567'
    r1 = '3456789012345678'
    r2 = '4567890123456789'
    cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv),backend = default_backend())
    while 1:                # process one request at a time
        data = conn.recv(BUFFER_SIZE)
        if not data: break
        rqst.ParseFromString(data)

        if rqst.type == pb_example_pb2.Request.TALK:
            nonce = base64.b64decode(rqst.nonce_r1)
            nonced = decrypt_ciphertext(cipher,nonce)
            if nonced == r1:
                usr = base64.b64decode(rqst.talk_to_user)
                usrd = decrypt_ciphertext(cipher,usr) 
                print "Received request to talk to :" , usrd
                rply.nonce_r1 = rqst.nonce_r1
                rply.nonce_r2 = encrypt_plaintext(shared_key,r2,cipher)
                conn.send(rply.SerializeToString())  # serialize response into string and send
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    break  
                rqst.ParseFromString(data)

            
        
        #print "received data..."

        #rqst.ParseFromString(data)  # parse message
        #print rqst.version, rqst.seqn , rqst.username  # print version and sequence number

        #if rqst.version != 7:       # only accept version 7
        #    continue

        #rply.version = rqst.version # use same version number for reply

        #rply.seqn = rqst.seqn       # use same version number for reply
        

while 1:
    conn, addr = sock.accept()  # accept connection from client
    start_new_thread(start_connection,(conn,addr))
    print 'Connection address:', addr
