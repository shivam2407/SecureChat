import socket
import time
import sys
import pb_example_pb2 	# import the module created by protobuf
						# for creating messages
import subprocess    	# module for executing commands from python
						# and retrieving stdout
from thread import *    # import thread module
import argparse
import os
import base64
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

parser.add_argument("-pr", "--private-key", type=str,
                    default='destination_private_key.der',
                    help="private key of server")

parser.add_argument("-pu", "--public-key", type=str,
                    default='destination_public_key.der',
                    help="public key of server")

args = parser.parse_args() 

IP_ADDR = '127.0.0.1'	# use loopback interface
TCP_PORT = args.server_port			# TCP port of server
BUFFER_SIZE = 1024

rqst = pb_example_pb2.Request()	# create protobuf Request message
rply = pb_example_pb2.Reply()	# create protobuf Reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind((IP_ADDR, TCP_PORT))	# bind to port

sock.listen(100)			# listen with one pending connection

def sign_in(rply,server_private_key,server_public_key):
    
    # parse response message
    rply.ParseFromString(data)
    #NEED TO IMPLEMENT PROOF OF WORK
    rply.hash = ec.generate_hash(IP_ADDR+'123')
    sock.send(rply.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    encrpt = Encrypt()
    public_key_file_name = args.public_key
    r1 = os.urandom(16)
    encrypted_file_name = base64.b64encode(encrpt.asy_encrpt_key(public_key_file_name,server_public_key))
    encrypted_r1 = encrpt.asy_encrpt_key(r1,server_public_key)
    rqst.nonce_r1 = base64.b64encode(encrypted_r1)
    print encrypted_file_name
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    encrypt_r2 = bas64.b64decode(rply.nonce_r2)
    dec = Decrypt()
    r2 = dec.asyn_decrypt(encrypt_r2,client_private_key)
    password_hash = ec.generate_hash(password+salt)
    rqst.nonce_r2 = base64.b64encode(ec.asy_encrpt_key(r2,server_public_key))
    rqst.hash = base64.b64encode(password_hash)
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    recieved_r1 = dec.asyn_decrypt(base64.b64decode(rply.nonce_r1),client_private_key)
    if(recieved_r1 == r1):
        print "Seems like the server is pawned closing the connection....."
    print 'all things executed'
    return dec.asyn_decrypt(base64.b64decode(rply.secret_key),client_private_key)

def start_connection(conn,addr):
    while 1:                # process one request at a time
        data = conn.recv(BUFFER_SIZE)
        if not data: break

        print "received data..."

        rqst.ParseFromString(data)  # parse message
        print rqst.version, rqst.seqn   # print version and sequence number

        if rqst.version != 7:       # only accept version 7
            continue

        rply.version = rqst.version # use same version number for reply

        rply.seqn = rqst.seqn       # use same version number for reply
        
        server_private_key = ec.get_private_key(args.private_key)
        server_public_key = ec.get_public_key(args.public_key)
        
        if (rqst.type == pb_example_pb2.Request.SIGN): # echo request
            sign_in(rply,server_private_key,server_public_key)   # just copy payload

        if (rqst.type == pb_example_pb2.Request.RCMD):  # remote command request
            rply.payload = rqst.payload
            ##print 'Executing command: ', rqst.payload
                                                        # execute command and get stdout
            ##rply.payload = subprocess.check_output(rqst.payload, shell='True')

        conn.send(rply.SerializeToString())  # serialize response into string and send

while 1:
    conn, addr = sock.accept()	# accept connection from client
    start_new_thread(start_connection,(conn,addr))
    print 'Connection address:', addr
