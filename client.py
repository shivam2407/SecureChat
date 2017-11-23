import socket
import time
import pb_example_pb2 	# import the module created by protobuf
						# for creating messages
import argparse
import os
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
                    default='source_private_key.der',
                    help="private key of client")

parser.add_argument("-pu", "--public-key", type=str,
                    default='source_public_key.der',
                    help="public key of client")

parser.add_argument("-u", "--user", type=str,
                    default='shivam',
                    help="username of loged in user")

parser.add_argument("-sk", "--server-public-key", type=str,
                    default='destination_public_key.der',
                    help="public key of server")

args = parser.parse_args() 


IP_ADDR = '127.0.0.1'	# use loopback interface
TCP_PORT = args.server_port		# TCP port of server
BUFFER_SIZE = 1024

rqst = pb_example_pb2.Request()	# create protobuf Request message
rply = pb_example_pb2.Reply()	# create protobuf Reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP_ADDR,TCP_PORT))	# connect to server

reqno = 0				# initialize request number to 0
ec = CommonMethod()
client_private_key = ec.get_private_key(args.private_key)
client_public_key = ec.get_public_key(args.public_key)
server_public_key = ec.get_public_key(args.server_public_key)


def sign_in():
    rqst.type = pb_example_pb2.Request.SIGN
    rqst.payload = args.user
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)

    # parse response message
    rply.ParseFromString(data)
    #NEED TO IMPLEMENT PROOF OF WORK
    encrpt = Encrypt()
    public_key_file_name = args.public_key
    r1 = os.urandom(16)
    encrypted_file_name = encrpt.asy_encrpt_key(public_key_file_name,server_public_key)
    encrypted_r1 = encrpt.asy_encrpt_key(r1,server_public_key)
    rqst.nonce_r1 = encrypted_r1
    print encrypted_file_name
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    encrypt_r2 = rply.nonce_r2
    dec = Decrypt()
    r2 = dec.asyn_decrypt(encrypt_r2,client_private_key)

def request_to_talk():
    rqst.type = pb_example_pb2.Request.TALK
    rqst.username = args.user
    encrypted_msg = Encrypt()
    # get shared key from sign-in

    user_to_talk_to = raw_input("Please input user you would like to talk to")
    rqst.talk_to_user = encrypted_msg.asy_encrpt_key(user_to_talk_to,shared_key) 
    r1 = os.urandom(16)
    rqst.nonce_r1 = encrypted_msg.asy_encrpt_key(r1, shared_key) 
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    encrypted_r1 = rply.nonce_r1
    encrypted_r2 = rply.nonce_r2
    decrypted_msg = Decrypt()
    r1d = decrypted_msg.asyn_decrypt(encrypted_r1,shared_key)
    r2d = decrypted_msg.asyn_decrypt(encrypted_r2,shared_key)
    if (r1d == r1):
        rqst.type = pb_example_pb2.Request.SEND
        rqst.nonce_r2 = encrypted_r2
        sock.send(rqst.SerializeToString())
        data = sock.recv(BUFFER_SIZE)


while 1:	# send 100 requests

    rqst.version = 7		# this is arbitrary for illustration purpose
    rqst.seqn = reqno		# set sequence number

							# get request type from user
    rcmd = raw_input('Request Type (1: SIGN-IN, 2: LIST, 3: SEND, 4: LOGOUT, 5: TALK): ')
    if rcmd == 1:
    	sign_in()
    if rcmd == 5:
    request_to_talk()




    # serialize message to string
    sock.send(rqst.SerializeToString())

    # read response
    data = sock.recv(BUFFER_SIZE)

    # parse response message
    rply.ParseFromString(data)

    # print fields of response
    print "received data... ", rply.version, rply.seqn, rply.payload

sock.close() # close socket

