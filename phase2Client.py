import socket
import time
import pb_example_pb2 	# import the module created by protobuf
						# for creating messages
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

def encrypt_plaintext(symm_key,plaintext,cipher):
    print 'Encrypting plaintext...'
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)+ encryptor.finalize()
    ciphertext = base64.b64encode(ciphertext)
    return ciphertext


def request_to_talk():
	rqst.type = pb_example_pb2.Request.TALK
	rqst.username = args.user
	r1 = os.urandom(16)
	shared_key = os.urandom(16)
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv),backend = default_backend())
	user_to_talk_to = raw_input("Please input user you would like to talk to")
	usr = encrypt_plaintext(shared_key,user_to_talk_to,cipher)
	print usr
	#usr1 = base64.b64encode(usr)
	#unicode_usr = usr.encode('utf-8').strip()
	rqst.talk_to_user = usr
	r1 = os.urandom(16)
	rqst.nonce_r1 = encrypt_plaintext(shared_key,r1,cipher)
	sock.send(rqst.SerializeToString())
	

while 1:  # send 100 requests

    rqst.version = 7          # this is arbitrary for illustration purpose
    rqst.seqn = reqno         # set sequence number

                                   # get request type from user
    rcmd = raw_input('Request Type (1: SIGN-IN, 2: LIST, 3: SEND, 4: LOGOUT, 5: TALK): ')
    #if rcmd == 5:
    request_to_talk()
    '''
	    # serialize message to string
	    sock.send(rqst.SerializeToString())

	    # read response
	    data = sock.recv(BUFFER_SIZE)

	    # parse response message
	    rply.ParseFromString(data)

	    # print fields of response
	    print "received data... ", rply.version, rply.seqn, rply.payload
	'''

sock.close() # close socket