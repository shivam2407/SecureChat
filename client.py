import socket
import time
import pb_example_pb2 	# import the module created by protobuf
						# for creating messages
import argparse
import os
import base64
import sqlite3
import pyDH
from thread import *    # import thread module
import sys
import select
from thread import *
import threading
from fcrypt import CommonMethod, Encrypt, Decrypt
from phase_1 import Phase_1
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import *
from thread import * 


parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
                    default=9090,
                    help="port number of server to connect to")

parser.add_argument("-ip", "--ip-addr", type=str,
                    default='127.0.0.1',
                    help="ip address of server")

parser.add_argument("-pass", "--password", type=str,
                    help="password of user")

parser.add_argument("-pr", "--private-key", type=str,
                    default='source_private_key.der',
                    help="private key of client")

parser.add_argument("-pu", "--public-key", type=str,
                    default='source_public_key.der',
                    help="public key of client")

parser.add_argument("-u", "--user", type=str,
                    help="username of loged in user")

parser.add_argument("-sk", "--server-public-key", type=str,
                    default='destination_public_key.der',
                    help="public key of server")

args = parser.parse_args() 

IP_ADDR = args.ip_addr
TCP_PORT = args.server_port		# TCP port of server
BUFFER_SIZE = 4098

TIMEOUT = 5
used_ports = []
RANDOM = os.urandom(16)

rqst = pb_example_pb2.Request()	# create protobuf Request message
rply = pb_example_pb2.Reply()	# create protobuf Reply message
talk_rqst = pb_example_pb2.talk_request() #create protobuf talk_request message0
talk_rply = pb_example_pb2.talk_reply() #create protobuf talk_reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP_ADDR,TCP_PORT))
reqno = 0				# initialize request number to 0
ec = CommonMethod()
client_private_key = ec.get_private_key(args.private_key)
client_public_key = ec.get_public_key(args.public_key)
server_public_key = ec.get_public_key(args.server_public_key)
try:
    user_password = args.password
except Exception:
    print "Provide user password"
    exit()
salt = str(123)

def sign_in():
    print 'inside sign in'
    rqst.type = pb_example_pb2.Request.SIGN
    try:
        rqst.payload = args.user
    except Exception:
        print "Provide username please"
        exit()
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    print 'first meessage sent'
    # parse response message
    rply.ParseFromString(data)
    #NEED TO IMPLEMENT PROOF OF WORK
    encrpt = Encrypt()
    public_key_file_name = args.public_key
    r1 = os.urandom(16)
    print 'The r1 is '+r1
    encrypted_file_name = base64.b64encode(encrpt.asy_encrpt_key(public_key_file_name,server_public_key))
    encrypted_r1 = encrpt.asy_encrpt_key(r1,server_public_key)
    rqst.nonce_r1 = base64.b64encode(encrypted_r1)
    rqst.payload = encrypted_file_name
    #print encrypted_file_name
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    encrypt_r2 = base64.b64decode(rply.nonce_r2)
    dec = Decrypt()
    r2 = dec.asyn_decrypt(encrypt_r2,client_private_key)
    password_hash = ec.generate_hash(user_password+salt)
    print 'The hash is '+password_hash
    rqst.nonce_r2 = base64.b64encode(encrpt.asy_encrpt_key(r2,server_public_key))
    rqst.hash = base64.b64encode(encrpt.asy_encrpt_key(password_hash,server_public_key))
    print 'sending password hash'
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    if not rply.sign_in_success:
        print 'Please check your username or password'
        exit()
    recieved_r1 = dec.asyn_decrypt(base64.b64decode(rply.nonce_r1),client_private_key)
    if(recieved_r1 != r1):
        print "Seems like the server is pawned closing the connection....."
    print 'all things executed'
    key = dec.asyn_decrypt(base64.b64decode(rply.secret_key),client_private_key)
    key_salt = dec.asyn_decrypt(base64.b64decode(rply.key_salt),client_private_key)
    ran = rply.udp_port
    return (key, key_salt,ran)

def logout(symetric_key,key_salt,rply):
    cipher_r1 = base64.b64decode(rply.nonce_r1)
    cipher_r2 = base64.b64decode(rply.nonce_r2)
    recieved_r1 = Decrypt().decrypt_message(cipher_r1,symetric_key,key_salt)
    recieved_r2 = Decrypt().decrypt_message(cipher_r2,symetric_key,key_salt)
    rqst.nonce_r2 = base64.b64encode(Encrypt().encrypt(recieved_r2,symetric_key,key_salt))
    if recieved_r1 != r1:
        print 'Logout was not successfull'
        return 102
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    cipher_r1 = base64.b64decode(rply.nonce_r1)
    recieved_r1 = Decrypt().decrypt_message(cipher_r1,symetric_key,key_salt)
    if recieved_r1 != r1 and not rply.logout_success:
        print 'Logout was not successfull'
        return 102

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

   
def request_to_talk(rply):
    
    # print 'Data sent to server'
    # try:
    # 	data = sock.recv(BUFFER_SIZE)
    # except Exception as e:
    # 	print e
    
    # print 'Data received from server'
    # rply.ParseFromString(data)
	print 'In request to talk'
	username = args.user
	print 'The username is ' + username
	sqlconn = sqlite3.connect("db.sqlite")
	c = sqlconn.cursor()
	sql = 'SELECT * from active_users where name = ?'
	c.execute(sql,(username,))
	data = c.fetchone()
	shared_key = base64.b64decode(data[1])
	iv = base64.b64decode(data[3])
	r1 = RANDOM
	nonce = base64.b64decode(rply.nonce_r1)
	nonced = Decrypt.decrypt_message(nonce,shared_key,iv)
	if nonced == r1:
	    rply.nonce_r2 = rply.nonce_r2
	    sock.send(rply.SerializeToString())
	    data = sock.recv(BUFFER_SIZE)
	    print 'Received data'
	    talk_to_another_client(data,iv,shared_key,username,user_to_talk_to)
	else:
	  	print "Nonces don't match. System exiting."
	   	exit()


def sign_message(sender_privkey,plaintext):
	try:
		private_key = CommonMethod.get_private_key(sender_privkey)
	except:
		print 'Error in reading file'
	try:
		signature = private_key.sign(
			plaintext,
			padding.PSS(
				mgf = padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256()
			)
		return signature
	except Exception as e:
		print 'Error in signing message' + str(e)

def talk_to_another_client(data,iv,shared_key,username,user_to_talk_to):
	rply.ParseFromString(data)
	cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv),backend = default_backend())
	pku2 = Decrypt.decrypt_message(base64.b64decode(rply.public_key_u2),shared_key,iv)
	print 'Public key of U2'
	print pku2
	print 'In talk to another client'
	pku1_ticket = Decrypt.decrypt_message(base64.b64decode(rply.public_key_u1),shared_key,iv)
	u1_ticket = Decrypt.decrypt_message(base64.b64decode(rply.username),shared_key,iv)
	d1 = pyDH.DiffieHellman()
	d1_pubkey = d1.gen_public_key()
	print "Diffie Hellman Component is: "
	d1_pubkey = (str(d1_pubkey)).encode()
	print d1_pubkey
	private_key_file = username + '_private_key.pem'
	print private_key_file
	signed_dh_component = sign_message(private_key_file,d1_pubkey)
	print 'Signing message succesful'
	print 'Encrypted DH component is: '
	r1 = os.urandom(16)
	sqlconn = sqlite3.connect("db.sqlite")
	c = sqlconn.cursor()
	sql = "SELECT port,ip from active_users where name = ?"
	c.execute(sql,(user_to_talk_to,))
	result = c.fetchone()
	port = result[0]
	print 'Port is '
	print port
	# port = str(port).encode('utf-8')
	port = int(port)
	ip = result[1]
	print 'IP address is'
	print ip
	ip = ip.encode('utf-8')
	if port is None:
		print 'Port is not present'
		exit()
	if ip is None:
		print 'IP is not present'
		exit()
	rply.username = username
	print 'Done executing talk to another client'
	udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	udp_sock.sendto(rply.SerializeToString(),(ip,port))
	print 'Message sent from client 1'

	# encrypted_r1 = Encrypt.asy_encrpt_key(r1,pku2)
	# print 'Encrypted r1 successfully'
	# encrypted_r1 = encrypt_plaintext(pku2,r1,cipher)
	# encrypted_u1 = encrypt_plaintext(pku2,username,cipher)
	# talk_rqst.username = encrypted_u1
	# talk_rqst.nonce = encrypted_r1
	# talk_rqst.public_key = base64.b64encode(pku1_ticket).decode('utf-8')
	# talk_rqst.ticket_username = base64.b64encode(u1_ticket).decode('utf-8')
	# talk_rqst.dh_component = encrypted_dh_component
	# print 'Message set to send'
	# sock.sendto(talk_rqst.SerializeToString(),(IP_ADDR,port))
	# print 'Messa
    



# def listen_on_client(sock,any):
# 	while 1:
# 		# data = sock.recv(BUFFER_SIZE)

		# talk_rqst.ParseFromString(data)
  #   	print 'Woohoo!! Data received'
  #   	print data


def listen_to_connections(sock,any,rply):
	print 'Started new thread for listening'
	data = sock.recv(BUFFER_SIZE)
	if data:
		print 'Data received'
		rply.ParseFromString(data)
		if rply.type == pb_example_pb2.Reply.TALK:
			request_to_talk(rply)
        if rply.type == pb_example_pb2.Reply.LOGOUT:
            logout(symetric_key,salt_for_key,rply)
            print "The logout was successfull"
            exit()

def chat_with_client(sock,any):
	print 'In chat with client'
	data = sock.recvfrom(BUFFER_SIZE)
	if data:
		print 'Data received in chat_with_client'
		print data






if __name__ == '__main__':
    print 'Sending for proof of work'
    rqst.type = pb_example_pb2.Request.POF_1
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    hash_recieved = base64.b64decode(rply.hash)
    ip = rply.ip
    port = rply.port
    print "Recieved Hash secret"
    sec = Phase_1.find_secret(hash_recieved,ip+port)
    rqst.payload = str(sec)
    print "Sending the found secret"
    sock.close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_ADDR,TCP_PORT))    # connect to server
    rqst.type = pb_example_pb2.Request.POF_2
    rqst.ip = ip
    rqst.port = port
    sock.send(rqst.SerializeToString())
    print "Waiting for server response"
    data = sock.recv(BUFFER_SIZE)
    print "Reply recieved"
    rply.ParseFromString(data)
    if not rply.pof_success:
        print "Wrong guess of secret"
        exit()
    print 'going to sign_in'
    symetric_key, salt_for_key,random_port = sign_in()
    udp_sock_talk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_sock_talk.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    udp_sock_talk.bind(('',random_port))
    print 'Random port is :'
    print random_port
    print 'The shared secret key is '+symetric_key
    print 'The salt for the key is '+salt_for_key
    start_new_thread(listen_to_connections,(sock,32,rply))
    start_new_thread(chat_with_client,(udp_sock_talk,32))

    while  1:
    	

        # rqst.version = 7		# this is arbitrary for illustration purpose
        # rqst.seqn = reqno		# set sequence number
        
            rcmd = raw_input('Request Type (1: SIGN-IN, 2: LIST, 3: SEND, 4: LOGOUT, 5: TALK): ')
            if rcmd == '5':
	            username = args.user
	            print 'The username is ' + username
	            sqlconn = sqlite3.connect("db.sqlite")
	            c = sqlconn.cursor()
	            sql = 'SELECT * from active_users where name = ?'
	            c.execute(sql,(username,))
	            data = c.fetchone()
	            if data is None:
	                print "User %s is not signed-in. Please sign in to talk." %username
	            else:
	                sqlconn = sqlite3.connect("db.sqlite")
	                c = sqlconn.cursor()
	                sql = 'SELECT public_key from user_public_key where name = ?'
	                c.execute(sql,(username,))
	                key = c.fetchone()
	                if key is None:
	                    print "No record exits"
	                else:
	                    print key
	                shared_key = base64.b64decode(data[1])
                    iv = base64.b64decode(data[3])
                    rqst.type = pb_example_pb2.Request.TALK
                    rqst.username = username
                    user_to_talk_to = raw_input("Please input user you would like to talk to")
                    usr = base64.b64encode(Encrypt.encrypt(user_to_talk_to,shared_key,iv))
                    print 'Encrypted user successfully'
                    rqst.talk_to_user = usr
                    r1 = RANDOM
                    rqst.nonce_r1 = base64.b64encode(Encrypt.encrypt(r1,shared_key,iv))
                    sock.send(rqst.SerializeToString())
                    print 'Data sent to server, in main'
                            # request_to_talk(data,username)

            if rcmd == '4':
                rqst.type = pb_example_pb2.Request.LOGOUT
                r1 = os.urandom(16)
                rqst.nonce_r1 = base64.b64encode(Encrypt().encrypt(r1,symetric_key,salt_for_key))
                print 'The encrypted nonce is '+rqst.nonce_r1
                sock.send(rqst.SerializeToString())
	        print "received data... ", rply.version, rply.seqn, rply.payload
		#print 'Message reived from client'
     
    print 'socket is closed'
    sock.close() # close socket

