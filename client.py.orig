import socket
import time
import pb_example_pb2  # import the module created by protobuf
# for creating messages
import argparse
import os
import base64
import sqlite3
import pyDH
from thread import *  # import thread module
import sys
import select
import threading
from fcrypt import CommonMethod, Encrypt, Decrypt
from phase_1 import Phase_1
import random
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
                    help="port number of server to connect to")

parser.add_argument("-ip", "--ip-addr", type=str,
                    help="ip address of server")

parser.add_argument("-pass", "--password", type=str,
                    help="password of user")

parser.add_argument("-pr", "--private-key", type=str,
                    help="private key of client")

parser.add_argument("-pu", "--public-key", type=str,
                    help="public key of client")

parser.add_argument("-u", "--user", type=str,
                    help="username of loged in user")

parser.add_argument("-sk", "--server-public-key", type=str,
                    help="public key of server")

args = parser.parse_args()

IP_ADDR = args.ip_addr
TCP_PORT = args.server_port  # TCP port of server
BUFFER_SIZE = 4098

TIMEOUT = 5
used_ports = []
RANDOM = os.urandom(16)
<<<<<<< HEAD
Loged_in = True
rqst = pb_example_pb2.Request()	# create protobuf Request message
rply = pb_example_pb2.Reply()	# create protobuf Reply message
talk_rqst = pb_example_pb2.talk_request() #create protobuf talk_request message0
talk_rply = pb_example_pb2.talk_reply() #create protobuf talk_reply message
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_ADDR,TCP_PORT))
    print "Connected"
except Exception:
    print "----Eitheryour format is wrong or server is done check you format from below template------"
    print "Format is :"
    print "python client.py -u Username -pass Password -ip IP -p Port -pr Private_Key -pu public_key -sk server_public_key"
    exit()
reqno = 0				# initialize request number to 0
ec = CommonMethod()
try:
    client_private_key = ec.get_private_key(args.private_key)
    client_public_key = ec.get_public_key(args.public_key)
    server_public_key = ec.get_public_key(args.server_public_key)
except Exception:
    print "Format is :"
    print "python client.py -u Username -pass Password -ip IP -p Port -pr Private_Key -pu public_key -sk server_public_key"
    exit()
symetric_key = ''
salt_for_key = ''
=======
USER1 = ''
USER2 = ''
dh1_obj = pyDH.DiffieHellman()
dh2_obj = pyDH.DiffieHellman()
global R1 
R1 = os.urandom(16)
global R2 
R2 = os.urandom(16)
rqst = pb_example_pb2.Request()  # create protobuf Request message
rply = pb_example_pb2.Reply()  # create protobuf Reply message
talk_rqst = pb_example_pb2.talk_request()  # create protobuf talk_request message0
talk_rply = pb_example_pb2.talk_reply()  # create protobuf talk_reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP_ADDR, TCP_PORT))
reqno = 0  # initialize request number to 0
ec = CommonMethod()
client_private_key = ec.get_private_key(args.private_key)
client_public_key = ec.get_public_key(args.public_key)
server_public_key = ec.get_public_key(args.server_public_key)
symetric_key = ''
salt_for_key = ''
global dh_shared_key_u1 
global dh_shared_key_u2 
>>>>>>> 19b85d48288c23537b1e424f8d9ed6b3339b6bb3
try:
    user_password = args.password
except Exception:
    print "Format is :"
    print "python client.py -u Username -pass Password -ip IP -p Port -pr Private_Key -pu public_key -sk server_public_key"
    exit()


def sign_in():
    #try:
        encrpt = Encrypt()
        #print 'inside sign in'
        rqst.type = pb_example_pb2.Request.SIGN
        try:
            #Here the payload will have username encrypted
            rqst.payload = base64.b64encode(encrpt.asy_encrpt_key(args.user,server_public_key))
        except Exception:
            print "Provide username please"
            exit()
        sock.send(rqst.SerializeToString())
        #print 'first meessage sent'
        # 
        public_key_file_name = args.public_key
        r1 = os.urandom(16)
        #print 'The r1 is '+r1
        encrypted_file_name = base64.b64encode(encrpt.asy_encrpt_key(public_key_file_name,server_public_key))
        encrypted_r1 = encrpt.asy_encrpt_key(r1,server_public_key)
        rqst.nonce_r1 = base64.b64encode(encrypted_r1)
        #Here payload will have encrypted public key file name of user
        rqst.payload = encrypted_file_name
        #print encrypted_file_name
        sock.send(rqst.SerializeToString())
        data = sock.recv(BUFFER_SIZE)
        rply.ParseFromString(data)
        #Recieved nonce r2 from server
        encrypt_r2 = base64.b64decode(rply.nonce_r2)
        dec = Decrypt()
        r2 = dec.asyn_decrypt(encrypt_r2,client_private_key)
        #Recieved salt for computing hash from password and salt combination. 
        salt = dec.asyn_decrypt(base64.b64decode(rply.payload),client_private_key)
        password_hash = ec.generate_hash(user_password+salt)
        #print 'The hash is '+password_hash
        rqst.nonce_r2 = base64.b64encode(encrpt.asy_encrpt_key(r2,server_public_key))
        #Sending password hash
        rqst.hash = base64.b64encode(encrpt.asy_encrpt_key(password_hash,server_public_key))
        print 'sending password hash'
        sock.send(rqst.SerializeToString())
        data = sock.recv(BUFFER_SIZE)
        rply.ParseFromString(data)
        #if server sends a True value for sign_in_sucees than proceed or else stop
        if not rply.sign_in_success:
            print 'Please check your username or password'
            exit()
        recieved_r1 = dec.asyn_decrypt(base64.b64decode(rply.nonce_r1),client_private_key)
        if(recieved_r1 != r1):
            print "Seems like the server is pawned closing the connection....."
        #print 'all things executed'
        #Server sent shared_key, salt  for this session and port for making a small UDP server for p2p connection.
        key = dec.asyn_decrypt(base64.b64decode(rply.secret_key),client_private_key)
        key_salt = dec.asyn_decrypt(base64.b64decode(rply.key_salt),client_private_key)
        ran = rply.udp_port
        return (key, key_salt,ran)
    #except Exception:
    #    print "Looks like server is down right now please try after some time"
    #    exit()

def logout(symetric_key,key_salt,rply):
    try:
        #Recieved r1 and r2    
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
        #This method is only to notigy user that complete logout was not completed
        #but we are not taking any steps to ensure that proper logout occurs in ideal 
        #implementation we will do that.
        if recieved_r1 != r1 and not rply.logout_success:
            print 'Logout was not successfull'
            return 102
    except Exception:
<<<<<<< HEAD
        print "Looks like server is down right now please try after some time"
        exit()



def list(symetric_key,key_salt,rply):
    try:
        cipher_r1 = base64.b64decode(rply.nonce_r1)
        cipher_r2 = base64.b64decode(rply.nonce_r2)
        recieved_r1 = Decrypt().decrypt_message(cipher_r1,symetric_key,key_salt)
        recieved_r2 = Decrypt().decrypt_message(cipher_r2,symetric_key,key_salt)
        """
        To make logout and list protocol different in list we will send nonce recieved from each other 
        decremented by 1. Whereas in logout we are just sending the same nonce back.
        """
        rqst.nonce_r2 = base64.b64encode(Encrypt().encrypt(str(int(recieved_r2)-1),symetric_key,key_salt))
        rqst.nonce_r1 = base64.b64encode(Encrypt().encrypt(str(int(recieved_r1)-1),symetric_key,salt_for_key))
        #print "The first nonce is "+str(r1)
        #print "The second nonce send to server list is "
        #print str(int(recieved_r1)-1)
        if int(recieved_r1) != int(r1)-1:
            print 'List was not successfull'
            return 102
        sock.send(rqst.SerializeToString())
        data = sock.recv(BUFFER_SIZE)
        rply.ParseFromString(data)
        cipher_r1 = base64.b64decode(rply.nonce_r1)
        recieved_r1 = Decrypt().decrypt_message(cipher_r1,symetric_key,key_salt)
        #print "Recieved nonce r1 is list "+recieved_r1
        if int(recieved_r1) != int(r1)-3 :
            print 'Looks like some one changed the list of user'
            return 102
        else:
            """
            Here payload have currently loged in users
            """
            print Decrypt().decrypt_message(base64.b64decode(rply.payload),symetric_key,key_salt)
    except Exception:
        print "Looks like server is down right now please try after some time"
        exit()




def listen_to_connections(sock,any,rply,symetric_key, salt_for_key,):
    #print 'Started new thread for listening'
    try:
        while 1:
            data = sock.recv(BUFFER_SIZE)
            #print "recieved empty data"
            if data:
                #print 'Data received'
                rply.ParseFromString(data)
                if rply.type == pb_example_pb2.Reply.TALK:
                    #print "Recieved message for talk from server"
                    request_to_talk(rply)
                if rply.type == pb_example_pb2.Reply.LOGOUT:
                    #print "Going for logout"
                    logout(symetric_key,salt_for_key,rply)
                    print "The logout was successfull. Enter 3 to exit"
                    Loged_in = False
                    exit()
                if rply.type == pb_example_pb2.Reply.LIST:
                    #print "Inside list now"
                    list(symetric_key,salt_for_key,rply)
            #print "Outside list now"
    except Exception:
        print "Looks like server is down right now please try after some time"
        exit()
        



if __name__ == '__main__':
    #print 'Sending for proof of work'
    """
    Here User will first initiate coonection with message type POF_1
    Then it will find a sec for hash it recieved from server and once it
    finds the sec it will send the secret to server with message type POF_2
    and then intiate the sign_in process. 
    """
    try:
        rqst.type = pb_example_pb2.Request.POF_1
        sock.send(rqst.SerializeToString())
        data = sock.recv(BUFFER_SIZE)
        rply.ParseFromString(data)
        #Receves hash and IP and port using which user will find secret
        hash_recieved = base64.b64decode(rply.hash)
        ip = rply.ip
        port = rply.port
        #print "Recieved Hash secret"
        #Finding secret using method in phase_1.py file
        sec = Phase_1.find_secret(hash_recieved,ip+port)
        rqst.payload = str(sec)
        #print "Sending the found secret"
        sock.close()
        #New Connection is established as previous one will be closed.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((IP_ADDR,TCP_PORT))    # connect to server
        rqst.type = pb_example_pb2.Request.POF_2
        rqst.ip = ip
        rqst.port = port
        sock.send(rqst.SerializeToString())
        #print "Waiting for server response"
        data = sock.recv(BUFFER_SIZE)
        #print "Reply recieved"
        rply.ParseFromString(data)
        #IF reply from server says it's successfull than only user will go to sign_in
        if not rply.pof_success:
            print "Wrong guess of secret"
            exit()
        #print 'going to sign_in'
        symetric_key, salt_for_key,random_port = sign_in()
        #Making udp socket for inter client communication.
        udp_sock_talk = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        udp_sock_talk.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        udp_sock_talk.bind(('',random_port))
        #print 'Random port is :'
        #print random_port
        #print 'The shared secret key is '+symetric_key
        #print 'The salt for the key is '+salt_for_key
        #This thread will listen to traffic from server
        start_new_thread(listen_to_connections,(sock,32,rply,symetric_key, salt_for_key))
        #This thread will listen to traffic from peers
        while  1:
        	
                rcmd = raw_input('Request Type ( 1: LIST, 2: LOGOUT,): ')
                if rcmd == '1':
                    rqst.type = pb_example_pb2.Request.LIST
                    r1 = random.SystemRandom().randint(1,1000000000000000000)
                    #print "The r1 for list is "+ str(r1)
                    rqst.nonce_r1 = base64.b64encode(Encrypt().encrypt(str(r1),symetric_key,salt_for_key))
                    #print 'The encrypted nonce is '+rqst.nonce_r1
                    sock.send(rqst.SerializeToString())

                if rcmd == '2':
                    rqst.type = pb_example_pb2.Request.LOGOUT
                    r1 = os.urandom(16)
                    rqst.nonce_r1 = base64.b64encode(Encrypt().encrypt(r1,symetric_key,salt_for_key))
                    #print 'The encrypted nonce is '+rqst.nonce_r1
                    sock.send(rqst.SerializeToString())
                if rcmd == '3':
                    exit()
    except Exception:
        print "Looks like server is down right now"
        exit()		
    print 'socket is closed'
    sock.close() # close socket
=======
        print "Provide username please"
        exit()
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    print 'first meessage sent'
    # parse response message
    rply.ParseFromString(data)
    # NEED TO IMPLEMENT PROOF OF WORK
    encrpt = Encrypt()
    public_key_file_name = args.public_key
    r1 = os.urandom(16)
    print 'The r1 is ' + r1
    encrypted_file_name = base64.b64encode(encrpt.asy_encrpt_key(public_key_file_name, server_public_key))
    encrypted_r1 = encrpt.asy_encrpt_key(r1, server_public_key)
    rqst.nonce_r1 = base64.b64encode(encrypted_r1)
    rqst.payload = encrypted_file_name
    # print encrypted_file_name
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    encrypt_r2 = base64.b64decode(rply.nonce_r2)
    dec = Decrypt()
    r2 = dec.asyn_decrypt(encrypt_r2, client_private_key)
    password_hash = ec.generate_hash(user_password + salt)
    print 'The hash is ' + password_hash
    rqst.nonce_r2 = base64.b64encode(encrpt.asy_encrpt_key(r2, server_public_key))
    rqst.hash = base64.b64encode(encrpt.asy_encrpt_key(password_hash, server_public_key))
    print 'sending password hash'
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    if not rply.sign_in_success:
        print 'Please check your username or password'
        exit()
    recieved_r1 = dec.asyn_decrypt(base64.b64decode(rply.nonce_r1), client_private_key)
    if (recieved_r1 != r1):
        print "Seems like the server is pawned closing the connection....."
    print 'all things executed'
    key = dec.asyn_decrypt(base64.b64decode(rply.secret_key), client_private_key)
    key_salt = dec.asyn_decrypt(base64.b64decode(rply.key_salt), client_private_key)
    ran = rply.udp_port
    return (key, key_salt, ran)


def logout(symetric_key, key_salt, rply):
    cipher_r1 = base64.b64decode(rply.nonce_r1)
    cipher_r2 = base64.b64decode(rply.nonce_r2)
    recieved_r1 = Decrypt().decrypt_message(cipher_r1, symetric_key, key_salt)
    recieved_r2 = Decrypt().decrypt_message(cipher_r2, symetric_key, key_salt)
    rqst.nonce_r2 = base64.b64encode(Encrypt().encrypt(recieved_r2, symetric_key, key_salt))
    if recieved_r1 != r1:
        print 'Logout was not successfull'
        return 102
    sock.send(rqst.SerializeToString())
    data = sock.recv(BUFFER_SIZE)
    rply.ParseFromString(data)
    cipher_r1 = base64.b64decode(rply.nonce_r1)
    recieved_r1 = Decrypt().decrypt_message(cipher_r1, symetric_key, key_salt)
    if recieved_r1 != r1 and not rply.logout_success:
        print 'Logout was not successfull'
        return 102


def encrypt_plaintext(symm_key, plaintext, cipher):
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    ciphertext = base64.b64encode(ciphertext)
    return ciphertext


def decrypt_ciphertext(cipher, ciphertext):
    decryptor = cipher.decryptor()
    output_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print 'Decrypting ciphertext...'
    return output_plaintext


def request_to_talk(rply):
    print 'In request to talk'
    symmetric_key_user1 = symetric_key
    iv_user1 = salt_for_key
    decrypted_r1 = base64.b64decode(rply.nonce_r1)
    decrypted_r1 = Decrypt.decrypt_message(decrypted_r1,symmetric_key_user1,iv_user1)
    print 'Decrypting r1 is successful'
    if RANDOM != decrypted_r1:
    	print 'Nonces do not match, something is wrong. Exiting'
    	exit()
    else:
    	rply.nonce_r2 = rply.nonce_r2
    	sock.send(rply.SerializeToString())
    	result_last = sock.recv(BUFFER_SIZE)
    	print 'Received last message on client'
    	talk_to_another_client(result_last,iv_user1,symmetric_key_user1,USER1,USER2)


def sign_message(sender_privkey, plaintext):
    try:
        private_key = CommonMethod.get_private_key(sender_privkey)
    except:
        print 'Error in reading file'
    try:
        signature = private_key.sign(
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        print 'Error in signing message' + str(e)

def verify_sign(sender_pubkey,plaintext,signature):
	print 'Verifying signature..'
	try:

		with open(sender_pubkey,"rb") as key_file:
			public_key = serialization.load_pem_public_key(
			key_file.read(),
		#	password=None,
			backend = default_backend())
	except:
		print 'Unable to load public key'
	try:
		public_key.verify(
		signature,
		plaintext,
		padding.PSS(
			mgf = padding. MGF1(hashes.SHA256()),
			salt_length = padding.PSS.MAX_LENGTH),
		hashes.SHA256())
		print 'Signature verification successful'
	except:
		print 'Invalid signature. Message has been tampered with'
		exit()


def talk_to_another_client(data,iv_user1,symmetric_key_user1,username,user_to_talk_to):
	rply.ParseFromString(data)
	decrypted_pku2 = base64.b64decode(rply.public_key_u2)
	decrypted_pku2 = Decrypt.decrypt_message(decrypted_pku2,symmetric_key_user1,iv_user1)
	print 'Decrypted pku2 is'
	print decrypted_pku2
	r1 = R1
	# r1 = os.urandom(16)
	# global R1
	# R1 = r1
	public_key_u2 = CommonMethod.get_public_key(decrypted_pku2)
	encrypted_r1 = Encrypt.asy_encrpt_key(r1,public_key_u2)
	encrypted_u1 = Encrypt.asy_encrpt_key(username,public_key_u2)
	ticket_pku1 = rply.public_key_u1
	ticket_u1 = rply.username
	# dh1 = pyDH.DiffieHellman()
	# dh1_obj = dh1
	dh_component_1 = dh1_obj.gen_public_key()
	dh_component_1 = str(dh_component_1).encode()
	print 'The Diffie Hellman component is'
	private_key_file = username + '_private_key.pem'
	print private_key_file
	signed_dh_component = sign_message(private_key_file,dh_component_1)
	print 'Signing message succesful'
	rply.nonce_r1 = base64.b64encode(encrypted_r1)
	rply.username = base64.b64encode(encrypted_u1)
	rply.public_key_u1 = base64.b64encode(ticket_pku1)
	rply.ticket_username = base64.b64encode(ticket_u1)
	print 'DH component sent is'
	print dh_component_1
	rply.dh_component = base64.b64encode(dh_component_1)
	rply.signature = base64.b64encode(signed_dh_component)
	sqlconn = sqlite3.connect("db.sqlite")
	c = sqlconn.cursor()
	sql = "SELECT port,ip from active_users where name = ?"
	c.execute(sql,(user_to_talk_to,))
	result = c.fetchone()
	port = result[0]
	print 'Port is '
	print port
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
	print 'Done executing talk to another client'
	udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	udp_sock.sendto(rply.SerializeToString(),(ip,port))
	print 'Message sent from client 1'
	# data = sock.recvfrom(BUFFER_SIZE)
	# if data:
	# 	print 'Something received on client 1'

	
	


def listen_to_connections(sock, any, rply):
    print 'Started new thread for listening'
    data = sock.recv(BUFFER_SIZE)
    if data:
    	print 'Data received from Server'
    	rply.ParseFromString(data)
    	if rply.type == pb_example_pb2.Reply.TALK:
        	request_to_talk(rply)
    	if rply.type == pb_example_pb2.Reply.LOGOUT:
        	logout(symetric_key, salt_for_key, rply)
        	print "The logout was successfull"
        	exit()

def process_step2_phase3(sock,rply):
	print 'In process step2 phase3'
	dh_component_2 = base64.b64decode(rply.dh_component)
	long_dh_component = long(dh_component_2)
	signature = base64.b64decode(rply.signature)
	r2 = base64.b64decode(rply.nonce_r2)
	private_key_file_user1 = USER1 + '_private_key.pem'
	user1_private_key = CommonMethod.get_private_key(private_key_file_user1)
	decrypted_r2 = Decrypt.asyn_decrypt(r2,user1_private_key)
	print 'R2 decrypted successfully'
	print decrypted_r2
	public_key_file_user2 = USER2 + '_public_key.pem'
	verify_sign(public_key_file_user2,dh_component_2,signature)
	print 'Signature verification successful on User1 side.'
	print 'Now going for calculating shared key'
	global dh_shared_key_u2
	dh_shared_key_u2 = generate_dh_shared_secret(dh1_obj,long_dh_component)
	print 'Shared secret generated here also'
	print dh_shared_key_u2
	sign_dh_shared_key_u1 = sign_message(private_key_file_user1,dh_shared_key_u2)
	print 'Shared key signed! :)'
	print sign_dh_shared_key_u1
	encrypted_r2 = Encrypt.encrypt(R2,dh_shared_key_u2,RANDOM)
	encrypted_signed_key = Encrypt.encrypt(sign_dh_shared_key_u1,dh_shared_key_u2,RANDOM)
	rply.secret_key = base64.b64encode(encrypted_signed_key)
	rply.nonce_r2 = base64.b64encode(encrypted_r2)
	rply.type = pb_example_pb2.Reply.SEND_1
	sqlconn = sqlite3.connect("db.sqlite")
	c = sqlconn.cursor()
	sql = "SELECT port,ip from active_users where name = ?"
	c.execute(sql,(USER2,))
	result = c.fetchone()
	port = result[0]
	print 'Port is '
	print port
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
	print 'Done executing chat with client'
	udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	udp_sock.sendto(rply.SerializeToString(),(ip,port))
	print 'Encryption done'
	print 'Process done!'


def generate_dh_shared_secret(dh,long_dh_component):
	print 'Calculating shared secret'
	shared_key = dh.gen_shared_key(long_dh_component)
	return shared_key[:16]


def process_step3_phase3(sock,rply):
	print 'In process3 phase 3'
	decrypted_r2 = base64.b64decode(rply.nonce_r2)
	decrypted_r2 = Decrypt.decrypt_message(decrypted_r2,dh_shared_key_u2,RANDOM)
	print decrypted_r2
	print R2
	print 'Just checking'
	if decrypted_r2 != R2:
		print 'R2 does not match, Something went wrong. Exiting.'
		exit()
	decrypted_signed_key = base64.b64decode(rply.secret_key)
	decrypted_signed_key = Decrypt.decrypt_message(decrypted_signed_key,dh_shared_key_u2,RANDOM)
	print 'Decrypted signed key is:'
	print decrypted_signed_key
	public_key_file_user1 = USER1 + '_public_key.pem'
	verify_sign(public_key_file_user1,dh_shared_key_u2,decrypted_signed_key)
	private_key_file_user2 = USER2 + '_private_key.pem'
	#Prepare next step process
	sign_dh_shared_key_u2 = sign_message(private_key_file_user2,dh_shared_key_u2)
	print 'Shared key signed here too! :)'
	print sign_dh_shared_key_u2
	encrypted_r1 = Encrypt.encrypt(R1,dh_shared_key_u2,RANDOM)
	encrypted_signed_key = Encrypt.encrypt(sign_dh_shared_key_u2,dh_shared_key_u2,RANDOM)

	rply.secret_key = base64.b64encode(encrypted_signed_key)
	rply.nonce_r1 = base64.b64encode(encrypted_r1)
	rply.type = pb_example_pb2.Reply.SEND_2
	sqlconn = sqlite3.connect("db.sqlite")
	c = sqlconn.cursor()
	sql = "SELECT port,ip from active_users where name = ?"
	c.execute(sql,(USER1,))
	result = c.fetchone()
	port = result[0]
	print 'Port is '
	print port
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
	print 'Done executing chat with client'
	udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
	udp_sock.sendto(rply.SerializeToString(),(ip,port))
	print 'Encryption done here also'
	print 'Process done here also!'

def process_step4_phase3(sock,rply):
	print 'In process step4 phase3'
	decrypted_r1 = base64.b64decode(rply.nonce_r1)
	decrypted_r1 = Decrypt.decrypt_message(decrypted_r1,dh_shared_key_u2,RANDOM)
	print decrypted_r1
	print R1
	if decrypted_r1 != R1:
		print 'R1 does not match, Something went wrong. Exiting.'
		exit()
	decrypted_signed_key = base64.b64decode(rply.secret_key)
	decrypted_signed_key = Decrypt.decrypt_message(decrypted_signed_key,dh_shared_key_u2,RANDOM)
	print 'Decrypted signed key is:'
	print decrypted_signed_key
	public_key_file_user2 = USER2 + '_public_key.pem'
	verify_sign(public_key_file_user2,dh_shared_key_u2,decrypted_signed_key)
	print 'Yayyy!! Protocol done! :D'
	message_to_send = 'Hi '+ USER2 +' ,this is ' +USER1
	print message_to_send
	

def chat_with_client(sock,any,rply):
	print 'In chat with client'
	data = sock.recvfrom(BUFFER_SIZE)
	if data:
		rply.ParseFromString(data[0])
		if rply.type == pb_example_pb2.Reply.SEND:
			process_step2_phase3(sock,rply)
		if rply.type == pb_example_pb2.Reply.SEND_1:
			process_step3_phase3(sock,rply)
		if rply.type == pb_example_pb2.Reply.SEND_2:
			process_step4_phase3(sock,rply)
			print 'Done with phase3'
		else:	
			print 'Data received in chat_with_client'
			print 'User 2 is ' + args.user
			user2 = args.user
			decrypted_r1 = Decrypt.asyn_decrypt(base64.b64decode(rply.nonce_r1),client_private_key)
			print decrypted_r1
			decrypted_u1 = Decrypt.asyn_decrypt(base64.b64decode(rply.username),client_private_key)
			print decrypted_u1
			sqlconn = sqlite3.connect("db.sqlite")
			c = sqlconn.cursor()
			sql = "SELECT * from active_users where name = ?"
			c.execute(sql,(user2,))
			result = c.fetchone()
			print 'Symmetric key of user 2 is:'
			symmetric_key_user2 = base64.b64decode(result[1])
			print symmetric_key_user2
			print 'IV of user2 is'
			iv_user2 = base64.b64decode(result[3])
			print iv_user2
			decrypted_ticket_username = base64.b64decode(rply.ticket_username)
			decrypted_ticket_username = base64.b64decode(decrypted_ticket_username)
			decrypted_ticket_username = Decrypt.decrypt_message(decrypted_ticket_username,symmetric_key_user2,iv_user2)
			print 'The answer you want is'
			print decrypted_ticket_username
			if decrypted_ticket_username != decrypted_u1:
				print 'Usernames are not same, something is wrong. Exiting.'
				exit()
			signature = base64.b64decode(rply.signature)	
			dh_component = base64.b64decode(rply.dh_component)
			print 'DH component received is'
			print dh_component
			long_dh_component = long(dh_component)
			sql = 'SELECT public_key from user_public_key where name = ?'
			c.execute(sql,(decrypted_u1,))
			public_key_user1_file = str(c.fetchone()[0])
			verify_sign(public_key_user1_file,dh_component,signature)
			print 'Diffie hellman signature verification successful in step 1 of phase 3'
			global dh_shared_key_u1 
			dh_shared_key_u1 = generate_dh_shared_secret(dh2_obj, long_dh_component)
			print 'Shared secret is:'
			print dh_shared_key_u1
			r2 = R2
			# r2 = os.urandom(16)
			# global R2 
			# R2 = r2
			print 'R2 on this side is:'
			print r2
			public_key_user1 = CommonMethod.get_public_key(public_key_user1_file)
			encrypted_r2 = Encrypt.asy_encrpt_key(r2,public_key_user1)
			# dh2 = pyDH.DiffieHellman()
			# dh2_obj = dh2
			dh_component_2 = dh2_obj.gen_public_key()
			dh_component_2 = str(dh_component_2).encode()
			print 'The Diffie Hellman component to be sent is'
			print dh_component_2
			private_key_file_user2 = user2 + '_private_key.pem'
			print private_key_file_user2
			signed_dh_component = sign_message(private_key_file_user2,dh_component_2)
			print 'Signing successful on user2 side'
			rply.nonce_r2 = base64.b64encode(encrypted_r2)
			rply.dh_component = base64.b64encode(dh_component_2)
			rply.signature = base64.b64encode(signed_dh_component)
			rply.type = pb_example_pb2.Reply.SEND
			sqlconn = sqlite3.connect("db.sqlite")
			c = sqlconn.cursor()
			sql = "SELECT port,ip from active_users where name = ?"
			c.execute(sql,(decrypted_u1,))
			result = c.fetchone()
			port = result[0]
			print 'Port is '
			print port
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
			print 'Done executing chat with client'
			udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
			udp_sock.sendto(rply.SerializeToString(),(ip,port))
			print 'Message sent from client 2'

# else:
# 	print 'Usernames dont match'
# 	exit()
# print type(result)
# print str(result)
# result = str(result[1:-2])
# print result


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
    sec = Phase_1.find_secret(hash_recieved, ip + port)
    rqst.payload = str(sec)
    print "Sending the found secret"
    sock.close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_ADDR, TCP_PORT))  # connect to server
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
    symetric_key, salt_for_key, random_port = sign_in()
    udp_sock_talk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock_talk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock_talk.bind(('', random_port))
    print 'Random port is :'
    print random_port
    print 'The shared secret key is ' + symetric_key
    print 'The salt for the key is ' + salt_for_key
    start_new_thread(listen_to_connections, (sock, 32, rply))
    start_new_thread(chat_with_client, (udp_sock_talk, 32, rply))

    while 1:

        # rqst.version = 7		# this is arbitrary for illustration purpose
        # rqst.seqn = reqno		# set sequence number
>>>>>>> 19b85d48288c23537b1e424f8d9ed6b3339b6bb3

        rcmd = raw_input('Request Type (1: SIGN-IN, 2: LIST, 3: SEND, 4: LOGOUT, 5: TALK): ')
        if rcmd == '5':
            # Check if user is signed-in. If not, exit.
            username = args.user
            USER1 = args.user
            sqlconn = sqlite3.connect("db.sqlite")
            c = sqlconn.cursor()
            sql = 'SELECT * from active_users where name = ?'
            c.execute(sql, (username,))
            data = c.fetchone()
            if data is None:
                print "User %s is not signed-in. Please sign in to talk." % username
            else:
                print 'User signed-in. You can talk now'
                user2 = raw_input("Please enter name of the user you would like to talk to:")
                USER2 = user2
                symmetric_key_user1 = symetric_key
                print 'Symmetric key of user1'
                print symmetric_key_user1
                user1_iv = salt_for_key
                print 'IV for user1'
                print user1_iv
                r1 = RANDOM
                rqst.username = username
                rqst.talk_to_user = base64.b64encode(Encrypt.encrypt(user2, symmetric_key_user1, user1_iv))
                rqst.nonce_r1 = base64.b64encode(Encrypt.encrypt(r1, symmetric_key_user1, user1_iv))
                rqst.type = pb_example_pb2.Request.TALK
                sock.send(rqst.SerializeToString())
                print 'Data sent to server'

        if rcmd == '4':
            rqst.type = pb_example_pb2.Request.LOGOUT
            r1 = os.urandom(16)
            rqst.nonce_r1 = base64.b64encode(Encrypt().encrypt(r1, symetric_key, salt_for_key))
            print 'The encentorypted nonce is ' + rqst.nonce_r1
            sock.send(rqst.SerializeToString())
            print "received data... ", rply.version, rply.seqn, rply.payload
# print 'Message reived from client'

print 'socket is closed'
sock.close()  # close socket
