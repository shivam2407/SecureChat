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
TCP_PORT = args.server_port  # TCP port of server
BUFFER_SIZE = 4098

TIMEOUT = 5
used_ports = []
RANDOM = os.urandom(16)
USER1 = ''
USER2 = ''

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


def talk_to_another_client(data,iv_user1,symmetric_key_user1,username,user_to_talk_to):
	rply.ParseFromString(data)
	decrypted_pku2 = base64.b64decode(rply.public_key_u2)
	decrypted_pku2 = Decrypt.decrypt_message(decrypted_pku2,symmetric_key_user1,iv_user1)
	print 'Decrypted pku2 is'
	print decrypted_pku2
	r1 = os.urandom(16)
	public_key_u2 = CommonMethod.get_public_key(decrypted_pku2)
	encrypted_r1 = Encrypt.asy_encrpt_key(r1,public_key_u2)
	encrypted_u1 = Encrypt.asy_encrpt_key(username,public_key_u2)
	ticket_pku1 = rply.public_key_u1
	ticket_u1 = rply.username
	rply.nonce_r1 = base64.b64encode(encrypted_r1)
	rply.username = base64.b64encode(encrypted_u1)
	rply.public_key_u1 = base64.b64encode(ticket_pku1)
	rply.ticket_username = base64.b64encode(ticket_u1)

	# r1 = os.urandom(16)
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
	# dh = pyDH.DiffieHellman()
	# u1_dh_component = dh.get_public_key()
# 	# pku2 = base64.b64decode(rply.public_key_u2)
# 	# pku2 = base64.b64decode(rply.public_key_u2)
# 	#pku2 = base64.b64decode(pku2)
# 	# pku2 = Decrypt.decrypt_message(base64.b64decode(rply.public_key_u2),shared_key,iv)
# 	# print 'IV is :'
# 	# print iv
# 	# print 'shared key is :'
# 	# print shared_key
# 	pku2 = Decrypt.decrypt_message(base64.b64decode(rply.public_key_u2),shared_key,iv)
# 	# pku2 = pku2.encode('utf-8')
# 	# pku2 = pku2.decode('utf-8')
# 	print '-------------------Public key of U2------------------'
# 	print str(pku2)
# 	print pku2
# 	print type(pku2)
# 	print 'In talk to another client'
# 	public_key_user2 = CommonMethod.get_public_key(pku2)
# 	pku1_ticket = Decrypt.decrypt_message(base64.b64decode(rply.public_key_u1),shared_key,iv)
# 	print 'PKU1 ticket is'
# 	print pku1_ticket
# 	u1_ticket = Decrypt.decrypt_message(base64.b64decode(rply.username),shared_key,iv)
# 	print 'Username after decrypting with U1S is:'
# 	print u1_ticket
# 	print 'IV 1 is: '
# 	print iv
# 	print 'shared key 1 is:'
# 	print shared_key
# 	d1 = pyDH.DiffieHellman()
# 	d1_pubkey = d1.gen_public_key()
# 	print "Diffie Hellman Component is: "
# 	d1_pubkey = (str(d1_pubkey)).encode()
# 	print d1_pubkey
# 	private_key_file = username + '_private_key.pem'
# 	print private_key_file
# 	signed_dh_component = sign_message(private_key_file,d1_pubkey)
# 	print 'Signing message succesful'
# 	print 'Encrypted DH component is: '
# 	r1 = os.urandom(16)
# 	# encrypted_r1 = encrypt_symm_key(pku2,r1)

# 	encrypted_r1 = Encrypt.asy_encrpt_key(r1,public_key_user2)
# 	print 'Encrypted r1 successfully'
# 	encrypted_u1 = Encrypt.asy_encrpt_key(username,public_key_user2)
# 	#send phase3 message1
# 	rply.nonce_r1 = base64.b64encode(encrypted_r1)
# 	print 'R1 is ------'
# 	print r1
# 	rply.username = base64.b64encode(encrypted_u1)
# 	rply.public_key_u1 = base64.b64encode(pku1_ticket)
# 	rply.ticket_username = base64.b64encode(u1_ticket)
# 	rply.dh_component = base64.b64encode(signed_dh_component)

	


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

def chat_with_client(sock,any,rply):
	print 'In chat with client'
	data = sock.recvfrom(BUFFER_SIZE)
	if data:
		rply.ParseFromString(data[0])
		print 'Data received in chat_with_client'
		print 'User 2 is ' + args.user
		user2 = args.user
		decrypted_r1 = Decrypt.asyn_decrypt(base64.b64decode(rply.nonce_r1),client_private_key)
		print decrypted_r1
		decrypted_u1 = Decrypt.asyn_decrypt(base64.b64decode(rply.username),client_private_key)
		print decrypted_u1
		# symmetric_key_user2 = symetric_key
		# iv_user2 = salt_for_key
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
		print 'Wohooo!! This is done!'

	

# username = args.user
# print username
# private_key_file = username + '_private_key.pem'
# print private_key_file
# private_key_u2 = CommonMethod.get_private_key(private_key_file)
# print 'Private key loaded successfully'
# print rply.nonce_r1
# # decrypted_r1 = decrypt_symm_key(private_key_file,base64.b64decode(rply.nonce_r1))
# decrypted_r1 = Decrypt.asyn_decrypt(base64.b64decode(rply.nonce_r1),private_key_u2)
# print 'R1 decryption successful'
# decrypted_u1 = Decrypt.asyn_decrypt(base64.b64decode(rply.username),private_key_u2)
# print 'U1 decryption successful'
# sqlconn = sqlite3.connect("db.sqlite")
# c = sqlconn.cursor()
# sql = 'SELECT * from active_users where name = ?'
# c.execute(sql,(username,))
# print 'Username for shared key is::'
# print username
# data = c.fetchone()
# shared_key_su2 = base64.b64decode(data[1])
# iv = base64.b64decode(data[3])
# print 'Fetched shared_key from database'
# print 'IV is: '
# print iv
# print 'Shared key is what you want: '
# print shared_key_su2
# print 'Username before decrypting with shared key of user2 is:'
# print (base64.b64decode(rply.ticket_username))
# decrypted_ticket_username = Decrypt.decrypt_message(base64.b64decode(rply.ticket_username),shared_key_su2,iv)
# print 'Decryption successful'
# public_key_user1 = Decrypt.decrypt_message(base64.b64decode(rply.public_key_u1),shared_key_su2,iv)
# print 'Got public key of user1'
# print decrypted_ticket_username
# print decrypted_u1

# if decrypted_u1 = decrypted_ticket_username:


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
