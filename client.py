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
TCP_PORT = args.server_port		# TCP port of server
BUFFER_SIZE = 4098

TIMEOUT = 5
used_ports = []
RANDOM = os.urandom(16)
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

