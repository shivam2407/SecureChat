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
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP_ADDR,TCP_PORT))
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

def request_to_talk(rply):
    #Fecth details from sign-in function
    symmetric_key_user1 = symetric_key
    iv_user1 = salt_for_key
    #Decrypt and verify the R1 returned by server. 
    decrypted_r1 = base64.b64decode(rply.nonce_r1)
    decrypted_r1 = Decrypt.decrypt_message(decrypted_r1,symmetric_key_user1,iv_user1)
    # If R1 returned correctly, continue, else exit.
    if RANDOM != decrypted_r1:
        print 'Nonces do not match, something is wrong. Exiting'
        exit()
    else:
        #Send R2 generated by server to server
        rply.nonce_r2 = rply.nonce_r2
        sock.send(rply.SerializeToString())
        #Receive ticket to user2 from server and use it to talk to user2
        result_last = sock.recv(BUFFER_SIZE)
        talk_to_another_client(result_last,iv_user1,symmetric_key_user1,USER1,USER2)

#Method to sign a message
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

#Verify signature method
def verify_sign(sender_pubkey,plaintext,signature):
    print 'Verifying signature..'
    try:

        with open(sender_pubkey,"rb") as key_file:
            public_key = serialization.load_pem_public_key(
            key_file.read(),
        #   password=None,
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

#Initiate the communication to user2 by sending it the ticket given by server
def talk_to_another_client(data,iv_user1,symmetric_key_user1,username,user_to_talk_to):
    rply.ParseFromString(data)
    #Decrypt the public key of user2 using the shared key of user1-server
    #this key will be used to send data to user2
    decrypted_pku2 = base64.b64decode(rply.public_key_u2)
    decrypted_pku2 = Decrypt.decrypt_message(decrypted_pku2,symmetric_key_user1,iv_user1)
    #Generate a nonce to send to server
    r1 = R1
    #Fetch public key value
    public_key_u2 = CommonMethod.get_public_key(decrypted_pku2)
    #Encrypt username of user1 and r1 with the public key of user2
    encrypted_r1 = Encrypt.asy_encrpt_key(r1,public_key_u2)
    encrypted_u1 = Encrypt.asy_encrpt_key(username,public_key_u2)
    #keep the ticket to user2 as it was received from Server. 
    ticket_pku1 = rply.public_key_u1
    ticket_u1 = rply.username
    #Generate the Diffie hellman component to generate session keys
    dh_component_1 = dh1_obj.gen_public_key()
    dh_component_1 = str(dh_component_1).encode()
    #Sign the Diffie Hellman component using user1's private key
    private_key_file = username + '_private_key.pem'
    signed_dh_component = sign_message(private_key_file,dh_component_1)

    #Set the message to send to user 2
    rply.nonce_r1 = base64.b64encode(encrypted_r1)
    rply.username = base64.b64encode(encrypted_u1)
    rply.public_key_u1 = base64.b64encode(ticket_pku1)
    rply.ticket_username = base64.b64encode(ticket_u1)
    rply.dh_component = base64.b64encode(dh_component_1)
    rply.signature = base64.b64encode(signed_dh_component)

    #Fetch the port to send on
    sqlconn = sqlite3.connect("db.sqlite")
    c = sqlconn.cursor()
    sql = "SELECT port,ip from active_users where name = ?"
    c.execute(sql,(user_to_talk_to,))
    result = c.fetchone()
    port = result[0]
    port = int(port)
    ip = result[1]
    ip = ip.encode('utf-8')
    if port is None:
        print 'Port is not present'
        exit()
    if ip is None:
        print 'IP is not present'
        exit()
    #Client to client communication takes place on udp port
    udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    udp_sock.sendto(rply.SerializeToString(),(ip,port))



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
        
def process_step2_phase3(sock,rply):

    ip = base64.b64decode(rply.ip_addr)
    port = rply.udp_port

    #Fetch the Diffie hellman component received and verify sign on it
    dh_component_2 = base64.b64decode(rply.dh_component)
    long_dh_component = long(dh_component_2)
    signature = base64.b64decode(rply.signature)
    r2 = base64.b64decode(rply.nonce_r2)
    private_key_file_user1 = USER1 + '_private_key.pem'
    user1_private_key = CommonMethod.get_private_key(private_key_file_user1)
    decrypted_r2 = Decrypt.asyn_decrypt(r2,user1_private_key)
    public_key_file_user2 = USER2 + '_public_key.pem'
    verify_sign(public_key_file_user2,dh_component_2,signature)
    #generate shared Diffie Hellman secret
    global dh_shared_key_u2
    dh_shared_key_u2 = generate_dh_shared_secret(dh1_obj,long_dh_component)
    
    #Sign and encrypt the Diffie hellman generated secret
    sign_dh_shared_key_u1 = sign_message(private_key_file_user1,dh_shared_key_u2)
    
    encrypted_r2 = Encrypt.encrypt(R2,dh_shared_key_u2,RANDOM)
    encrypted_signed_key = Encrypt.encrypt(sign_dh_shared_key_u1,dh_shared_key_u2,RANDOM)
    #set message to send
    rply.ip_addr = base64.b64encode(args.ip_addr)
    rply.udp_port= random_port
    rply.secret_key = base64.b64encode(encrypted_signed_key)
    rply.nonce_r2 = base64.b64encode(encrypted_r2)
    rply.type = pb_example_pb2.Reply.SEND_1

    # sqlconn = sqlite3.connect("db.sqlite")
    # c = sqlconn.cursor()
    # sql = "SELECT port,ip from active_users where name = ?"
    # c.execute(sql,(USER2,))
    # result = c.fetchone()
    # port = result[0]
    # print 'Port is '
    # print port
    # port = int(port)
    # ip = result[1]
    # print 'IP address is'
    # print ip
    # ip = ip.encode('utf-8')
    # if port is None:
    #   print 'Port is not present'
    #   exit()
    # if ip is None:
    #   print 'IP is not present'
    #   exit()
    udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    udp_sock.sendto(rply.SerializeToString(),(ip,port))

#Method to generate Diffie Hellman shared secret
def generate_dh_shared_secret(dh,long_dh_component):
    print 'Calculating shared secret'
    shared_key = dh.gen_shared_key(long_dh_component)
    return shared_key[:16]


def process_step3_phase3(sock,rply):
    ip = base64.b64decode(rply.ip)
    port = rply.udp_port
    decrypted_r2 = base64.b64decode(rply.nonce_r2)
    decrypted_r2 = Decrypt.decrypt_message(decrypted_r2,dh_shared_key_u2,RANDOM)
    #verify the R2 given to user1 in previous message is same as R2 given here
    if decrypted_r2 != R2:
        print 'R2 does not match, Something went wrong. Exiting.'
        exit()
    #verify sign on the diffie hellman shared key
    decrypted_signed_key = base64.b64decode(rply.secret_key)
    decrypted_signed_key = Decrypt.decrypt_message(decrypted_signed_key,dh_shared_key_u2,RANDOM)
    public_key_file_user1 = USER1 + '_public_key.pem'
    verify_sign(public_key_file_user1,dh_shared_key_u2,decrypted_signed_key)
    private_key_file_user2 = USER2 + '_private_key.pem'
    #Prepare next step process. Sign the diffie hellman key with private key of user2
    sign_dh_shared_key_u2 = sign_message(private_key_file_user2,dh_shared_key_u2)
    #Encrypt the diffie hellman key and R!
    encrypted_r1 = Encrypt.encrypt(R1,dh_shared_key_u2,RANDOM)
    encrypted_signed_key = Encrypt.encrypt(sign_dh_shared_key_u2,dh_shared_key_u2,RANDOM)
    #set message to send
    rply.ip = base64.b64encode(args.ip_addr)
    rply.port = random_port
    rply.secret_key = base64.b64encode(encrypted_signed_key)
    rply.nonce_r1 = base64.b64encode(encrypted_r1)
    rply.type = pb_example_pb2.Reply.SEND_2
    # sqlconn = sqlite3.connect("db.sqlite")
    # c = sqlconn.cursor()
    # sql = "SELECT port,ip from active_users where name = ?"
    # c.execute(sql,(USER1,))
    # result = c.fetchone()
    # port = result[0]
    # print 'Port is '
    # print port
    # port = int(port)
    # ip = result[1]
    # print 'IP address is'
    # print ip
    # ip = ip.encode('utf-8')
    # if port is None:
    #   print 'Port is not present'
    #   exit()
    # if ip is None:
    #   print 'IP is not present'
    #   exit()
    #send message
    udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    udp_sock.sendto(rply.SerializeToString(),(ip,port))
    

def process_step4_phase3(sock,rply):
    
    ip = base64.b64decode(rply.ip)
    port = rply.udp_port
    #Verify the R! sent in the last message is same as R1 given in the first message.
    decrypted_r1 = base64.b64decode(rply.nonce_r1)
    decrypted_r1 = Decrypt.decrypt_message(decrypted_r1,dh_shared_key_u2,RANDOM)
    if decrypted_r1 != R1:
        print 'R1 does not match, Something went wrong. Exiting.'
        exit()
    decrypted_signed_key = base64.b64decode(rply.secret_key)
    decrypted_signed_key = Decrypt.decrypt_message(decrypted_signed_key,dh_shared_key_u2,RANDOM)
    
    #Verify signature on Diffie Hellman
    public_key_file_user2 = USER2 + '_public_key.pem'
    public_key_user2 = CommonMethod.get_public_key(public_key_file_user2)
    verify_sign(public_key_file_user2,dh_shared_key_u2,decrypted_signed_key)
    
    #Prepare message that the user1 wants to give user2
    #hash the message, encrypt it and then send to user1.
    rply.type = pb_example_pb2.Reply.SEND_3
    message_to_send = 'Hi '+ USER2 +' ,this is ' +USER1
    message_hash = hashing_process(message_to_send,RANDOM)
    
    encrypted_message = Encrypt.encrypt(message_to_send,dh_shared_key_u2,RANDOM)
    rply.message = base64.b64encode(encrypted_message)
    encrypted_dh_key = Encrypt.asy_encrpt_key(dh_shared_key_u2,public_key_user2)
    rply.secret_key = base64.b64encode(encrypted_dh_key)
    rply.hash = base64.b64encode(message_hash)
    rply.ip = base64.b64encode(args.ip_addr)
    rply.port = random_port
    sqlconn = sqlite3.connect("db.sqlite")
    # c = sqlconn.cursor()
    # sql = "SELECT port,ip from active_users where name = ?"
    # c.execute(sql,(USER2,))
    # result = c.fetchone()
    # port = result[0]
    # print 'Port is '
    # print port
    # port = int(port)
    # ip = result[1]
    # print 'IP address is'
    # print ip
    # ip = ip.encode('utf-8')
    # if port is None:
    #   print 'Port is not present'
    #   exit()
    # if ip is None:
    #   print 'IP is not present'
    #   exit()
    # print 'Done executing chat with client'
    udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    udp_sock.sendto(rply.SerializeToString(),(ip,port))


#Hash method
def hashing_process(factors_to_hash,hash_iv):
    for _hash in [hashes.SHA256]:
        h = hmac.HMAC(hash_iv,hashes.SHA256(), backend = default_backend())
        h.update(factors_to_hash)
        msg_digest=h.finalize()
        return msg_digest

#Method to verify hash
def verify_hash(factors_to_hash,hash_iv,msg_digest):
    try:
        for _hash in [hashes.SHA256]:
            h = hmac.HMAC(hash_iv, hashes.SHA256(), backend=default_backend())
            h.update(factors_to_hash)
            h.verify(msg_digest)
            print 'Hash verified.'
    except:
        print 'Hash did not match, something is wrong. Exiting.'
        exit()

        
#This method verifies whether the message that user1 wants to give to user2 is not tampered in the sending process.
def verify_sent_message(sock,rply):
    ciphertext = base64.b64decode(rply.message)
    msg_digest = base64.b64decode(rply.hash)
    encrypted_shared_key = base64.b64decode(rply.secret_key)
    private_key_user2 = USER2 + '_private_key.pem'
    private_key_user2 = CommonMethod.get_private_key(private_key_user2) 
    dh_shared_key_u1 = Decrypt.asyn_decrypt(encrypted_shared_key,private_key_user2)
    decrypted_ciphertext = Decrypt.decrypt_message(ciphertext,dh_shared_key_u1,RANDOM)
    verify_hash(decrypted_ciphertext,RANDOM,msg_digest)
    

    
#This method handles client to client communication
def chat_with_client(sock,any,rply):
    #Receive any message coming from client
    data = sock.recvfrom(BUFFER_SIZE)
    if data:
        rply.ParseFromString(data[0])
        if rply.type == pb_example_pb2.Reply.SEND:
            process_step2_phase3(sock,rply)
        if rply.type == pb_example_pb2.Reply.SEND_1:
            process_step3_phase3(sock,rply)
        if rply.type == pb_example_pb2.Reply.SEND_2:
            process_step4_phase3(sock,rply)
        if rply.type == pb_example_pb2.Reply.SEND_3:
            verify_sent_message(sock,rply)
        else:   
            #User2 verifies the data sent by user1.
            user2 = args.user
            decrypted_r1 = Decrypt.asyn_decrypt(base64.b64decode(rply.nonce_r1),client_private_key)
            decrypted_u1 = Decrypt.asyn_decrypt(base64.b64decode(rply.username),client_private_key)
            #Fetch the shared key of user2-server and IV from the database
            sqlconn = sqlite3.connect("db.sqlite")
            c = sqlconn.cursor()
            sql = "SELECT * from active_users where name = ?"
            c.execute(sql,(user2,))
            result = c.fetchone()
            symmetric_key_user2 = base64.b64decode(result[1])
            iv_user2 = base64.b64decode(result[3])

            #Fetch the shared key of user1-server and IV from the database
            sql = "SELECT * from active_users where name = ?"
            c.execute(sql,(decrypted_u1,))
            result_u1 = c.fetchone()
            symmetric_key_user1 = base64.b64decode(result_u1[1])
    
            iv_user1 = base64.b64decode(result_u1[3])
            ip = base64.b64decode(rply.ip)
            port = rply.port
            #Decrypt username oof user1 in the ticket to B and verify it with
            #the username in the tuple encrypted with public key of user2.
            #If usernames in both places are same, continue, else exit
            decrypted_ticket_username = base64.b64decode(rply.ticket_username)
            decrypted_ticket_username = base64.b64decode(decrypted_ticket_username)
            decrypted_ticket_username = Decrypt.decrypt_message(decrypted_ticket_username,symmetric_key_user1,iv_user1)
            decrypted_ticket_username = Decrypt.decrypt_message(decrypted_ticket_username,symmetric_key_user2,iv_user2)
            if decrypted_ticket_username != decrypted_u1:
                print 'Usernames are not same, something is wrong. Exiting.'
                exit()
            #verify signature on the diffie hellman component
            signature = base64.b64decode(rply.signature)    
            dh_component = base64.b64decode(rply.dh_component)
            long_dh_component = long(dh_component)
            sql = 'SELECT public_key from user_public_key where name = ?'
            c.execute(sql,(decrypted_u1,))
            public_key_user1_file = str(c.fetchone()[0])
            verify_sign(public_key_user1_file,dh_component,signature)

            #Generate the shared secret key of Diffie Hellman
            global dh_shared_key_u1 
            dh_shared_key_u1 = generate_dh_shared_secret(dh2_obj, long_dh_component)
            #Send a nonce, r2 and user2 sides's diffie hellman component to user 1
            r2 = R2
            public_key_user1 = CommonMethod.get_public_key(public_key_user1_file)
            encrypted_r2 = Encrypt.asy_encrpt_key(r2,public_key_user1)
            dh_component_2 = dh2_obj.gen_public_key()
            dh_component_2 = str(dh_component_2).encode()
            private_key_file_user2 = user2 + '_private_key.pem'
            print private_key_file_user2

            #Sign the diffie hellman component
            signed_dh_component = sign_message(private_key_file_user2,dh_component_2)
            
            #prepare emssage to send
            rply.ip = base64.b64encode(args.ip_addr)
            rply.udp_port = random_port
            rply.nonce_r2 = base64.b64encode(encrypted_r2)
            rply.dh_component = base64.b64encode(dh_component_2)
            rply.signature = base64.b64encode(signed_dh_component)
            rply.type = pb_example_pb2.Reply.SEND
            # sqlconn = sqlite3.connect("db.sqlite")
            # c = sqlconn.cursor()
            # sql = "SELECT port,ip from active_users where name = ?"
            # c.execute(sql,(decrypted_u1,))
            # result = c.fetchone()
            # port = result[0]
            # print 'Port is '
            # print port
            # port = int(port)
            # ip = result[1]
            # print 'IP address is'
            # print ip
            # ip = ip.encode('utf-8')
            # if port is None:
            #   print 'Port is not present'
            #   exit()
            # if ip is None:
            #   print 'IP is not present'
            #   exit()
            udp_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            udp_sock.sendto(rply.SerializeToString(),(ip,port))


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

