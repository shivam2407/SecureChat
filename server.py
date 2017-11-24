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
import sqlite3
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
                    default=9090,
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
BUFFER_SIZE = 4096

rqst = pb_example_pb2.Request()	# create protobuf Request message
rply = pb_example_pb2.Reply()	# create protobuf Reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#reuse the address even if it is in the TIME_WAIT state
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
sock.bind(('', TCP_PORT))	# bind to port

sock.listen(100)			# listen with one pending connection

def sign_in(conn,server_private_key,server_public_key):
    name_of_user = rqst.payload
    sqlconn = sqlite3.connect("db.sqlite")
    c = sqlconn.cursor()
    #NEED TO IMPLEMENT PROOF OF WORK
    rply.hash = 'hashed secret'
    hash_send = 'hashed secret'
    conn.send(rply.SerializeToString())
    data = conn.recv(BUFFER_SIZE)
    rqst.ParseFromString(data)
    encrpt = Encrypt()
    decrpt = Decrypt()
    cm = CommonMethod()
    hash_answer = base64.b64decode(rqst.hash)
    if (hash_answer != hash_send):
        print 'Cant do proof of work'
    client_public_key_name = decrpt.asyn_decrypt(base64.b64decode(rqst.payload),server_private_key)
    client_public_key = cm.get_public_key(client_public_key_name)
    client_r1 = decrpt.asyn_decrypt(base64.b64decode(rqst.nonce_r1),server_private_key)
    print 'Client r1 is '+ client_r1
    r2 = os.urandom(16)
    rply.nonce_r2 = base64.b64encode(encrpt.asy_encrpt_key(r2,client_public_key))
    conn.send(rply.SerializeToString())
    data = conn.recv(BUFFER_SIZE)
    rqst.ParseFromString(data)
    recieved_hash = decrpt.asyn_decrypt(base64.b64decode(rqst.hash),server_private_key)
    print 'Recieved HASH is '+ recieved_hash
    print 'The b64encoded hash is '+ base64.b64encode(recieved_hash)
    recieved_r2 = decrpt.asyn_decrypt(base64.b64decode(rqst.nonce_r2),server_private_key)
    sql = "SELECT name from users where password_hash = ?"
    c.execute(sql,(base64.b64encode(recieved_hash),))
    user_name = c.fetchone()
    #print 'The username fetched from sql is '+ user_name[0] +' and the name is '+ name_of_user
    if user_name == None or name_of_user != user_name[0] or recieved_r2 != r2:
        print 'Please check your username or password'
        rply.sign_in_success = False
        conn.send(rply.SerializeToString())    
        exit()
    else:
        rply.sign_in_success = True
    encrypt_r1 = base64.b64encode(encrpt.asy_encrpt_key(client_r1,client_public_key))
    print 'Client r1 is encrypted '+ encrypt_r1
    rply.nonce_r1 = encrypt_r1
    secret_key = os.urandom(16)
    salt_key = os.urandom(16)
    rply.secret_key = base64.b64encode(encrpt.asy_encrpt_key(secret_key,client_public_key))
    rply.key_salt = base64.b64encode(encrpt.asy_encrpt_key(salt_key,client_public_key))
    conn.send(rply.SerializeToString())
    print 'Done sign_in'
    sql = "INSERT into active_users ('name', 'shared_key', 'public_key', 'key_salt') values (?, ?, ?, ?)"
    c.execute(sql,(name_of_user,base64.b64encode(secret_key),client_public_key_name,base64.b64encode(salt_key)))
    sqlconn.commit()
    sqlconn.close()
    print 'Inserted the data for user'


    """public_key_file_name = args.public_key
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
    return dec.asyn_decrypt(base64.b64decode(rply.secret_key),client_private_key)"""

def logout(user_name,conn,server_private_key,server_public_key):
    sqlconn = sqlite3.connect("db.sqlite")
    c = sqlconn.cursor()
    sql = 'SELECT * from active_users where name = ?'
    c.execute(sql,(user_name,))
    r = c.fetchone()
    shared_key = base64.b64decode(r[1])
    key_salt = base64.b64decode(r[3])
    client_public_key_name = r[2]
    print ' The shared secret key from database is '+shared_key
    print ' The salt is '+key_salt
    print 'The encrypted nonce_r1 is '+base64.b64decode(rqst.nonce_r1)
    client_public_key = CommonMethod().get_public_key(client_public_key_name)
    recieved_r1 = Decrypt().decrypt_message(base64.b64decode(rqst.nonce_r1),shared_key,key_salt)
    r2 = os.urandom(16)
    rply.nonce_r2 = base64.b64encode(Encrypt().encrypt(r2,shared_key,key_salt))
    rply.nonce_r1 = base64.b64encode(Encrypt().encrypt(recieved_r1,shared_key,key_salt))
    rply.logout_success = False
    conn.send(rply.SerializeToString())
    data = conn.recv(BUFFER_SIZE)
    rqst.ParseFromString(data)
    recieved_r2 = Decrypt().decrypt_message(base64.b64decode(rqst.nonce_r2),shared_key,key_salt)
    sql = 'DELETE from active_users where name = ?'
    c.execute(sql,(user_name,))
    sqlconn.commit()
    sqlconn.close()
    if recieved_r2 != r2:
        print 'seems like someone else is trying to logout user'
    rply.logout_success = True
    conn.send(rply.SerializeToString())
    print 'Logout successfull' 


            


def start_connection(conn,addr):
    user_name = ""
    while 1:                # process one request at a time
        data = conn.recv(BUFFER_SIZE)
        if not data: 
            break

        print "received data..."

        rqst.ParseFromString(data)  # parse message
        print rqst.version, rqst.seqn   # print version and sequence number
        print 'RQST parsed'
        rply.version = rqst.version # use same version number for reply

        rply.seqn = rqst.seqn       # use same version number for reply
        ec = CommonMethod()
        server_private_key = ec.get_private_key(args.private_key)
        server_public_key = ec.get_public_key(args.public_key)
        print server_public_key

        if (rqst.type == pb_example_pb2.Request.SIGN): # SIGN-IN request
            sqlconn = sqlite3.connect("db.sqlite")
            c = sqlconn.cursor()
            sql = 'SELECT count(1) from active_users where name = ?'
            user_name = rqst.payload
            user_name = user_name.encode('UTF-8')
            count = c.execute(sql,(user_name,))
            sqlconn.close()
            if count == 1:
                print 'Already online seems like you already have a session running'
                exit()
            else:
                print 'Welcome: '+user_name
                sign_in(conn,server_private_key,server_public_key)   # just copy payload
                print 'Sign in is done'
        if (rqst.type == pb_example_pb2.Request.LOGOUT):
            logout(user_name,conn,server_private_key,server_public_key)
        #conn.send(rply.SerializeToString())  # serialize response into string and send

        #if (rqst.type == pb_example_pb2.Request.ECHO): # echo request
        #    rply.payload = rqst.payload                # just copy payload

        #if (rqst.type == pb_example_pb2.Request.RCMD):  # remote command request
        #    rply.payload = rqst.payload
            ##print 'Executing command: ', rqst.payload
                                                        # execute command and get stdout
            ##rply.payload = subprocess.check_output(rqst.payload, shell='True')

while 1:
    print "Listening again"
    conn, addr = sock.accept()	# accept connection from client
    print 'ADDR : '+ str(addr[1])
    print 'CONN : '+ str(conn)
    start_new_thread(start_connection,(conn,addr))
    print 'Connection address:', addr
