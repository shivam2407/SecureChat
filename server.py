import socket
import time
import sys
import pb_example_pb2 	# import the module created by protobuf
						# for creating messages
import subprocess    	# module for executing commands from python
						# and retrieving stdout
from thread import *    # import thread module
import chardet
import argparse
import os
import base64
import sqlite3
from random import *
from fcrypt import CommonMethod, Encrypt, Decrypt
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import *

used_ports = []

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
talk_rqst = pb_example_pb2.talk_request() #create protobuf talk_request message
talk_rply = pb_example_pb2.talk_reply() #create protobuf talk_reply message

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#reuse the address even if it is in the TIME_WAIT state
sock.bind(('', TCP_PORT))	# bind to port

sock.listen(100)

def sign_in(conn,addr,server_private_key,server_public_key):
    name_of_user = rqst.payload
    #Connecting to sql database
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

    #fetching client public key    
    client_public_key_name = decrpt.asyn_decrypt(base64.b64decode(rqst.payload),server_private_key)
    client_public_key = cm.get_public_key(client_public_key_name)
    
    # Decrypting nonce R1 sent by client
    client_r1 = decrpt.asyn_decrypt(base64.b64decode(rqst.nonce_r1),server_private_key)
    print 'Client r1 is '+ client_r1

    #Generating nonce R2 to be sent to client
    r2 = os.urandom(16)
    rply.nonce_r2 = base64.b64encode(encrpt.asy_encrpt_key(r2,client_public_key))
    conn.send(rply.SerializeToString())
    data = conn.recv(BUFFER_SIZE)
    rqst.ParseFromString(data)

    #checking wether password hash for the client
    recieved_hash = decrpt.asyn_decrypt(base64.b64decode(rqst.hash),server_private_key)
    print 'Recieved HASH is '+ recieved_hash
    print 'The b64encoded hash is '+ base64.b64encode(recieved_hash)
    recieved_r2 = decrpt.asyn_decrypt(base64.b64decode(rqst.nonce_r2),server_private_key)
    
    # Fetching user name for generated password hash
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

    #Encrypting nonce R1 to be sent to client
    encrypt_r1 = base64.b64encode(encrpt.asy_encrpt_key(client_r1,client_public_key))
    print 'Client r1 is encrypted '+ encrypt_r1
    rply.nonce_r1 = encrypt_r1
    
    #Generating secret key and salt for this specific session with client
    secret_key = os.urandom(16)
    salt_key = os.urandom(16)
    rply.secret_key = base64.b64encode(encrpt.asy_encrpt_key(secret_key,client_public_key))
    rply.key_salt = base64.b64encode(encrpt.asy_encrpt_key(salt_key,client_public_key))
    while 1:

        ran = randint(1025,65535)
        if ran not in used_ports:
            break
    rply.udp_port = ran
    used_ports.append(ran)
    conn.send(rply.SerializeToString())
    print 'Done sign_in'
    sql = "INSERT into active_users ('name', 'shared_key', 'public_key', 'key_salt', 'port', 'ip') values (?, ?, ?, ?, ?, ?)"
    c.execute(sql,(name_of_user,base64.b64encode(secret_key),client_public_key_name,base64.b64encode(salt_key),str(ran),addr[0]))
    sqlconn.commit()
    sqlconn.close()
    print 'Inserted the data for user'

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
    rply.type = pb_example_pb2.Reply.LOGOUT
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


def process_talk(conn,rqst):
    username = rqst.username
    # uername = Decrypt.decrypt_message(username,shared_key,iv)
    print 'Username received is ' + username
    sqlconn = sqlite3.connect("db.sqlite")
    c = sqlconn.cursor()
    sql = 'SELECT * from active_users where name = ?'
    print 'Name given is :'
    print rqst.username
    c.execute(sql,(rqst.username,))
    r = c.fetchone()
    if r is None:
        print "Something went wrong."
    else:
        shared_key = base64.b64decode(r[1])
        iv = base64.b64decode(r[3])
        cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv),backend = default_backend())
        rply.username = username
        rply.nonce_r1 = rqst.nonce_r1
        r2 = os.urandom(16)
        print 'R2 is: ' + r2
        usr = base64.b64decode(rqst.talk_to_user)
        talk_to_user = Decrypt.decrypt_message(usr,shared_key,iv)
        print 'Received request to talk to ' + talk_to_user
        encrypted_r2 = base64.b64encode(Encrypt.encrypt(r2,shared_key,iv))
        rply.nonce_r2 = encrypted_r2.decode('utf-8')
        rply.type = pb_example_pb2.Reply.TALK
        conn.send(rply.SerializeToString())  # serialize response into string and send
        print 'Data sent to client'
        data = conn.recv(BUFFER_SIZE)
        if not data: 
            print 'No response received.'
            sys.exit()
        rply.ParseFromString(data)
        nonce = base64.b64decode(rply.nonce_r2)
        nonced = Decrypt.decrypt_message(nonce,shared_key,iv)
        print nonced
        if nonced == r2:
            su2 = os.urandom(16);
            print 'User to talk to is ' + talk_to_user
            sqlconn = sqlite3.connect("db.sqlite")
            c = sqlconn.cursor()
            sql = 'SELECT * from active_users where name = ?'
            decode_usr = talk_to_user.decode('utf-8')
            c.execute(sql,(decode_usr,))
            result = c.fetchone()
            if result is None:
                print "DK went wrong."
                sys.exit()
            else:
                print 'Result should be'
                print result
                shared_key_u2 = result[1]
                sql = 'SELECT public_key from user_public_key where name = ?'
                decode_username = str(talk_to_user.decode('utf-8'))
                c.execute(sql,(decode_username,))
                res_u1 = str(c.fetchone()[0])
                print 'File name is '
                print res_u1
                ec = CommonMethod()
                res_u1 = str(ec.get_public_key(res_u1))
                print "Public key is: " 
                print res_u1
                c.execute(sql,(decode_usr,))
                res_u2 = (str(c.fetchone()[0]))
                res_u2 = str(ec.get_public_key(res_u2))
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(shared_key), modes.CTR(iv),backend = default_backend())
                print 'Username is' + username
                print shared_key_u2
                res_u1 = res_u1.encode('utf-8')
                res_u2 = res_u2.encode('utf-8')
                username = username.encode('utf-8')
                shared_key_u2= shared_key_u2.encode('utf-8')
                encrypted_username = Encrypt.encrypt(username,shared_key_u2,iv)
                encrypted_pku1 = Encrypt.encrypt(res_u1,shared_key_u2,iv) 
                encrypted_pku2 = Encrypt.encrypt(res_u2,shared_key,iv)
                shared_encrypted_username = Encrypt.encrypt(encrypted_username,shared_key,iv) 
                shared_encrypted_pku1 = Encrypt.encrypt(encrypted_pku1,shared_key,iv)
                rply.public_key_u1 = (base64.b64encode(shared_encrypted_pku1)).encode('utf-8')
                rply.public_key_u2 = (base64.b64encode(encrypted_pku2)).encode('utf-8')
                rply.username = (base64.b64encode(shared_encrypted_username)).encode('utf-8')
                print 'Executed'
                conn.send(rply.SerializeToString())
        else:
            print 'Nonces do not match'


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
                sign_in(conn,addr,server_private_key,server_public_key)   # just copy payload
                print 'Sign in is done'
        if (rqst.type == pb_example_pb2.Request.LOGOUT):
            logout(user_name,conn,server_private_key,server_public_key)

        if rqst.type == pb_example_pb2.Request.TALK:           
            process_talk(conn,rqst)

while 1:
    print "Listening again"
    conn, addr = sock.accept()	# accept connection from client
    print 'ADDR : '+ str(addr[1])
    print 'CONN : '+ str(conn)
    data = conn.recv(BUFFER_SIZE)
    rqst.ParseFromString(data)  # parse message
    if rqst.type == pb_example_pb2.Request.POF_1:
        sqlconn = sqlite3.connect("db.sqlite")
        c = sqlconn.cursor()
        print "Querying for first time"
        sec = randint(1, 1000000)
        print "The secret is "+str(sec)
        print "The ip is "+addr[0]
        print "The port is "+str(addr[1])
        sec_hash = CommonMethod().generate_hash(addr[0]+str(addr[1])+str(sec))
        sql = "INSERT into proof_of_work ('ip', 'port', 'sec') values (?, ?, ?)"
        c.execute(sql,(addr[0],addr[1],sec))
        sqlconn.commit()
        sqlconn.close()
        rply.hash = base64.b64encode(sec_hash)
        rply.ip = addr[0]
        rply.port = str(addr[1])
        conn.send(rply.SerializeToString())
        conn.close()
        continue
    if rqst.type == pb_example_pb2.Request.POF_2:    
        sqlconn = sqlite3.connect("db.sqlite")
        c = sqlconn.cursor()
        ip = rqst.ip
        port = rqst.port
        print "The secret is "+rqst.payload
        print "The ip is "+ip
        print "The port is "+port
        sql = "SELECT sec from proof_of_work WHERE ip = ? and port = ?"
        sql_querry = c.execute(sql,(ip,port))
        sec = sql_querry.fetchone()
        sql = 'DELETE from proof_of_work WHERE ip = ? and port = ?'
        c.execute(sql,(ip,port))
        sqlconn.commit()
        sqlconn.close()
        print "Quering with sec"
        print "The secret fetched from database is "+str(sec)
        if rqst.payload == str(sec[0]):
            rply.pof_success = True
            conn.send(rply.SerializeToString())
            start_new_thread(start_connection,(conn,addr))
            print 'Connection address:', addr
        else:
            rply.pof_success = False
            print "Secret returned is not correct"
            conn.send(rply.SerializeToString())
            
