import sqlite3
import base64
import binascii
from fcrypt import CommonMethod, Encrypt, Decrypt

conn = sqlite3.connect("db.sqlite")
c = conn.cursor()
user_password = 'any'
user_password1 = 'test'
user_password2 = 'ashu'
g = 2
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
#print pow(g,a)
password_hash = CommonMethod().generate_hash(user_password+"123")
password_hash1 = CommonMethod().generate_hash(user_password1+"321")
password_hash2 = CommonMethod().generate_hash(user_password2+"231")
a_1 = str(int(binascii.hexlify(password_hash), base=16))
a_2 = str(int(binascii.hexlify(password_hash1), base=16))
a_3 = str(int(binascii.hexlify(password_hash2), base=16))
pass_1 = str(pow(g,int(a_1),p))
pass_2 = str(pow(g,int(a_2),p))
pass_3 = str(pow(g,int(a_3),p))
user1_public_key = 'user1_public_key.pem'
user2_public_key = 'user2_public_key.pem'

#Table 1
table_name1 = 'active_users' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'shared_key'
field_type = 'TEXT'
field_3 = 'public_key'
field_type = 'TEXT'
field_type = 'TEXT'
field_4 = 'key_salt'
field_type = 'TEXT'
field_5 = 'port'
field_type = 'INTEGER'
field_6 = 'ip'
field_type = 'TEXT'
#c.execute('INSERT INTO  {tn} ({f1}, {f2}, {f3}) VALUES () '.format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3))
#c.execute('INSERT INTO  {tn} ({f1}, {f2}, {f3}) VALUES () '.format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3))

#Table 2
table_name1 = 'users' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'password_hash'
field_type = 'TEXT'
sql = "INSERT INTO users ('name', 'password_hash','salt') VALUES (?, ?, ?)"
c.execute(sql, ('shivam',base64.b64encode(pass_1),"123"))
c.execute(sql, ('prachi',base64.b64encode(pass_2),"321"))
c.execute(sql, ('ashu',base64.b64encode(pass_3),"231"))

table_name1 = 'user_public_key'
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'public key'
field_type = 'TEXT'
sql = "INSERT INTO user_public_key ('name', 'public_key') VALUES (?, ?)"
c.execute (sql, ('shivam','shivam_public_key.pem'))
c.execute (sql, ('prachi','prachi_public_key.pem'))
c.execute (sql, ('prachi','ashu_public_key.pem'))

conn.commit()
conn.close()
print 'Data Inserted'