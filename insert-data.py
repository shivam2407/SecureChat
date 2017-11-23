import sqlite3
import base64
from fcrypt import CommonMethod, Encrypt, Decrypt

conn = sqlite3.connect("db.sqlite")
c = conn.cursor()
user_password = 'any'
salt = str(123)
password_hash = CommonMethod().generate_hash(user_password+salt)
#Table 1
table_name1 = 'active_users' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'shared_key'
field_type = 'TEXT'
field_3 = 'public_key'
field_type = 'TEXT'
#c.execute('INSERT INTO  {tn} ({f1}, {f2}, {f3}) VALUES () '.format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3))
#c.execute('INSERT INTO  {tn} ({f1}, {f2}, {f3}) VALUES () '.format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3))

#Table 2
table_name1 = 'users' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'password_hash'
field_type = 'TEXT'
sql = "INSERT INTO users ('name', 'password_hash') VALUES (?, ?)"
c.execute(sql, ('shivam',base64.b64encode(password_hash)))
conn.commit()
conn.close()
print 'Data Inserted'