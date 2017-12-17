import sqlite3

"""facebook = {
	"events" :	[
		{"name" : "HackWitus 2017!",
		"start_time" : "2017/11/18 09:00",
		"end_time" : "2017/11/19 12:00"
		}

	]
}
file = open("facebook.json","wb")
jn = json.dumps(facebook,ensure_ascii=False)
file.write(jn)
file.close"""
conn = sqlite3.connect("db.sqlite")
c = conn.cursor()

c.execute("DROP TABLE IF EXISTS active_users")
#Table 1
table_name1 = 'active_users' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'shared_key'
field_type = 'TEXT'
field_3 = 'public_key'
field_type = 'TEXT'
field_4 = 'key_salt'
field_type = 'TEXT'
field_5 = 'port'
field_type = 'INTEGER'
field_6 = 'ip'
field_type = 'TEXT'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft}, {f3} {ft}, {f4} {ft}, {f5} {ft}, {f6} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3, f4=field_4, f5=field_5, f6=field_6, ft=field_type))

c.execute("DROP TABLE IF EXISTS users")
#Table 2
table_name1 = 'users' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'password_hash'
field_type = 'TEXT'
field_3 = 'salt'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft},{f3} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3, ft=field_type))


c.execute("DROP TABLE IF EXISTS user_public_key")
#Table 3
table_name1 = 'user_public_key' 
field_1 = 'name'
field_type = 'TEXT'
field_2 = 'public_key'
field_type = 'TEXT'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, ft=field_type))

c.execute("DROP TABLE IF EXISTS proof_of_work")
#Table 4
table_name1 = 'proof_of_work'
field_1 = 'ip'
field_type = 'TEXT'
field_2 = 'port'
field_3 = 'sec'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft}, {f3} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3, ft=field_type))
conn.commit()
conn.close()

"""
#Table 4
table_name1 = 'users_friend' 
field_1 = 'user_id'
field_type = 'TEXT'
field_2 = 'friend_id'
field_type = 'TEXT'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, ft=field_type))

#Table 5
table_name1 = 'spotify_user' 
field_1 = 'artist_id'
field_type = 'TEXT'
field_2 = 'spot_id'
field_type = 'TEXT'
field_3 = 'user_id'
field_type = 'TEXT'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft}, {f3} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3, ft=field_type))

#Table 6
table_name1 = 'artists' 
field_1 = 'artist_id'
field_type = 'TEXT'
field_2 = 'artist_name'
field_type = 'TEXT'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, ft=field_type))

#Table 7
table_name1 = 'latest_releases' 
field_1 = 'date'
field_type = 'TEXT'
field_2 = 'track_name'
field_type = 'TEXT'
field_3 = 'artist_id'
field_type = 'TEXT'
c.execute('CREATE TABLE {tn} ({f1} {ft}, {f2} {ft}, {f3} {ft})'\
        .format(tn=table_name1, f1=field_1, f2=field_2, f3=field_3, ft=field_type))
"""