from fcrypt import CommonMethod, Encrypt, Decrypt
from random import *
import binascii

class Phase_1:

	@classmethod
	def find_secret(cls,sec_hash,ip_addr):
		for i in range(1000000):
			temp_hash = CommonMethod().generate_hash(ip_addr.encode('UTF-8')+str(i).encode('UTF-8'))
			if temp_hash == sec_hash:
				return i


if __name__ == '__main__':
	sec = randint(1, 1000000)
	sec_hash = CommonMethod().generate_hash('9090'+str(sec))
	g = 2
	a = int(binascii.hexlify(sec_hash), base=16)
	a = int(str(a)[:4])
	print pow(g,a)
	#found_sec = Phase_1().find_secret(sec_hash,'9090')
	#print 'input was '+str(sec)+' and the output is '+ str(found_sec)


