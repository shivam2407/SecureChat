
Username
Password
shivam
any
Prachi
test
ashu
ashu
CREDENTIALS


Instruction to run: (In case of doubt email us at rawat.s@husky.neu.edu)

1. UnZip the folder than go inside the folder and open the terminal in that folder. Make sure you have python2.7.

2. if you don’t have virtualenv installed run bellow command

	$ [sudo] pip install virtualenv

3. Then open virtual environment for that run below command

	$ source ns-virtual/bin/activate

4. Now we need to make DB for that run below command

	$ python make-db.py
	$ python insert-data.py

5. Now we need to exract protocol puffer to python file

	 $protoc --python_out=. pb-example.proto


6. Now we need to run server for that run below command

	$python server.py -pr PRIVATE KEY -pu PUBLIC KEY -p PORT

7. Now you can run as many as client you want here. You might have to wait few seconds(10-20sec) as client will do proof of work before initiating the signin.

	$ python client.py -u USERNAME -pass PASSWORD -ip IP -p PORT -pr CLIENT PRIVATE KEY -pu CLIENT PUBLIC KEY -sk SOURCE PUBLIC KEY 

Important: We were not able to implement send so you won’t find send option. For LIST enter 1 and or LOGOUT enter 2 and than press enter. 





Vulnerabilities:

1. In our code for logout and Phase-2 we are encrypting and decrypting nonces by itself and not in any combination with other field. So an adversary can simply send the nonce back without decrypting it and prove it’s identity. We can stop this attack by making protocol where we send nonce received subtracted 1 instead of same nonce.

2. Phase_2 and logout are quite similar in our code where an adversary can simply change type of packet and make user logout. We can remove this vulnerability by changing the way we send back the nonce for example in one protocol we will send nonce-1 in other nonce-2 and so on. This way if adversary changes the type the server will not complete the instruction as the nonce will not match.

3. We are providing proof of work only when user logs in. In ideal case we will do that at every single step i.e. when it ask for list.

Assumptions:

1. Every username will be unique and the password which server store for each user will be unique as well.

2. The private and public key for clients will be unique and server doesn’t have to worry about it as the public key will assigned to user by CA which keep takes care of this.

3. Here we are giving access to Client and server of same database but in real world we will keep two different database one for client and one for user.

