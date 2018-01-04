**Technologies Used**
> Python2.7,
> SQL,
> Google Protocol Buffer.

**Instruction to run:**

1. Make sure you have python2.7(Link for [Installation](https://www.python.org/downloads/release/python-2714/)).

2. if you don’t have virtualenv installed run bellow command.

	``` $ [sudo] pip install virtualenv ```

3. Then open virtual environment for that run below command.

	``` $ source ns-virtual/bin/activate ```

4. Now we need to make DB for that run below command.

	```$ python make-db.py```
	```$ python insert-data.py```

5. Now we need to exract Google Protocol puffer to python file.

	 ``` $protoc --python_out=. pb-example.proto ```

6. Now we need to run server for that run below command.

	```$python server.py -pr PRIVATE KEY -pu PUBLIC KEY -p PORT```

7. Now you can run as many as client you want here. You might have to wait few seconds(10-20sec) as client will do proof of work before initiating the signin.

	```$ python client.py -u USERNAME -pass PASSWORD -ip IP -p PORT -pr CLIENT PRIVATE KEY -pu CLIENT PUBLIC KEY -sk SERVER PUBLIC KEY``` 

| Username | Password |
| -------- | -------- |
| shivam   | any      |
| prachi   | test     |
| ashu     | ashu     |

**CREDENTIALS to be used for logging in.**

You can see our protocol Blueprint in **Blueprint.odp**

Side Note: For LIST enter 1 and for LOGOUT enter 2 and than press enter. Implementation of Send command is incomplete and work in Progress.  

**Don't Use this for academic uses as it can be easily caught by Professor and can result in Catostrophic implication for you**
