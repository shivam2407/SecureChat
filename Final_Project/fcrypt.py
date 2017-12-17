import sys
import os
import json
import base64
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import *

# The format in which data will be stored in cipher text file
cipher_dict = {"cipher_text": "", "symmetric_key": "", "random_number": "", "hmac": "", "signature": "", "hmac_key": ""}


class CommonMethod:
    """This class includes every method which can be used in both encrypt and decrypt mode"""
    def __init__(self):
        pass

    @classmethod
    def read_text(cls, file_name):  # This method is reading text from file given as parameter
        try:
            file_object=open(file_name, 'rb')
            input_text = file_object.read()
            if len(input_text) == 0:
                print("No Input in file")
            file_object.close()
            return input_text
        except Exception:
            print("Seems like there was some error in opening file: ", file_name, "so closing program")
            exit()

    @classmethod
    def generate_hash(cls, message):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        ans = digest.finalize()
        return ans

    @classmethod
    def get_private_key(cls, file_name):  # This method is fetching private_key
        #try:
            if file_name[-3:] == "pem":  # Checking whether the file is of .pem format.
                with open(file_name, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend())
                    return private_key
            elif file_name[-3:] == "der":  # Checking whether the file is of .der format.
                with open(file_name, "rb") as key_file:
                    private_key = serialization.load_der_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend())
                    return private_key
            else:
                print("Wrong format of private key provided. Closing the program")
                exit()
        #except Exception:
        #    print("Something went wrong with fetching your private key!")
        #    exit()

    @classmethod
    def get_public_key(cls, file_name):  # Fetching the public key
        #try:
            if file_name[-3:] == "der":  # Checking whether the file is of .der format.
                with open(file_name, "rb") as key_file:
                    public_key = serialization.load_der_public_key(
                        key_file.read(),
                        backend=default_backend())
                    return public_key
            elif file_name[-3:] == "pem":  # Checking whether the file is of .pem format.
                with open(file_name, "rb") as key_file:
                    public_key = serialization.load_pem_public_key(
                        key_file.read(),
                        backend=default_backend())
                    return public_key
            else:
                print("Wrong format of public key provided. Closing the program")
                exit()
        #except Exception:
        #    print("Something went wrong with fetching your public key")
        #    exit()

    @classmethod
    def write_text(cls, file_name, text):  # Writing data into file
        file_object = open(file_name, 'wb')
        file_object.write(text)
        file_object.close()


class Encrypt:
    """This class contains method related to encryption"""

    def __init__(self):
        pass

    @classmethod
    def asy_encrpt_key(cls, key, public_key):  # Encrypting data using destination public key
        try:
            cipher_key = public_key.encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            return cipher_key
        except ValueError:
            print("Message size was too long!")
            exit()

    @classmethod
    def generate_hmac(cls):  # Generating hash using HMAC
        try:
            key = os.urandom(16)
            # Encrypting HMAC key using destination public_key
            cipher_dict["hmac_key"] = base64.b64encode(cls.asy_encrpt_key(key, destination_public_key))
            hmac_value = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            hmac_value.update(cipher_dict["cipher_text"])  # Adding cipher_text, Symmetric_key and random_number to
            hmac_value.update(cipher_dict["symmetric_key"])  # hash so that if anyone changes the hash wont match.
            hmac_value.update(cipher_dict["random_number"])
            hash_generated = hmac_value.finalize()
            cipher_dict["cipher_text"] = base64.b64encode(cipher_dict["cipher_text"])
            cipher_dict["hmac"] = base64.b64encode(hash_generated)
            cipher_dict["symmetric_key"] = base64.b64encode(cipher_dict["symmetric_key"])
            cipher_dict["random_number"] = base64.b64encode(cipher_dict["random_number"])
            json_object = json.dumps(cipher_dict, ensure_ascii=False)
            return json_object
        except Exception:
            print("Something went wrong while generating HMAC hash")
            exit()

    @classmethod
    def sign_message(cls):  # Signing the message using senders private_key on plain_text
        try:
            signature = source_private_key.sign(
                input_plain_text,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            cipher_dict["signature"] = base64.b64encode(signature)
        except Exception:
            print("Something went wrong while signing the message")
            exit()

    @classmethod
    def encrypt(cls, plain_text,key,iv):  # Encrypting plaint_text using symmetric key
        # The encryption code goes here. Right now I am simply returning the file
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CFB(iv),
                backend=default_backend())
            encryptor = cipher.encryptor()
            cipher_text = encryptor.update(plain_text) + encryptor.finalize()
            # Encrypting symmetric key and random number using destination public key.
            #cipher_key = cls.asy_encrpt_key(key, destination_public_key)
            #cipher_random_number = cls.asy_encrpt_key(iv, destination_public_key)
            #cipher_dict["cipher_text"] = cipher_text
            #cipher_dict["symmetric_key"] = cipher_key
            #cipher_dict["random_number"] = cipher_random_number
            return cipher_text
        except Exception:
            print("Something went wrong while encrypting plain text")
            exit()


class Decrypt:

    def __init__(self):
        pass

    @classmethod
    def is_hmac_equal(cls, input_dict):  # This verifying HMAC
        try:
            h = hmac.HMAC(cls.asyn_decrypt(base64.b64decode(input_dict["hmac_key"])), hashes.SHA256(), backend=default_backend())
            h.update(base64.b64decode(input_dict["cipher_text"]))
            h.update(base64.b64decode(input_dict["symmetric_key"]))
            h.update(base64.b64decode(input_dict["random_number"]))
            h.verify(base64.b64decode(input_dict["hmac"]))
        except InvalidSignature:
            print("Seems like you have changed the message Boo! Closing program Bye....")
            exit()

    @classmethod
    def is_sign_same(cls, input_dict):  # Verifying the sign of message
        try:
            source_public_key.verify(
                base64.b64decode(input_dict["signature"]),
                destination_plain_text,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            print("Seems like you are not the one who you say you are! Closing program Bye....")
            exit()



    @classmethod
    def asyn_decrypt(cls, message,destination_private_key):  # Decrypting message using destination private_key
        try:
            value = destination_private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            return value
        except Exception:
            print("Something went wrong with decrypting using RSA2048")
            exit()

    @classmethod
    def decrypt_message(cls, cipher_text, symmetric_key, iv):  # Decrypting message using symmetric key
        try:
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
            decrypter = cipher.decryptor()
            plain_text = decrypter.update(cipher_text) + decrypter.finalize()
            return plain_text
        except Exception:
            print("Something went wrong while decrypting the message")
            exit()

if __name__ == '__main__':
    # checking whether the input is correct or not
    if len(sys.argv) == 6 and sys.argv[1] == "-e":
        ec = CommonMethod
        input_plain_text = ec.read_text(sys.argv[4])
        source_private_key = ec.get_private_key(sys.argv[3])
        destination_public_key = ec.get_public_key(sys.argv[2])
        Encrypt.encrypt(input_plain_text)
        Encrypt.sign_message()
        cipher_dict = Encrypt.generate_hmac()
        ec.write_text(sys.argv[5], cipher_dict)

    elif len(sys.argv) == 6 and sys.argv[1] == "-d":
        dc = CommonMethod
        input_cipher_text = dc.read_text(sys.argv[4])
        destination_private_key = dc.get_private_key(sys.argv[2])
        source_public_key = dc.get_public_key(sys.argv[3])
        input_dict = json.loads(input_cipher_text)
        Decrypt.is_hmac_equal(input_dict)
        destination_plain_text = Decrypt.decrypt_message(input_dict)
        Decrypt.is_sign_same(input_dict)
        dc.write_text(sys.argv[5], destination_plain_text)
    else:
        print("Incorrect Input.")
        print("The format is 'python fcrypt.py -e destination_public_key_filename"),
        print(" sender_private_key_filename input_plaintext_file ciphertext_file'")