import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from salsa20 import XSalsa20_xor

backend = default_backend()

def keyPair():
    #gera a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    #gera a public key
    public_key = private_key.public_key()
    return private_key,public_key


private_key, public_key = keyPair()

def getKey():
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
            )
    return salt, kdf.derive(salt)


salt, key = getKey()
print(key)


encrypted = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

print(encrypted)

key = private_key.decrypt(
				encrypted,
				padding.OAEP(mgf=padding.MGF1(
					algorithm=hashes.SHA512()),
					algorithm=hashes.SHA512(),
					label=None
				)
			)
print(key)



def encryptFile(key,algorithm,mode=None,iv=None):
    with open('file.txt', 'r') as file:
        text = file.read()
    text = str.encode(text)
    if algorithm == "AES":
        algorithm_name = algorithms.AES(key)
        bs = int(algorithm_name.block_size / 8)
        missing_bytes = bs - (len(text) % bs)
        if missing_bytes == 0:
            missing_bytes = bs
        padding = bytes([missing_bytes] * missing_bytes)
        text += padding
        print("Text += padding  :: {}".format(text))
        if mode == "CBC":
            cipher = Cipher(algorithm_name, modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            end = encryptor.update(text) + encryptor.finalize()
        elif mode == "GCM":
            aad = b"AES_128_CBC_SHA512"
            aesgcm = AESGCM(key)
            end = aesgcm.encrypt(iv,text,aad)
        else:
            raise (Exception("Invalid mode"))

    elif algorithm == "Salsa20":
        end = XSalsa20_xor(text,iv,key)

    else:
        raise (Exception("Invalid algorithm"))

    with open('output.txt','wb') as file:
        file.write(end)

iv = os.urandom(16)
#encryptFile(key, 'AES', 'CBC',iv)
encryptFile(key, 'AES', 'GCM',iv)
#encryptFile(key,'Salsa20',iv=iv)

def decryptFile(key,algorithm,mode=None,iv=None):
    with open('output.txt', 'rb') as file:
        cryptogram = file.read()
        print(len(cryptogram))
    if algorithm == "AES":
        algorithm_name = algorithms.AES(key)
        if mode == "CBC":
            cipher = Cipher(algorithm_name, modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            end = decryptor.update(cryptogram) + decryptor.finalize()

        elif mode == "GCM":
            aad = b"AES_128_CBC_SHA512"
            aesgcm = AESGCM(key)
            end=aesgcm.decrypt(iv, cryptogram, aad)
        else:
            raise (Exception("Invalid mode"))

        p = end[-1]
        if len(end) < p:
            raise (Exception("Invalid padding. Larger than text"))
        if not 0 < p <= algorithm_name.block_size / 8:
            raise (Exception("Invalid padding. Larger than block size"))
        pa = -1 * p
        end = end[:pa]

    elif algorithm == "Salsa20":
        end = XSalsa20_xor(cryptogram,iv,key)

    else:
        raise (Exception("Invalid algorithm"))


    with open('outputFinal.txt','w') as file:
        file.write(end.decode())


print(iv)
#decryptFile(key, 'AES', 'CBC',iv)
decryptFile(key, 'AES', 'GCM',iv)
#decryptFile(key,'Salsa20',iv=iv)










