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
senaparapassar = str(encrypted)
paravoltaraonormal = senaparapassar.encode()

print(encrypted == paravoltaraonormal)

key = private_key.decrypt(
				paravoltaraonormal,
				padding.OAEP(mgf=padding.MGF1(
					algorithm=hashes.SHA512()),
					algorithm=hashes.SHA512(),
					label=None
				)
			)
print(key)















