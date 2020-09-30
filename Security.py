from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64decode, b64encode
import hashlib
import os


def rsaDumpKey(publicKey):
    pem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem = pem.decode()
    return pem


def rsaLoadKey(pem):
    return serialization.load_pem_public_key(pem.encode())


def rsaKeyPair():
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    publicKey = privateKey.public_key()
    return publicKey, privateKey


def rsaEncrypt(plainText,publicKey):
    cipherText = publicKey.encrypt(
        plainText,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    return b64encode(cipherText)


def rsaDecrypt(cipherText,privateKey):
    cipherText = b64decode(cipherText)
    return privateKey.decrypt(
        cipherText,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsaSign(data,privateKey):
    data = b64decode(data)
    signature = privateKey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return b64encode(signature).decode()


def rsaVerify(data,signature,publicKey):
    data = b64decode(data)
    signature = b64decode(signature)
    try:
        publicKey.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def rsaReadPublicKey(path):
    f = open(path,'rb')
    data = f.read()
    f.close()
    key = load_pem_public_key(data)
    return key


def rsaReadPrivateKey(path):
    f = open(path,'rb')
    data = f.read()
    f.close()
    key = load_pem_private_key(data, password=None)
    return key


def rsaWritePrivateKey(privateKey,path):
    f = open(path,'wb')
    pem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(pem)
    f.close()


def rsaWritePublicKey(publicKey,path):
    f = open(path,'wb')
    pem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    f.write(pem)
    f.close()


def aesKey():
    key = Fernet.generate_key()
    return key.decode()


def aesEncrypt(plainText,key):
    key = key.encode()
    cipher = Fernet(key)
    cipherText = cipher.encrypt(plainText)
    return cipherText


def aesDecrypt(cipherText,key):
    key = key.encode()
    cipher = Fernet(key)
    plainText = cipher.decrypt(cipherText)
    return plainText


def shaHash(data):
    sha = hashlib.sha256()
    bytecode = data.encode()
    sha.update(bytecode)
    digest = sha.digest()
    return b64encode(digest).decode()


def nonce():
    return b64encode(os.urandom(8)).decode()


if __name__ == '__main__':

   public, private = rsaKeyPair()
   rsaWritePrivateKey(private,'private.pem')
   rsaWritePublicKey(public,'public.pem')