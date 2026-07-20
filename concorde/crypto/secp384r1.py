# concorde.crpyto.secp384r1

import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives            import serialization

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

def key_opener(path, flags):
    # for use as the 'opener' of the builtin 'open', to keep private keys
    # readable by the owner only
    return os.open(path, flags, 0o600)

def make_key():
    return ec.generate_private_key(ec.SECP384R1(), backend)

def to_file(key, f):
    f.write(key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))

def from_file(f):
    return serialization.load_pem_private_key(f.read(), None, backend)
