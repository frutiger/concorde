# concorde.crpyto.secp384r1

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives            import serialization

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

def make_key():
    return ec.generate_private_key(ec.SECP384R1, backend)

def to_file(key, f):
    f.write(key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))

def to_bytes(key):
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key.public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

def to_public_bytes(key):
    pubkey = key.public_key()
    return pubkey.public_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw)

def from_file(f):
    return serialization.load_pem_private_key(f.read(), None, backend)

