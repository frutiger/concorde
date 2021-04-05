# concorde.client.acme

import base64
import json

import cryptography
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives            import hashes

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

def utf8_json(obj: object) -> bytes:
    return json.dumps(obj,
                      sort_keys=True,
                      separators=(',', ':')).encode('utf-8')

def urlsafe_b64(bytes) -> bytes:
    return base64.urlsafe_b64encode(bytes).rstrip(b'=')

def urlsafe_b64_uint(n: int, size: int) -> bytes:
    as_bytes = n.to_bytes(size, 'big')
    return urlsafe_b64(as_bytes)

def pubkey_to_jwk(key):
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP384R1):
            curve = 'P-384'
        else:
            raise ValueError(f'Unsupported curve type: {key.curve.name}')

        key_size_bytes = (key.key_size + 7) // 8
        numbers = key.public_numbers()
        x = urlsafe_b64_uint(numbers.x, key_size_bytes)
        y = urlsafe_b64_uint(numbers.y, key_size_bytes)
        return {
            'kty': 'EC',
            'crv': curve,
            'x':   x.decode('ascii'),
            'y':   y.decode('ascii'),
        }
    else:
        raise ValueError('Unsupported key type: ' + str(type(key)))

def thumbprint(pubkey):
    hasher = hashes.Hash(hashes.SHA256(), backend)
    hasher.update(utf8_json(pubkey_to_jwk(pubkey)))
    return urlsafe_b64(hasher.finalize())

def sign(key, header, payload):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP384R1):
            header['alg'] = 'ES384'
        else:
            raise ValueError(f'Unsupported curve type: {key.curve.name}')
    else:
        raise ValueError('Unsupported key type: ' + str(type(key)))

    if 'kid' not in header:
        header['jwk'] = pubkey_to_jwk(key.public_key())

    protected = urlsafe_b64(utf8_json(header))
    if payload == None:
        payload = b''
    else:
        payload = urlsafe_b64(utf8_json(payload))
    message = protected + b'.' + payload

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP384R1):
            signature = key.sign(message, ec.ECDSA(hashes.SHA384()))
        else:
            raise ValueError(f'Unsupported curve type: {key.curve.name}')
        key_size_bytes = (key.key_size + 7) // 8
        r, s = utils.decode_dss_signature(signature)
        signature = urlsafe_b64_uint(r, key_size_bytes) + \
                    urlsafe_b64_uint(s, key_size_bytes)
    else:
        raise ValueError('Unsupported key type: ' + str(type(key)))

    return {
        'protected': protected.decode('ascii'),
        'payload':   payload.decode('ascii'),
        'signature': signature.decode('ascii'),
    }

