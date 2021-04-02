# concorde.client.acme

import base64
import json

import cryptography
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives            import hashes

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

def safe_b64_encode(bytes):
    return base64.urlsafe_b64encode(bytes).replace(b'=', b'')

def bytes_to_jwk(bytes):
    return safe_b64_encode(bytes).decode('ascii')

def uint_to_bytes(n):
    size = (n.bit_length() + 7) // 8
    return n.to_bytes(size, 'big')

def uint_to_jwk(n):
    return safe_b64_encode(uint_to_bytes(n)).decode('ascii')

def canonical_json(obj):
    return json.dumps(obj,
                      sort_keys=True,
                      separators=(',', ':')).encode('utf-8')

def jws_safe_obj(obj):
    return safe_b64_encode(canonical_json(obj))

def pubkey_to_jwk(key):
    if isinstance(key, ec.EllipticCurvePublicKey):
        if isinstance(key.curve, ec.SECP384R1):
            curve = 'P-384'
        else:
            raise ValueError(f'Unsupported curve type: {key.curve.name}')

        numbers = key.public_numbers()
        return {
            'kty': 'EC',
            'crv': curve,
            'x':   uint_to_jwk(numbers.x),
            'y':   uint_to_jwk(numbers.y),
        }
    else:
        raise ValueError('Unsupported key type: ' + str(type(key)))

def thumbprint(pubkey):
    hasher = hashes.Hash(hashes.SHA256(), backend)
    hasher.update(canonical_json(pubkey_to_jwk(pubkey)))
    return safe_b64_encode(hasher.finalize())

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

    protected = jws_safe_obj(header)
    payload   = jws_safe_obj(payload) if payload != None else b''
    message   = protected + b'.' + payload

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if isinstance(key.curve, ec.SECP384R1):
            signature = key.sign(message, ec.ECDSA(hashes.SHA384()))
        else:
            raise ValueError(f'Unsupported curve type: {key.curve.name}')
        r, s = utils.decode_dss_signature(signature)
        signature = safe_b64_encode(uint_to_bytes(r) + uint_to_bytes(s))
    else:
        raise ValueError('Unsupported key type: ' + str(type(key)))

    return {
        'protected': protected.decode('ascii'),
        'payload':   payload.decode('ascii'),
        'signature': signature.decode('ascii'),
    }

