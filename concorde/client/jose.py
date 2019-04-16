# concorde.client.jose

import base64
import json

import cryptography
from cryptography.hazmat.primitives            import asymmetric
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives            import hashes
from cryptography.hazmat.primitives            import hmac

# TBD: make backend pluggable?
backend = cryptography.hazmat.backends.default_backend()

def acme_safe_b64_encode(bytes):
    return base64.urlsafe_b64encode(bytes).replace(b'=', b'')

def bytes_to_jwk(bytes):
    return base64.urlsafe_b64encode(bytes).decode('ascii')

def jwk_to_bytes(jwk):
    return base64.urlsafe_b64decode(jwk.encode('ascii'))

def uint_to_jwk(n):
    size = (n.bit_length() + 7) // 8
    return acme_safe_b64_encode(n.to_bytes(size, 'big')).decode('ascii')

def jwk_to_uint(jwk):
    return int.from_bytes(base64.urlsafe_b64decode(jwk.encode('ascii')), 'big')

def curve_to_jwk(curve):
    if curve == 'secp256k1':
        return 'P-256'
    elif curve == 'secp384k1':
        return 'P-384'
    elif curve == 'secp521k1':
        return 'P-521'
    else:
        raise ValueError('RFC 7518 non-compliant curve: ' + curve)

def jwk_to_curve(jwk):
    if jwk == 'P-256':
        return 'secp256k1'
    elif jwk == 'P-384':
        return 'secp384k1'
    elif jwk == 'P-521':
        return 'secp521k1'
    else:
        raise ValueError('RFC 7518 non-compliant curve: ' + jwk)

def pubkey_to_jwk(pubkey):
    if isinstance(pubkey, bytes):
        return {
            'kty': 'oct',
            'k': bytes_to_jwk(pubkey),
        }

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        numbers = pubkey.public_numbers()
        return {
            'kty': 'EC',
            'crv': curve_to_jwk(pubkey.curve.name),
            'x':   uint_to_jwk(numbers.x),
            'y':   uint_to_jwk(numbers.y),
        }

    if isinstance(pubkey, rsa.RSAPublicKey):
        numbers = pubkey.public_numbers()
        return {
            'kty': 'RSA',
            'n':   uint_to_jwk(numbers.n),
            'e':   uint_to_jwk(numbers.e),
        }

    raise ValueError('Unsupported public key: ' + str(type(pubkey)))

def jwk_to_pubkey(jwk):
    if jwk['kty'] == 'oct':
        return jwk_to_bytes(jwk['k'])
    elif jwk['kty'] == 'EC':
        numbers = ec.EllipticCurvePublicNumbers(jwk_to_uint(jwk['x']),
                                                jwk_to_uint(jwk['y']),
                                                jwk_to_curve(jwk['crv']))
        return numbers.public_key(backend)
    elif jwk['kty'] == 'RSA':
        numbers = rsa.RSAPublicNumbers(jwk_to_uint(jwk['e']),
                                       jwk_to_uint(jwk['n']))
        return numbers.public_key(backend)

def jwk_thumbprint(pubkey, digest=hashes.SHA256):
    jwk       = pubkey_to_jwk(pubkey)
    canonical = json.dumps(jwk,
                           sort_keys=True,
                           separators=(',', ':')).encode('utf-8')
    hasher    = hashes.Hash(digest(), backend)
    hasher.update(canonical)
    return acme_safe_b64_encode(hasher.finalize())

def jws_safe_obj(obj):
    return acme_safe_b64_encode(json.dumps(obj).encode('utf-8'))

def key_to_pubkey(key):
    if isinstance(key, bytes):
        return key
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return key.public_key()
    elif isinstance(key, rsa.RSAPrivateKey):
        return key.public_key()
    else:
        raise ValueError('RFC 7518 non-compliant key: ' + str(type(key)))

def jws_encapsulate(key,
                    header,
                    payload,
                    digest=hashes.SHA256,
                    padder=asymmetric.padding.PKCS1v15):
    if digest == hashes.SHA256:
        suffix = '256'
    elif digest == hashes.SHA384:
        suffix = '384'
    elif digest == hashes.SHA512:
        suffix = '512'
    else:
        raise ValueError('RFC 7518 non-compliant digest: ' + digest)

    if isinstance(key, bytes):
        algorithm = 'HS' + suffix
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        algorithm = 'ES' + suffix
    elif isinstance(key, rsa.RSAPrivateKey):
        if padder == asymmetric.padding.PSS:
            algorithm = 'PS' + suffix
        elif padder == asymmetric.padding.PKCS1v15:
            algorithm = 'RS' + suffix
        else:
            raise ValueError('RFC 7518 non-compliant padding: ' + \
                             str(type(padder)))
    else:
        raise ValueError('RFC 7518 non-compliant key: ' + str(type(key)))

    pubkey = key_to_pubkey(key)

    header['alg'] = algorithm
    header['jwk'] = pubkey_to_jwk(pubkey)

    protected = jws_safe_obj(header)
    payload   = jws_safe_obj(payload)
    message   = protected + b'.' + payload

    if isinstance(key, bytes):
        signer = hmac.HMAC(key, digest(), backend)
        signer.update(message)
        signature = signer.finalize()
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        signature = key.sign(message, ec.ECDSA(digest()))
    elif isinstance(key, rsa.RSAPrivateKey):
        if padder == asymmetric.padding.PSS:
            signature = key.sign(message,
                                 padder(asymmetric.padding.MGF1(digest()),
                                        padder.MAX_LENGTH),
                                 digest())
        elif padder == asymmetric.padding.PKCS1v15:
            signature = key.sign(message, padder(), digest())
        else:
            raise ValueError('RFC 7518 non-compliant padding: ' + \
                             str(type(padder)))
    else:
        raise ValueError('RFC 7518 non-compliant key: ' + str(type(key)))

    signature = acme_safe_b64_encode(signature)

    return json.dumps({
        'protected': protected.decode('ascii'),
        'payload':   payload.decode('ascii'),
        'signature': signature.decode('ascii'),
    }).encode('ascii')

