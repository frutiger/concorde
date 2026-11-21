# concorde.crpyto.x509

from cryptography                   import x509
from cryptography.hazmat.primitives import hashes, serialization

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

def get_expiry(pem):
    return x509.load_pem_x509_certificate(pem, backend).not_valid_after_utc

def make_csr(key, names):
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, names[0])]
    ))
    builder = builder.add_extension(x509.SubjectAlternativeName(
        [x509.DNSName(name) for name in names]
    ), critical=True)
    csr = builder.sign(key, hashes.SHA256(), backend)
    return csr.public_bytes(serialization.Encoding.DER)
