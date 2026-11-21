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

def load_csr(pem):
    # return the DER encoding and the set of names (CN and DNS SANs) of the PEM
    # encoded CSR, raising 'ValueError' if it is malformed or badly signed
    csr = x509.load_pem_x509_csr(pem, backend)
    if not csr.is_signature_valid:
        raise ValueError('signature is not valid')

    names = {a.value for a in
             csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)}
    try:
        san = csr.extensions.get_extension_for_class(
                                                 x509.SubjectAlternativeName)
        names.update(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    return csr.public_bytes(serialization.Encoding.DER), names
