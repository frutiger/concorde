# concorde.crpyto.x509

from cryptography import x509

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

def get_expiry(pem):
    return x509.load_pem_x509_certificate(pem, backend).not_valid_after

