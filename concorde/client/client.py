# concorde.client.client

import json

import cryptography
import requests
from cryptography                   import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import acme

import cryptography.hazmat.backends
backend = cryptography.hazmat.backends.default_backend()

class Error(Exception):
    pass

class ServerError(Error):
    def __init__(self, status_code, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.status_code = status_code

class Client:
    def __init__(self, url, key=None, account_id=None):
        self._nonce      = None
        self._key        = key
        self._account_id = account_id

        self._session = requests.Session()
        self._session.headers['content-type'] = 'application/jose+json'

        directory = self._session.get(url)
        directory.raise_for_status()
        self._directory = directory.json()

    def set_account_id(self, account_id):
        if self._account_id != None:
            raise Error(f'Account already set to {self._account_id}')
        self._account_id = account_id

    def get_account_id(self, account_id):
        if self._account_id == None:
            raise Error('Account not yet set')
        return self._account_id
        self._account_id = account_id

    def _needs_account_id(method):
        def result(self, *args, **kwargs):
            if self._account_id == None:
                raise Error('An account ID is required for this operation')
            return method(self, *args, **kwargs)
        return result

    def _post(self, resource, payload=None):
        if self._nonce == None:
            nonce_url = self._directory['newNonce']
            new_nonce = self._session.head(nonce_url)
            new_nonce.raise_for_status()
            self._nonce = new_nonce.headers['Replay-Nonce']

        url = self._directory.get(resource, resource)

        header = {
            'nonce': self._nonce,
            'url':   url,
        }
        if self._account_id != None:
            header['kid'] = self._account_id

        data     = acme.sign(self._key, header, payload)
        response = self._session.post(url, json.dumps(data).encode('ascii'))

        self._nonce = response.headers['Replay-Nonce']

        error_kind = None
        if 400 <= response.status_code < 500:
            error_kind = 'User'
        elif 500 <= response.status_code:
            error_kind = 'Server'
        if error_kind:
            if response.text:
                detail = response.json()['detail']
            else:
                detail = response.reason
            raise ServerError(response.status_code,
                              f'{error_kind} Error: {detail}')

        return response

    @_needs_account_id
    def get(self, resource_id):
        response = self._post(resource_id)
        if response.headers['Content-Type'].startswith('application/json'):
            return response.json()
        else:
            return response.text

    def new_account(self, contacts=None):
        account = self._post('newAccount', {
            'contact':              contacts,
            'termsOfServiceAgreed': True,
        })

        if account.status_code == 200:
            raise Error('Account creation failed, account already exists with '
                        'key')

        if account.status_code == 201:
            return account.headers['Location'], account.json()

    def _get_account_with_key(self):
        account = self._post('newAccount', {
            'onlyReturnExisting': True,
        })

        return account.headers['Location'], account.json()

    @_needs_account_id
    def _get_account_with_id(self):
        account = self._post(self._account_id, {
            'onlyReturnExisting': True,
        })

        return account.json()

    def get_account(self):
        if self._account_id == None:
            return self._get_account_with_key()
        else:
            return self._account_id, self._get_account_with_id()

    @_needs_account_id
    def update_account(self, contacts=None):
        account = self._post(self._account_id, {
            'contact':            contacts,
            'onlyReturnExisting': True,
        })

        return account.json()

    @_needs_account_id
    def new_order(self, identifiers):
        order = self._post('newOrder', {
            'identifiers': identifiers,
        })

        return order.headers['Location'], order.json()

    @_needs_account_id
    def finalize_order(self, order_id, key, names):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name(
            [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, names[0])]
        ))
        builder = builder.add_extension(x509.SubjectAlternativeName(
            [x509.DNSName(name) for name in names]
        ), critical=True)
        csr = builder.sign(key, hashes.SHA256(), backend)
        csr = csr.public_bytes(serialization.Encoding.DER)
        csr = acme.urlsafe_b64(csr).decode('ascii')

        order = self._post(self._post(order_id).json()['finalize'], {
            'csr': csr,
        })

        return order.json()

    @_needs_account_id
    def get_order_certificate(self, order_id):
        certificate_id = self._post(order_id).json()['certificate']
        certificate    = self._post(certificate_id)
        return certificate.text

    @_needs_account_id
    def authorize_challenge(self, challenge_id):
        token    = self._post(challenge_id).json()['token'].encode('ascii')
        key_auth = token + b'.' + acme.thumbprint(self._key.public_key())
        return token, key_auth

    @_needs_account_id
    def validate_challenge(self, challenge_id):
        challenge = self._post(challenge_id, {})
        return challenge.json()

