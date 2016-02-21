# concorde.client.client

import urllib.parse

import cryptography
import requests
from cryptography                   import x509
from cryptography.hazmat.primitives import serialization

from .jose import jws_encapsulate, acme_safe_b64_encode

# TBD: make backend pluggable?
backend = cryptography.hazmat.backends.default_backend()

class ClientError(Exception):
    pass

class Client:
    def __init__(self, url):
        directory = requests.get(url)
        directory.raise_for_status()
        self._url       = url
        self._directory = directory.json()

    def _jws_header(self):
        return {
            'nonce': requests.head(self._url).headers['Replay-Nonce'],
        }

    def new_registration(self, key):
        # tbd: recovery
        payload = {
            'resource': 'new-reg',
        }
        new_reg = requests.post(self._directory['new-reg'],
                                data=jws_encapsulate(key,
                                                     self._jws_header(),
                                                     payload))
        if new_reg.status_code != 201:
            raise ClientError('New registration failed: {}'.format(
                                                     new_reg.json()['detail']))

        return new_reg.headers['Location'], new_reg.json()

    def registration(self, key, registration, agreement=None, contacts=None):
        payload = {
            'resource': 'reg',
        }
        if agreement:
            payload['agreement'] = agreement
        if contacts:
            payload['contact'] = contacts

        reg = requests.post(registration,
                            data=jws_encapsulate(key,
                                                 self._jws_header(),
                                                 payload))
        if reg.status_code != 202:
            raise ClientError('Registration status/update failed: {}'.format(
                                                         reg.json()['detail']))

        return reg.links, reg.json()

    def new_authorization(self, key, type, value):
        payload = {
            'resource': 'new-authz',
            'identifier': {
                'type':  type,
                'value': value,
            }
        }
        new_authz = requests.post(self._directory['new-authz'],
                                  data=jws_encapsulate(key,
                                                       self._jws_header(),
                                                       payload))

        if new_authz.status_code != 201:
            raise ClientError('New authorization request failed: {}'.format(
                                                   new_authz.json()['detail']))

        return new_authz.headers['Location'], new_authz.json()

    def get_authorization(self, authorization):
        authz = requests.get(authorization)
        if authz.status_code != 200:
            raise ClientError('Authorization status failed: {}'.format(
                                                       authz.json()['detail']))

        return authz.json()

    def challenge(self, key, challenge, key_authorization):
        payload = {
            'resource':         'challenge',
            'keyAuthorization': key_authorization,
        }
        response = requests.post(challenge,
                                 data=jws_encapsulate(key,
                                                      self._jws_header(),
                                                      payload))

        if response.status_code != 202:
            raise ClientError('Challenge response failed: {}'.format(
                                                    response.json()['detail']))

    def new_certificate(self, key, csr):
        csr = csr.public_bytes(serialization.Encoding.DER)
        payload = {
            'resource': 'new-cert',
            'csr':      acme_safe_b64_encode(csr).decode('ascii'),
        }
        new_cert = requests.post(self._directory['new-cert'],
                                 data=jws_encapsulate(key,
                                                      self._jws_header(),
                                                      payload))

        if new_cert.status_code != 201:
            raise ClientError('Certificate request failed: {}'.format(
                                                    new_cert.json()['detail']))

        return new_cert.headers['Location']

    def get_certificate(self, certificate):
        cert = requests.get(certificate)
        if cert.status_code != 200:
            raise ClientError('Certificate fetch failed: {}'.format(
                                                        cert.json()['detail']))

        return x509.load_der_x509_certificate(cert.content, backend)

    def get_certificate_chain(self, certificate):
        cert = requests.get(certificate)
        if cert.status_code != 200:
            raise ClientError('Certificate fetch failed: {}'.format(
                                                        cert.json()['detail']))

        if 'up' not in cert.links:
            return

        chain_url = urllib.parse.urljoin(certificate, cert.links['up']['url'])
        chain = requests.get(chain_url)
        if chain.status_code != 200:
            raise ClientError('Certificate chain fetch failed: {}'.format(
                                                        cert.json()['detail']))

        return x509.load_der_x509_certificate(chain.content, backend)

