# shaman.profile

import datetime
import json
import subprocess
import time

import cryptography
from cryptography                              import x509
from cryptography.hazmat.primitives            import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives            import hashes

from ..client      import Client, ClientError
from ..client.jose import jwk_thumbprint

# TBD: make backend pluggable?
backend = cryptography.hazmat.backends.default_backend()

class Profile:
    def __init__(self):
        self._filename = 'shaman.json'
        with open(self._filename) as f:
            self._config = json.load(f)
        self._client = Client(self._config['server'])

    def _write_config(self):
        with open(self._filename, 'w') as f:
            json.dump(self._config, f, indent=4)

    def _generate_account_key(self, path):
        print('[account] generating key...')
        key = rsa.generate_private_key(65537, 4096, backend)
        with open(path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        print('[account] done')

        return key

    def _add_account(self):
        path = 'account_key'
        key = self._generate_account_key(path)

        print('[account] registering...')
        location, _ = self._client.new_registration(key)
        self._config['account'] = {
            'key': path,
            'key_type': 'pem',
            'registration': location,
        }
        self._write_config()
        print('[account] done: {}'.format(location))

        return location, key

    def _check_or_add_account(self):
        if 'account' in self._config:
            account = self._config['account']
            with open(account['key'], 'rb') as f:
                data = f.read()

            if account['key_type'] == 'raw':
                key = data
            elif account['key_type'] == 'pem':
                key = serialization.load_pem_private_key(data, None, backend)
            elif account['key_type'] == 'der':
                key = serialization.load_der_private_key(data, None, backend)
            else:
                raise RuntimeError('Unknown key type: ' + account['key_type'])

            registration = account['registration']
        else:
            registration, key = self._add_account()

        links, account = self._client.registration(key, registration)
        agreement = links.get('terms-of-service', {}).get('url')
        if account.get('agreement') != agreement:
            print('[account] accepting {} in 5 seconds...'.format(agreement))
            time.sleep(5)
            self._client.registration(key, registration, agreement)
            print('[account] done')

        return key

    def _add_authorization(self, name, domain):
        print('[domain:{}] requesting authz...'.format(name))
        authz, _ = self._client.new_authorization(self._key, 'dns', name)
        domain['authorization'] = authz
        self._write_config()
        print('[domain:{}] done: {}'.format(name, authz))

        return authz

    def _respond_challenges(self,
                            name,
                            challenges,
                            combinations,
                            authenticators):
        requirements = []
        for combination in combinations:
            requirement = []
            for challenge in combination:
                requirement.append(challenges[challenge])
            requirements.append(requirement)

        for requirement in requirements:
            if all(c['type'] in authenticators for c in requirement):
                break
        else:
            human_error = ' or '.join(' and '.join(c['type'] for c in r) \
                                                         for r in requirements)
            raise RuntimeError('No available authenticators for challenge. ' +
                               'Needed: ' + human_error)

        for challenge in requirement:
            if challenge['status'] != 'pending':
                continue

            token             = challenge['token'].encode('ascii')
            thumbprint        = jwk_thumbprint(self._key.public_key())
            key_authorization = token + b'.' + thumbprint
            print('[domain:{}] authenticating with {}...'.format(
                                                            name,
                                                            challenge['type']))
            auth = subprocess.Popen([authenticators[challenge['type']]],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL)
            auth.communicate(input=token + b'\n' + key_authorization + b'\n')
            if auth.returncode:
                raise RuntimeError('Failed to run {}'.format(
                                                            challenge['type']))
            print('[domain:{}] done'.format(name))

            print('[domain:{}] replying to challenge...'.format(name))
            self._client.challenge(self._key,
                                   challenge['uri'],
                                   key_authorization.decode('ascii'))
            print('[domain:{}] done'.format(name))

    def _check_or_add_authorization(self, name, domain):
        if 'authorization' in domain:
            # TBD: check authorization expiry
            authorization = domain['authorization']
        else:
            authorization = self._add_authorization(name, domain)

        authz = self._client.get_authorization(authorization)
        if authz['status'] == 'pending':
            self._respond_challenges(name,
                                     authz['challenges'],
                                     authz['combinations'],
                                     domain['authenticators'])
        elif authz['status'] == 'valid':
            return authorization
        else:
            print('[domain:{}] authz ({}) was {}'.format(name,
                                                         authorization,
                                                         authz['status']))
            authz = self._add_authorization(name, domain)

    def _add_domain_key(self, name, domain, path):
        print('[domain:{}] generating key...'.format(name))
        key = rsa.generate_private_key(65537, 4096, backend)
        with open(path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        domain['key'] = path
        domain['key_type'] = 'pem'
        self._write_config()
        print('[domain:{}] done'.format(name))

        return key

    def _check_or_add_domain_key(self, name, domain):
        if 'key' in domain:
            with open(domain['key'], 'rb') as f:
                data = f.read()

            if domain['key_type'] == 'raw':
                return data
            elif domain['key_type'] == 'pem':
                return serialization.load_pem_private_key(data, None, backend)
            elif domain['key_type'] == 'der':
                return serialization.load_der_private_key(data, None, backend)
            else:
                raise RuntimeError('Unknown key type: ' + account['key_type'])
        else:
            return self._add_domain_key(name, domain, name + '_key')

    def _check_or_add_cert(self, name, domain, key, authorization):
        if 'certificate' in domain:
            return domain['certificate']

        print('[domain:{}] generating CSR...'.format(name))
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, name),
        ]))
        csr = builder.sign(key, hashes.SHA256(), backend)
        print('[domain:{}] done'.format(name))

        print('[domain:{}] requesting certificate...'.format(name))
        certificate = self._client.new_certificate(self._key, csr)
        domain['certificate'] = certificate
        self._write_config()
        print('[domain:{}] done: {}'.format(name, certificate))

        return certificate

    def _check_cert_validity(self, name, domain, cert):
        renewal = self._config['renewal']
        if cert.not_valid_after - datetime.timedelta(renewal) \
                                                     < datetime.datetime.now():
            print('[domain:{}] cert will expire in {} days'.format(name,
                                                                   renewal))
            del domain['certificate']
            self._write_config()

            print('[domain:{}] obtaining replacement certificate...'.format(
                                                                         name))
            self._check_domain(name, domain)
            print('[domain:{}] done'.format(name))

            print('[domain:{}] revoking old certificate...'.format(name))
            self._client.revoke_certificate(self._key, cert)
            print('[domain:{}] done'.format(name))

    def _check_domain(self, name, domain):
        authorization = self._check_or_add_authorization(name, domain)
        if not authorization:
            return

        key  = self._check_or_add_domain_key(name, domain)
        cert = self._check_or_add_cert(name, domain, key, authorization)

        print('[domain:{}] fetching certficate...'.format(name))
        certificate = self._client.get_certificate(cert)
        print('[domain:{}] done'.format(name))

        print('[domain:{}] checking certificate validity...'.format(name))
        self._check_cert_validity(name, domain, certificate)

        print('[domain:{}] fetching certficate chain...'.format(name))
        chain = self._client.get_certificate_chain(cert)
        print('[domain:{}] done'.format(name))

        with open(name + '_full', 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
            f.write(chain.public_bytes(serialization.Encoding.PEM))

    def _check_domains(self):
        for name, domain in self._config['domains'].items():
            try:
                self._check_domain(name, domain)
            except ClientError as e:
                print('[domain:{}] ERROR: {}'.format(name, e.args[0]))

    def run(self):
        self._key = self._check_or_add_account()
        self._check_domains()

