# shaman.profile

import datetime
import io
import json
import logging
import logging.handlers
import os
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

logHandler = logging.handlers.SysLogHandler('/dev/log')
logHandler.setFormatter(
                       logging.Formatter('%(levelname)s %(name)s %(message)s'))
logging.getLogger().addHandler(logHandler)

logHandler = logging.StreamHandler()
logHandler.setFormatter(
                       logging.Formatter('%(levelname)s %(name)s %(message)s'))
logging.getLogger().addHandler(logHandler)

logger = logging.getLogger(__name__)

class Profile:
    def __init__(self):
        self._filename = 'shaman.json'
        with open(self._filename) as f:
            self._config = json.load(f)
        self._client = Client(self._config['server'])
        logging.getLogger().setLevel(self._config.get('logThreshold', 20))

    def _log(self, message, *args, level=logging.INFO, **kwargs):
        logger.log(level, message.format(*args), **kwargs)

    def _write_config(self):
        with open(self._filename, 'w') as f:
            json.dump(self._config, f, indent=4)

    def _generate_account_key(self, path):
        self._log('account: generating key...')
        key = rsa.generate_private_key(65537, 4096, backend)
        with open(path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))

        return key

    def _add_account(self):
        path = 'account_key'
        key = self._generate_account_key(path)

        self._log('account: registering...')
        location, _ = self._client.new_registration(key)
        self._config['account'] = {
            'key': path,
            'key_type': 'pem',
            'registration': location,
        }
        self._write_config()

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
            self._log('account: accepting {} in 5 seconds...', agreement)
            time.sleep(5)
            self._client.registration(key, registration, agreement)

        return key

    def _add_authorization(self, name, domain):
        self._log('domain:{}: requesting authz...', name)
        authz, _ = self._client.new_authorization(self._key, 'dns', name)
        domain['authorization'] = authz
        self._write_config()

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
            self._log('domain:{}: authenticating with {}...',
                      name,
                      challenge['type'])
            auth = subprocess.Popen([authenticators[challenge['type']]],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL)
            auth.communicate(input=token + b'\n' + key_authorization + b'\n')
            if auth.returncode:
                raise RuntimeError('Failed to run {}', challenge['type'])

            self._log('domain:{}: replying to challenge...', name)
            self._client.challenge(self._key,
                                   challenge['uri'],
                                   key_authorization.decode('ascii'))

    def _check_or_add_authorization(self, name, domain):
        authz = None
        if 'authorization' in domain:
            authorization = domain['authorization']
            authz = self._client.get_authorization(authorization)
            if authz['status'] != 'pending' and authz['status'] != 'valid':
                self._log('domain:{}: authz ({}) was {}',
                          name,
                          authorization,
                          authz['detail'])
                authz = None

        if authz == None:
            authorization = self._add_authorization(name, domain)
            authz         = self._client.get_authorization(authorization)

        return authz

    def _add_domain_key(self, name, domain, path):
        self._log('domain:{}: generating key...', name)
        key = rsa.generate_private_key(65537, 4096, backend)
        with open(path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        domain['key'] = path
        domain['key_type'] = 'pem'
        self._write_config()

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
                raise RuntimeError('Unknown key type: ' + domain['key_type'])
        else:
            return self._add_domain_key(name, domain, name + '_key')

    def _check_or_add_cert(self, name, domain, key):
        if 'certificate' in domain:
            return domain['certificate']

        self._log('domain:{}: generating CSR...', name)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, name),
        ]))
        csr = builder.sign(key, hashes.SHA256(), backend)

        self._log('domain:{}: requesting certificate...', name)
        certificate = self._client.new_certificate(self._key, csr)
        domain['certificate'] = certificate
        self._write_config()

        return certificate

    def _check_cert_validity(self, name, domain, cert):
        renewal = self._config['renewal']
        if cert.not_valid_after - datetime.timedelta(renewal) \
                                                     < datetime.datetime.now():
            self._log('domain:{}: cert will expire in {} days',
                      name,
                      renewal)
            del domain['certificate']
            self._write_config()

            self._log('domain:{}: obtaining replacement certificate...', name)
            self._check_domain(name, domain)

            return True

    def _update_cert(self, name, certificate, chain):
        new_chain = io.BytesIO()
        new_chain.write(certificate.public_bytes(serialization.Encoding.PEM))
        new_chain.write(chain.public_bytes(serialization.Encoding.PEM))

        needs_write = True
        if os.path.exists(name + '_full'):
            with open(name + '_full', 'rb') as f:
                existing_chain_data = f.read()
            if new_chain.getvalue() == existing_chain_data:
                needs_write = False

        if needs_write:
            self._log('domain:{}: updating certificate', name)
            with open(name + '_full', 'wb') as f:
                f.write(new_chain.getvalue())

    def _check_domain(self, name, domain):
        authz = self._check_or_add_authorization(name, domain)
        if authz['status'] == 'pending':
            self._respond_challenges(name,
                                     authz['challenges'],
                                     authz['combinations'],
                                     domain['authenticators'])

        key  = self._check_or_add_domain_key(name, domain)
        cert = self._check_or_add_cert(name, domain, key)

        certificate = self._client.get_certificate(cert)
        if self._check_cert_validity(name, domain, certificate):
            return

        chain = self._client.get_certificate_chain(cert)

        self._update_cert(name, certificate, chain)

    def _check_domains(self):
        for name, domain in self._config['domains'].items():
            try:
                self._check_domain(name, domain)
            except (ClientError, IOError) as e:
                self._log('domain:{}: {}', name, e.args[0], level=logging.ERROR)

    def run(self):
        try:
            self._key = self._check_or_add_account()
            self._check_domains()
        except ClientError as e:
            self._log('error: {}', e.args[0], level=logging.ERROR)

