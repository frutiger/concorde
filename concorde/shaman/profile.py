# shaman.profile

import datetime
import json
import logging
import logging.handlers
import os
import subprocess

from ..crypto import secp256r1, x509
from ..client import Client, ClientError

formatter = logging.Formatter('%(levelname)s %(name)s %(message)s')

outHandler = logging.StreamHandler()
outHandler.setFormatter(formatter)
logging.getLogger().addHandler(outHandler)

logger = logging.getLogger(__name__)

class Profile:
    def __init__(self):
        self._filename = 'shaman.json'
        with open(self._filename) as f:
            self._config = json.load(f)
        logging.getLogger().setLevel(self._config.get('logThreshold', 20))

    def _log(self, message, level=logging.INFO):
        logger.log(level, message)

    def _write_config(self):
        with open(self._filename, 'w') as f:
            json.dump(self._config, f, indent=4, sort_keys=True)

    def _get_or_make_key(self, config, name):
        if 'key' in config:
            with open(config['key'], 'rb') as f:
                key = secp256r1.from_file(f)
        else:
            key = secp256r1.make_key()

            path = name + '.key.priv.pem'
            with open(path, 'wb') as f:
                secp256r1.to_file(key, f)
            config['key'] = path
            self._write_config()
        return key

    def _make_client(self):
        acct_key = self._get_or_make_key(self._config, 'account')
        self._client = Client(self._config['server'], acct_key)

    def _check_or_add_domain_key(self, name, domain):
        return self._get_or_make_key(domain, name)

    def _add_account(self):
        acct_id, _ = self._client.new_account()
        self._config['account_id'] = acct_id
        self._write_config()
        self._log(f'account: registered account @ {acct_id}')

        return acct_id

    def _check_or_add_account(self):
        if 'account_id' in self._config:
            acct_id = self._config['account_id']
        else:
            acct_id = self._add_account()
        self._client.set_account_id(acct_id)

    def _add_order(self, name, domain):
        order_id, order = self._client.new_order([{
            'type':   'dns',
            'value':  name,
        }])
        domain['order_id'] = order_id
        self._write_config()
        self._log(f'domain:{name}: got order @ {order_id}')

        return order_id, order

    def _respond_challenges(self,
                            name,
                            challenges,
                            authenticators):
        for challenge in challenges:
            if challenge['status'] != 'pending':
                continue

            chal_type = challenge['type']
            if chal_type not in authenticators:
                continue

            url = challenge['url']
            token, key_auth = self._client.authorize_challenge(url)
            auth = subprocess.Popen([authenticators[chal_type]],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL)
            auth.communicate(input=token + b'\n' + key_auth + b'\n')
            if auth.returncode:
                raise RuntimeError(f'Failed to run {chal_type}')
            self._log(f'domain:{name}: authenticated with {chal_type}')

            self._client.validate_challenge(url)
            self._log(f'domain:{name}: replied to challenge')

            break
        else:
            types = ' or '.join(c['type'] for c in challenges)
            raise RuntimeError('Failed to find authenticator for ' + name +
                               ' needed: ' + types)

    def _check_or_add_order(self, name, domain):
        order = None

        if 'order_id' in domain:
            order_id = domain['order_id']
            order = self._client.get(order_id)
            if order['status'] not in { 'pending', 'ready', 'valid' }:
                self._log(f'domain:{name}: order @ {order_id} was ' +
                          f'{order["status"]}')
                order = None

        if order == None:
            order_id, order = self._add_order(name, domain)

        return order_id, order

    def _check_cert_validity(self, name, domain, cert):
        renewal = self._config['renewal']
        if x509.get_expiry(cert) - datetime.timedelta(renewal) \
                                                     < datetime.datetime.now():
            self._log(f'domain:{name}: cert will expire in {renewal} days')
            del domain['certificate']
            self._write_config()

            self._log(f'domain:{name}: obtaining replacement certificate...')
            self._check_domain(name, domain)

            return True
        return False

    def _update_cert(self, name, certificate):
        path = name + '.cert.pub.pem'
        needs_write = True
        if os.path.exists(path):
            with open(path, 'rb') as f:
                existing_cert = f.read()
            if certificate == existing_cert:
                needs_write = False

        if needs_write:
            self._log(f'domain:{name}: updating certificate')
            with open(path, 'wb') as f:
                f.write(certificate)

    def _check_domain(self, name, domain):
        key = self._check_or_add_domain_key(name, domain)
        order_id, order = self._check_or_add_order(name, domain)

        # TBD: check other order states
        if order['status'] == 'pending':
            # TBD: check other authorizations?
            authz_id = order['authorizations'][0]

            authz = self._client.get(authz_id)
            if authz['status'] == 'pending':
                self._respond_challenges(name,
                                         authz['challenges'],
                                         domain['authenticators'])
                # poll for the authz status next time
                return
            # TBD: handle other 'authz' states?
        elif order['status'] == 'ready':
            self._client.finalize_order(order_id, key, [name])
        elif order['status'] == 'valid':
            certificate_id = order['certificate']
            domain['certificate'] = certificate_id
            self._write_config()

            certificate = self._client.get_order_certificate(order_id)
            certificate = certificate.encode('ascii')

            self._update_cert(name, certificate)
            self._check_cert_validity(name, domain, certificate)

    def _check_domains(self):
        for name, domain in self._config['domains'].items():
            try:
                self._check_domain(name, domain)
            except ClientError as e:
                self._log(f'domain:{name}: {e.args[0]}', logging.ERROR)
            except IOError as e:
                self._log(f'domain:{name}: {e}', logging.ERROR)

    def run(self):
        try:
            self._make_client()
            self._check_or_add_account()
            self._check_domains()
        except ClientError as e:
            self._log(f'{e.args[0]}', logging.ERROR)

