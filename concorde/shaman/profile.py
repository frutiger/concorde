# shaman.profile

import datetime
import json
import logging
import logging.handlers
import os
import subprocess

from ..crypto import secp384r1, x509
from ..acme   import Client, Error, ServerError

formatter = logging.Formatter('%(levelname)s %(message)s')

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
                key = secp384r1.from_file(f)
        else:
            key = secp384r1.make_key()

            path = name + '.key.priv.pem'
            with open(path, 'wb') as f:
                secp384r1.to_file(key, f)
            config['key'] = path
            self._write_config()
        return key

    def _make_client(self):
        acct_key = self._get_or_make_key(self._config, 'account')
        self._client = Client(self._config['server'], acct_key)

    def _add_account(self):
        acct_id, _ = self._client.new_account()
        self._config['account_id'] = acct_id
        self._write_config()
        self._log(f'created account {acct_id}')

        return acct_id

    def _check_or_add_account(self):
        if 'account_id' in self._config:
            acct_id = self._config['account_id']
        else:
            acct_id = self._add_account()
        self._client.set_account_id(acct_id)

    def _check_or_add_domain_key(self, name, domain):
        return self._get_or_make_key(domain, name)

    def _add_order(self, name, domain):
        order_id, order = self._client.new_order([{
            'type':   'dns',
            'value':  name,
        }])
        domain['order_id'] = order_id
        self._write_config()
        self._log(f'{name}: created order {order_id}')

        return order_id, order

    def _respond_challenges(self,
                            name,
                            challenges,
                            authenticators,
                            fallback_authenticators):
        for challenge in challenges:
            if challenge['status'] != 'pending':
                continue

            chal_type = challenge['type']
            authenticator = authenticators.get(chal_type, None)
            if authenticator == None:
                authenticator = fallback_authenticators.get(chal_type, None)
            if authenticator == None:
                continue

            url = challenge['url']
            token, key_auth = self._client.authorize_challenge(url)
            auth = subprocess.Popen([authenticator],
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL)
            auth.communicate(input=token + b'\n' + key_auth + b'\n')
            if auth.returncode:
                raise RuntimeError(f'Failed to run {chal_type}')
            self._log(f'{name}: authenticated with {chal_type}')

            self._client.validate_challenge(url)
            self._log(f'{name}: validating challenge')

            break
        else:
            types = ' or '.join(c['type'] for c in challenges)
            raise RuntimeError('Failed to find authenticator for ' + name +
                               ' needed: ' + types)

    def _update_cert(self, name, certificate):
        path = name + '.cert.pub.pem'
        needs_write = True
        if os.path.exists(path):
            with open(path, 'rb') as f:
                existing_cert = f.read()
            if certificate == existing_cert:
                needs_write = False

        if needs_write:
            self._log(f'{name}: updating certificate')
            with open(path, 'wb') as f:
                f.write(certificate)

    def _check_order(self, name, domain, key):
        order_id = domain['order_id']
        try:
            order = self._client.get(order_id)
            if order['status'] == 'invalid':
                self._log(f'{name}: order {order_id} was invalid')
                order = None
        except ServerError as e:
            if e.status_code == 404:
                self._log(f'{name}: order {order_id} was not found')
                order = None
            else:
                raise e

        if order == None:
            del domain['order_id']
            self._write_config()
            order_id, order = self._add_order(name, domain)

        if order['status'] == 'pending':
            for authz_id in order['authorizations']:
                authz = self._client.get(authz_id)

                # TBD: handle other 'authz' states?
                if authz['status'] == 'pending':
                    self._log(f'{name}: authorizing {authz_id}')
                    self._respond_challenges(
                                        name,
                                        authz['challenges'],
                                        domain.get('authenticators', {}),
                                        self._config.get('authenticators', {}))
                    # poll for the order status next time
                    # TBD: should we poll immediately?
                    return
        elif order['status'] == 'ready':
            self._log(f'{name}: finalizing order')
            self._client.finalize_order(order_id, key, [name])
        elif order['status'] == 'valid':
            certificate_id = order['certificate']
            self._log(f'{name}: got certificate {certificate_id}')
            domain['certificate_id'] = certificate_id
            del domain['order_id']
            self._write_config()

            certificate = self._client.get_order_certificate(order_id)
            certificate = certificate.encode('ascii')

            self._update_cert(name, certificate)

    def _is_cert_valid(self, name, domain, cert):
        renewal = self._config['renewal']
        time_left = x509.get_expiry(cert) - datetime.datetime.now()
        if time_left < datetime.timedelta(renewal):
            self._log(f'{name}: cert will expire in {time_left}')
            return False
        return True

    def _check_domain(self, name, domain):
        key = self._check_or_add_domain_key(name, domain)
        if 'order_id' in domain:
            self._check_order(name, domain, key)
        elif 'certificate_id' in domain:
            certificate = self._client.get(domain['certificate_id'])
            certificate = certificate.encode('ascii')

            if self._is_cert_valid(name, domain, certificate):
                self._update_cert(name, certificate)
            else:
                del domain['certificate_id']
                self._write_config()

                if 'order_id' not in domain:
                    self._check_domain(name, domain)
        else:
            self._add_order(name, domain)
            # TBD: should we check domain again?

    def _check_domains(self):
        for name, domain in self._config['domains'].items():
            try:
                self._check_domain(name, domain)
            except Error as e:
                self._log(f'{name}: {e.args[0]}', logging.ERROR)
            except IOError as e:
                self._log(f'{name}: {e}', logging.ERROR)

    def run(self):
        try:
            self._make_client()
            self._check_or_add_account()
            self._check_domains()
        except Error as e:
            self._log(f'{e.args[0]}', logging.ERROR)

