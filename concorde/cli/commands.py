# concorde.cli.commands

import locale
import sys

from cryptography.hazmat.primitives import serialization

from ..client import jose

def acct_create(args):
    # TBD: recovery keys
    location, response = args.client.new_registration(args.key)
    print('Account: ' + location)

def acct_update(args):
    args.client.registration(args.key, args.account, args.agreement)

def acct_status(args):
    links, response = args.client.registration(args.key, args.account)
    print('Account: ' + args.account)
    if response.get('agreement') != \
                                  links.get('terms-of-service', {}).get('url'):
        print('Awaiting Terms of Service acceptance: ' + \
                                      links.get('terms-of-service').get('url'))
    if 'contact' in response:
        print('Contacts: ' + ', '.join(response['contact']))
    if 'authorizations' in response:
        print('Authorizations: ' + ', '.join(response['authorizations']))
    if 'certificates' in response:
        print('Certificates: ' + ', '.join(response['certificates']))

def challenge_type_to_human(type):
    if type == 'http-01':
        return 'HTTP'
    if type == 'dns-01':
        return 'DNS'
    if type == 'tls-sni-01':
        return 'TLS SNI'
    return type

def human_to_challenge_type(type):
    if type == 'HTTP':
        return 'http-01'
    if type == 'DNS':
        return 'dns-01'
    if type == 'TLS ':
        return 'tls-sni-01'
    return type

def print_authz(authz):
    for i, challenge in enumerate(authz['challenges']):
        print('''Challenge {}:
{human_type} [{status}]: {token} to {uri}
'''.format(i,
           human_type=challenge_type_to_human(challenge['type']),
           **challenge))
    combinations = authz['combinations']
    requirements = [' and '.join(map(str, c)) for c in combinations]
    print('Needed: {}'.format(' or '.join(requirements)))

def authz_create(args):
    location, response = args.client.new_authorization(args.key,
                                                       args.type,
                                                       args.value)
    print('Authorization: ' + location)

def authz_status(args):
    response = args.client.get_authorization(args.authorization)
    print('''Authorization: {}
Status: {}'''.format(args.authorization, response['status']))
    if response['status'] != 'valid':
        print()
        print_authz(response)

def approve(args):
    token         = args.token.encode(locale.getpreferredencoding())
    thumbprint    = jose.jwk_thumbprint(args.pubkey)
    authorization = token + b'.' + thumbprint
    print('Key authorization: ' + authorization.decode('ascii'))

def challenge_respond(args):
    args.client.challenge(args.key, args.challenge, args.key_authorization)

def cert_sign_request(args):
    location = args.client.new_certificate(args.key, args.csr)
    print('Certificate: ' + location)

def cert(args):
    cert = args.client.get_certificate(args.certificate)
    sys.stdout.buffer.write(cert.public_bytes(serialization.Encoding.PEM))

def cert_chain(args):
    cert = args.client.get_certificate_chain(args.certificate)
    sys.stdout.buffer.write(cert.public_bytes(serialization.Encoding.PEM))

def cert_revoke(args):
    args.client.revoke_certificate(args.key, args.certificate)

