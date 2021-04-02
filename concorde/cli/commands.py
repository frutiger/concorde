# concorde.cli.commands

import json
import sys

from ..crypto import secp256r1

def print_object(type, id, object):
    print(f'{type}: {id}')
    json.dump(object, sys.stdout, indent=2, separators=(',', ': '))
    print()

def print_account(id, account):
    del account['key']
    del account['ID']
    print_object('Account', id, account)

def key_create(args) -> None:
    key = secp256r1.make_key()
    with open(args.path, 'wb') as f:
        secp256r1.to_file(key, f)

def acct_create(args):
    account_id, account = args.client.new_account(args.contacts)
    print_account(account_id, account)

def acct_update(args):
    account = args.client.update_account(args.contacts)
    print_account(args.client.get_account_id(), account)

def acct_status(args):
    account_id, account = args.client.get_account()
    print_account(account_id, account)

def order_create(args):
    order_id, order = args.client.new_order(args.identifiers)
    print_object('Order', order_id, order)

def order_status(args):
    order = args.client.get(args.order_id)
    print_object('Order', args.order_id, order)

def order_authz(args):
    order = args.client.get(args.order_id)
    authz_id = order['authorizations'][args.index]
    authz = args.client.get(authz_id)
    print_object('Authorization', authz_id, authz)

def order_finalize(args):
    order = args.client.finalize_order(args.order_id,
                                       args.key,
                                       args.names)
    print_object('Order', args.order_id, order)

def order_get_cert(args):
    certificate = args.client.get_order_certificate(args.order_id)
    print(certificate, end='')

def challenge_status(args):
    challenge = args.client.get(args.challenge_id)
    print_object('Challenge', args.challenge_id, challenge)

def challenge_authorize(args):
    _, key_auth = args.client.authorize_challenge(args.challenge_id)
    print('Key authorization: ' + key_auth.decode('ascii'))

def challenge_validate(args):
    challenge = args.client.validate_challenge(args.challenge_id)
    print_object('Challenge', args.challenge_id, challenge)

