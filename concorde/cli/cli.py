# concorde.cli.cli

import argparse

from ..crypto  import secp256r1
from ..client  import Client, ClientError
from .commands import \
        key_create, \
        acct_create,  acct_status,  acct_update, \
        order_create, order_status, order_authz, order_finalize, order_get_cert, \
        challenge_status, challenge_authorize, challenge_validate

class MakeClient(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        client = Client(values,
                        getattr(namespace, 'key',        None),
                        getattr(namespace, 'account_id', None))
        setattr(namespace, self.dest, client)

class MakeKey(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        with open(values, 'rb') as f:
            setattr(namespace, self.dest, secp256r1.from_file(f))

class MakeIdentifiers(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        result = []
        for value in values:
            typ, val = value.split('|')
            result.append({
                'type':  typ,
                'value': val,
            })
        setattr(namespace, self.dest, result)

def parser_key_create_raw(ss_parsers):
    ss_parser = ss_parsers.add_parser('create', help='create key')
    ss_parser.set_defaults(ss_action=key_create, help=False)
    ss_parser.add_argument('path', metavar='<path>')

def parser_unreg_create(ss_parsers):
    ss_parser = ss_parsers.add_parser('create', help='create account')
    ss_parser.set_defaults(ss_action=acct_create, help=False)
    ss_parser.add_argument('--contact', metavar='<email>',
                           dest='contacts', action='append')

def parser_unreg_status(ss_parsers):
    ss_parser = ss_parsers.add_parser('status', help='get account status')
    ss_parser.add_argument('--account-id', metavar='<acct id>')
    ss_parser.set_defaults(ss_action=acct_status)

def parser_reg_acct_status(sss_parsers):
    sss_parser = sss_parsers.add_parser('status', help='get account status')
    sss_parser.set_defaults(sss_action=acct_status)

def parser_reg_acct_update(sss_parsers):
    sss_parser = sss_parsers.add_parser('update', help='update account')
    sss_parser.set_defaults(sss_action=acct_update)
    sss_parser.add_argument('--contact', metavar='<email>',
                            dest='contacts', action='append', default=[])

def parser_reg_order_create(sss_parsers):
    sss_parser = sss_parsers.add_parser('create', help='create order')
    sss_parser.set_defaults(sss_action=order_create)
    sss_parser.add_argument('identifiers', metavar='<type>|<value>',
                              action=MakeIdentifiers, nargs='+')

def parser_reg_order_status(sss_parsers):
    sss_parser = sss_parsers.add_parser('status', help='get order status')
    sss_parser.set_defaults(sss_action=order_status)
    sss_parser.add_argument('order_id', metavar='<order id>')

def parser_reg_order_authz(sss_parsers):
    sss_parser = sss_parsers.add_parser('get-authz',
                                         help='get authorization status')
    sss_parser.set_defaults(sss_action=order_authz)
    sss_parser.add_argument('order_id', metavar='<order id>')
    sss_parser.add_argument('index', metavar='<authorization index>', type=int)

def parser_reg_order_finalize(sss_parsers):
    sss_parser = sss_parsers.add_parser('finalize', help='finalize order')
    sss_parser.set_defaults(sss_action=order_finalize)
    sss_parser.add_argument('order_id', metavar='<order id>')
    sss_parser.add_argument('key', metavar='<key>', action=MakeKey)
    sss_parser.add_argument('names', metavar='<name>', nargs='+')

def parser_reg_order_get_cert(sss_parsers):
    sss_parser = sss_parsers.add_parser('get-cert',
                                         help='get order certificate')
    sss_parser.set_defaults(sss_action=order_get_cert)
    sss_parser.add_argument('order_id', metavar='<order id>')

def parser_reg_challenge_status(sss_parsers):
    sss_parser = sss_parsers.add_parser('status', help='get challenge status')
    sss_parser.set_defaults(sss_action=challenge_status)

def parser_reg_challenge_authorize(sss_parsers):
    sss_parser = sss_parsers.add_parser('authorize', help='authorize a challenge')
    sss_parser.set_defaults(sss_action=challenge_authorize)

def parser_reg_challenge_validate(sss_parsers):
    sss_parser = sss_parsers.add_parser('validate', help='validate a challenge')
    sss_parser.set_defaults(sss_action=challenge_validate)

def parser_reg_acct(ss_parsers):
    ss_parser = ss_parsers.add_parser('acct',
                                      help='create and manage accounts')

    sss_parsers = ss_parser.add_subparsers(metavar='<account subcommand>')
    sss_parsers.required = True
    parser_reg_acct_status(sss_parsers)
    parser_reg_acct_update(sss_parsers)

def parser_reg_order(ss_parsers):
    ss_parser = ss_parsers.add_parser('order', help='create and manage orders')

    sss_parsers = ss_parser.add_subparsers(metavar='<order subcommand>')
    sss_parsers.required = True
    parser_reg_order_create(sss_parsers)
    parser_reg_order_status(sss_parsers)
    parser_reg_order_authz(sss_parsers)
    parser_reg_order_finalize(sss_parsers)
    parser_reg_order_get_cert(sss_parsers)

def parser_reg_challenge(ss_parsers):
    ss_parser = ss_parsers.add_parser('challenge',
                                      help='create and manage authorizations')
    ss_parser.add_argument('challenge_id', metavar='<challenge id>')

    sss_parsers = ss_parser.add_subparsers(metavar='<challenge subcommand>')
    sss_parsers.required = True
    parser_reg_challenge_status(sss_parsers)
    parser_reg_challenge_authorize(sss_parsers)
    parser_reg_challenge_validate(sss_parsers)

def parser_key(s_parsers):
    s_parser = s_parsers.add_parser('key', help='create keys')

    ss_parsers = s_parser.add_subparsers(metavar='<key subcommand>')
    ss_parsers.required = True
    parser_key_create_raw(ss_parsers)

def parser_unreg(s_parsers):
    s_parser = s_parsers.add_parser('unreg', help='actions without an account')
    s_parser.add_argument('key', metavar='<key path>', action=MakeKey)
    s_parser.add_argument('client', metavar='<server>', action=MakeClient)

    ss_parsers = s_parser.add_subparsers(metavar='<unreg subcommand>')
    ss_parsers.required = True
    parser_unreg_create(ss_parsers)
    parser_unreg_status(ss_parsers)

def parser_reg(s_parsers):
    s_parser = s_parsers.add_parser('reg', help='actions with an account')
    s_parser.add_argument('key', metavar='<key path>', action=MakeKey)
    s_parser.add_argument('account_id', metavar='<acct id>')
    s_parser.add_argument('client', metavar='<server>', action=MakeClient)

    ss_parsers = s_parser.add_subparsers(metavar='<reg subcommand>')
    ss_parsers.required = True
    parser_reg_acct(ss_parsers)
    parser_reg_order(ss_parsers)
    parser_reg_challenge(ss_parsers)

def make_parser(name):
    parser = argparse.ArgumentParser(prog=name)

    s_parsers = parser.add_subparsers(metavar='<subcommand>')
    s_parsers.required = True
    parser_key(s_parsers)
    parser_unreg(s_parsers)
    parser_reg(s_parsers)

    return parser

def main(args, errfile):
    args = make_parser('concorde').parse_args(args[1:])

    action = getattr(args, 'sss_action',
                     getattr(args, 'ss_action',
                             getattr(args, 's_action',
                                     getattr(args, 'action',
                                             None))))

    if action is None:
        print(args)
        return

    try:
        action(args)
    except ClientError as e:
        print(e.args[0], file=errfile)

