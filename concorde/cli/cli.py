# concorde.cli.cli

import argparse

import cryptography
from cryptography                   import x509
from cryptography.hazmat.primitives import serialization

from ..client  import Client, ClientError
from .commands import acct_create,  acct_status,  acct_update, \
                      authz_create, authz_status, \
                      approve, \
                      challenge_respond, \
                      cert_sign_request, cert, cert_chain, cert_revoke

# TBD: make backend pluggable?
backend = cryptography.hazmat.backends.default_backend()

def raw_loader(path):
    with open(path, 'rb') as f:
        return f.read()

class MakeClient(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        setattr(namespace, self.dest, Client(values))

class MakeKey(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):

        if namespace.key_type == 'raw':
            setattr(namespace, self.dest, raw_loader(values))
        elif namespace.key_type == 'pem':
            setattr(namespace,
                    self.dest,
                    serialization.load_pem_private_key(raw_loader(values),
                                                       None,
                                                       backend))
        elif namespace.key_type == 'der':
            setattr(namespace,
                    self.dest,
                    serialization.load_der_private_key(raw_loader(values),
                                                       None,
                                                       backend))

class MakePubKey(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):

        if namespace.key_type == 'raw':
            setattr(namespace, self.dest, raw_loader(values))
        elif namespace.key_type == 'pem':
            setattr(namespace,
                    self.dest,
                    serialization.load_pem_public_key(raw_loader(values),
                                                      backend))
        elif namespace.key_type == 'der':
            setattr(namespace,
                    self.dest,
                    serialization.load_der_public_key(raw_loader(values),
                                                      backend))

class MakeCsr(argparse.Action):
    def __call__(self, parser, namespace, values, option_string):
        setattr(namespace,
                self.dest,
                x509.load_pem_x509_csr(raw_loader(values), backend))

def parser_acct_create(subsubparsers):
    subsubparser = subsubparsers.add_parser('create', help='create accounts')
    subsubparser.set_defaults(subsubaction=acct_create, help=False)
    subsubparser.add_argument('--contact', metavar='<email>',
                              dest='contacts', action='append', default=[])
    subsubparser.add_argument('--agreement', metavar='<agreement>')

def parser_acct_status(subsubparsers):
    subsubparser = subsubparsers.add_parser('status',
                                            help='get account status')
    subsubparser.set_defaults(subsubaction=acct_status)
    subsubparser.add_argument('account', metavar='<account>')

def parser_acct_update(subsubparsers):
    subsubparser = subsubparsers.add_parser('update', help='update account')
    subsubparser.set_defaults(subsubaction=acct_update)
    subsubparser.add_argument('account', metavar='<account>')
    subsubparser.add_argument('--contact', metavar='<email>',
                              dest='contacts', action='append', default=[])
    subsubparser.add_argument('--agreement', metavar='<agreement>')

def parser_authz_create(subsubparsers):
    subsubparser = subsubparsers.add_parser('create',
                                            help='create authorizations')
    subsubparser.set_defaults(subsubaction=authz_create)
    subsubparser.add_argument('--key-type', metavar='<privkey type>',
                              choices=['raw', 'pem', 'der'], required=True)
    subsubparser.add_argument('--key', metavar='<acct privkey>', required=True,
                              action=MakeKey)
    subsubparser.add_argument('type', metavar='<type>')
    subsubparser.add_argument('value', metavar='<value>')

def parser_authz_status(subsubparsers):
    subsubparser = subsubparsers.add_parser('status',
                                            help='get authorization status')
    subsubparser.set_defaults(subsubaction=authz_status)
    subsubparser.add_argument('authorization', metavar='<authorization>')

def parser_challenge_respond(subsubparsers):
    subsubparser = subsubparsers.add_parser('respond',
                                            help='respond to a challenge')
    subsubparser.set_defaults(subsubaction=challenge_respond)
    subsubparser.add_argument('challenge', metavar='<challenge>')
    subsubparser.add_argument('key_authorization',
                              metavar='<key authorization>')

def parser_cert_sign_request(subsubparsers):
    subsubparser = subsubparsers.add_parser('sign-req',
                                            help='request signature')
    subsubparser.set_defaults(subsubaction=cert_sign_request)
    subsubparser.add_argument('--key-type', metavar='<privkey type>',
                               choices=['raw', 'pem', 'der'], required=True)
    subsubparser.add_argument('--key', metavar='<acct privkey>', required=True,
                              action=MakeKey)
    subsubparser.add_argument('csr', metavar='<csr>',
                              action=MakeCsr)

def parser_cert_fetch(subsubparsers):
    subsubparser = subsubparsers.add_parser('fetch', help='get certificate')
    subsubparser.set_defaults(subsubaction=cert)
    subsubparser.add_argument('certificate', metavar='<certificate>')

def parser_cert_chain(subsubparsers):
    subsubparser = subsubparsers.add_parser('chain',
                                            help='get certificate chain')
    subsubparser.set_defaults(subsubaction=cert_chain)
    subsubparser.add_argument('certificate', metavar='<certificate>')

def parser_cert_revoke(subsubparsers):
    subsubparser = subsubparsers.add_parser('revoke',
                                            help='revoke certificate')
    subsubparser.set_defaults(subsubaction=cert_revoke)
    subsubparser.add_argument('--key-type', metavar='<privkey type>',
                               choices=['raw', 'pem', 'der'], required=True)
    subsubparser.add_argument('--key', metavar='<acct privkey>', required=True,
                              action=MakeKey)
    subsubparser.add_argument('certificate', metavar='<certificate>')

def parser_acct(subparsers):
    subparser = subparsers.add_parser('acct',
                                      help='create and manage accounts')
    subparser.set_defaults(subaction=lambda x: subparser.print_help())
    subparser.add_argument('--server', metavar='<url>', required=True,
                           action=MakeClient, dest='client')
    subparser.add_argument('--key-type', metavar='<privkey type>',
                            choices=['raw', 'pem', 'der'], required=True)
    subparser.add_argument('--key', metavar='<acct privkey>', required=True,
                           action=MakeKey)

    subsubparsers = subparser.add_subparsers(metavar='<account subcommand>')
    parser_acct_create(subsubparsers)
    parser_acct_status(subsubparsers)
    parser_acct_update(subsubparsers)

def parser_authz(subparsers):
    subparser = subparsers.add_parser('authz',
                                      help='create and manage authorizations')
    subparser.set_defaults(subaction=lambda x: subparser.print_help())
    subparser.add_argument('--server', metavar='<url>', required=True,
                           action=MakeClient, dest='client')

    subsubparsers = subparser.add_subparsers(
                                          metavar='<authorization subcommand>')
    parser_authz_create(subsubparsers)
    parser_authz_status(subsubparsers)

def parser_approve(subparsers):
    subparser = subparsers.add_parser('approve',
                                      help='validate challenges')
    subparser.set_defaults(subaction=approve)
    subparser.add_argument('--key-type', metavar='<pubkey type>',
                            choices=['raw', 'pem', 'der'], required=True)
    subparser.add_argument('--pubkey', metavar='<acct pubkey>', required=True,
                           action=MakePubKey)
    subparser.add_argument('token', metavar='<token>')

def parser_challenge(subparsers):
    subparser = subparsers.add_parser('challenge',
                                      help='create and manage authorizations')
    subparser.set_defaults(subaction=lambda x: subparser.print_help())
    subparser.add_argument('--server', metavar='<url>', required=True,
                           action=MakeClient, dest='client')
    subparser.add_argument('--key-type', metavar='<privkey type>',
                            choices=['raw', 'pem', 'der'], required=True)
    subparser.add_argument('--key', metavar='<acct privkey>', required=True,
                           action=MakeKey)

    subsubparsers = subparser.add_subparsers(metavar='<challenge subcommand>')
    parser_challenge_respond(subsubparsers)

def parser_cert(subparsers):
    subparser = subparsers.add_parser('cert',
                                      help='request and fetch certificates')
    subparser.set_defaults(subaction=lambda x: subparser.print_help())
    subparser.add_argument('--server', metavar='<url>', required=True,
                           action=MakeClient, dest='client')

    subsubparsers = subparser.add_subparsers(metavar='<cert subcommand>')
    parser_cert_sign_request(subsubparsers)
    parser_cert_fetch(subsubparsers)
    parser_cert_chain(subsubparsers)
    parser_cert_revoke(subsubparsers)

def make_parser(name):
    parser = argparse.ArgumentParser(prog=name)
    parser.set_defaults(action=lambda x: parser.print_help())

    subparsers = parser.add_subparsers(metavar='<subcommand>')
    parser_acct(subparsers)
    parser_authz(subparsers)
    parser_approve(subparsers)
    parser_challenge(subparsers)
    parser_cert(subparsers)

    return parser

def main(args, errfile):
    args = make_parser('concorde').parse_args(args[1:])

    action = getattr(args, 'subsubaction',
                     getattr(args, 'subaction',
                             getattr(args, 'action',
                                     None)))

    if action is None:
        print(args)
        return

    try:
        action(args)
    except ClientError as e:
        print(e.args[0], file=errfile)

