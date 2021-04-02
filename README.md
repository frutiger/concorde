# concorde

`concorde` is an ACMEv2 client in three parts:

1. `concorde.shaman`: a fully automated tool designed to sign TLS certificates
   with minimal setup required
2. `concorde.client`: a low-level Python 3 ACME client library that
   `concorde.shaman` uses
3. `concorde.cli`: a not-so-user-friendly commandline ACME client tool that
   uses `concorde.client` for when you need to do something manual.

## Design goals

`concorde` has a lightweight dependency footprint: its immediate dependencies
are the `cryptography` and `requests` libraries.  `concorde` also completely
defers authenticating authorization challenges to external programs.  This
allows it to run without requiring any special privileges.

`concorde` does not allow flexibility in choice of the signature algorithms
used for account keys nor domain keys.  It also prefers PEM format for
persisting these to disk.  This is intended to reduce the possibility of using
poor algorithm choices.

## Shaman

`shaman` is designed to be a tool that is safe to run repeatedly to keep your
certificates up to date.

Usage:

```sh
$ shaman [<profile>]
```

If `<profile>` is not specified, `shaman`, defaults to the current directory.
All configuration is read from a file `shaman.json` in the profile directory.
`shaman` will update this file as necessary.

The minimal file should look something like this:

```json
{
    "server": "https://acme-v02.api.letsencrypt.org/directory",
    "renewal": 10,
    "domains": {
        "example.com": {
            "authenticators": {
                "http-01": "prove-challenge"
            }
        }
    }
}
```

Each piece in the configuration will be explained, by outlining what `shaman`
will do:

1. look for a `key` property.  If:
    * it doesn't exist:
        1. generate a new SECP384R1 account private key
        1. write that key to disk
        1. create a `key` property that refers to the location from the
           previous step
    * it does exist:
        1. skip to the next step
1. look for an `account_id` property.  If:
    * it doesn't exist:
        1. create a new account on the specified `server` with the account key
        1. create an `account_id` property that refers to the location of the
           account created in the previous step
    * it does exist:
        1. skip to the next step
1. for each entry in the `domain` block:
    1. look for a `key` property.  If:
        * it doesn't exist:
            1. generate a new SECP384R1 domain private key
            1. write that key to disk
            1. create a `key` property that refers to the location from the
               previous step
        * it does exist:
            1. skip to the next step
    1. look for an `order_id` entry.  If:
        * it doesn't exist:
            1. create a new order having a single identifier of type DNS and
               a value corresponding to the domain name of this `domain` entry
        * it does exist:
            1. skip to the next step
    1. get the order object corresponding to the `order_id` from the previous
       step.  If its status is:
        * `pending`, then:
            1. select the first authorization in this order object
            1. get the challenge objects corresponding to that authorization
            1. for each challenge in the authorization:
                1. load the challenge object corresponding to the
                   `challenge_id` from the previous step. If its status is:
                    * `pending`, then:
                        1. authorize the challenge using the account key
                        1. invoke the specified `authenticator` for this domain
                        1. validate the challenge
                    * otherwise skip this step
        * `ready`, then:
            1. finalize this order object with this domain name
        * `valid`, then:
            1. get the certificate from this order object
            1. add a `certificate_id` entry for this domain
            1. update the certificate on disk (only if the contents have
               changed)
            1. check if the certificate will expire before `renewal` days.  If:
                * it will, then:
                    1. erase the `certificate_id` entry from this domain
                    1. repeat the entire step for this domain block anew

The optional `logThreshold` can control the logging level used. It defaults to
`20`, but can be set to `10` or lower for more verbose logging.

### Authenticators

Since `shaman` defers to 'authenticators' it doesn't need any special
privileges to prove domain ownership, however it does mean that some additional
set up is required.  An authenticator is invoked with no arguments.  Data is
supplied to its standard input as follows (where `<LF>` is the ASCII Line Feed
character or the `0x0A` octet):

```
<token><LF><key_authorization><LF>
```

The authenticator is expected to perform whatever action is appropriate and
exit with status code zero.  Any other status code is regarded a failure to
authenticate.

As an example of an authenticator, the following `nginx` server block:

```
server {
    listen 80;
    server_name ~(?<vhost>.*);

    location ~\/\.well-known\/acme-challenge\/(.*) {
        alias /mnt/acme-challenge/$1;
    }
}
```

would make the following `bash` script with executable permissions a valid
authenticator:

```bash
#!/bin/bash

read token
read key_authorization

echo $key_authorization > /mnt/acme-challenge/$token
```

### Logs

`shaman` logs its actions to '/dev/log' using the 'syslog' protocol as well as
to standard out.

## Commandline tool

The commandline tool is purposefully a stateless and tedious tool to use,
because it does not read any configuration files.  It is strongly recommended
to use `shaman` and only use the commandline tool if something manual needs to
be done.

The tool has built-in help, but an overview of its commands are listed below:

```
concorde keys create <path>

concorde unreg <key> <server> create
concorde unreg <key> <server> status

concorde reg <key> <account id> <server> acct status
concorde reg <key> <account id> <server> acct update

concorde reg <key> <account id> <server> order create <type>|<value> [<type>|value>...]
concorde reg <key> <account id> <server> order status <order_id>
concorde reg <key> <account id> <server> order get-authz <order_id> <index>
concorde reg <key> <account id> <server> order finalize <order_id> <key> <value> [<value>...]
concorde reg <key> <account id> <server> order get-cert <order_id>

concorde reg <key> <account id> <server> challenge <challenge_id> status
concorde reg <key> <account id> <server> challenge <challenge_id> authorize
concorde reg <key> <account id> <server> challenge <challenge_id> validate
```

## Installation

Install via pip:

```bash
$ python3 -m pip install git+https://github.com/frutiger/concorde.git
```

This will install the `concorde` and `shaman` scripts into Python's binary
path.

## License

Copyright (C) 2016 Masud Rahman

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

