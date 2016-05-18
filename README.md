# concorde

`concorde` is three things:

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
allows it to not require any knowledge of how the authentication is to proceed
and thus does not require any special privileges to run.

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
    "server": "https://acme-v01.api.letsencrypt.org/directory",
    "quieter": true,
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

1. look for an `account` block.  If:
    * it doesn't exist:
        1. generate a new account private key
        2. create a new account on the specified `server`
        3. print the URL of an agreement if appropriate allowing the user to
           opt-out before auto-accepting
        4. save the key path, key type, and registration URL so this step can be
           skipped in the future
2. for each entry in the `domain` block:
    1. look for an `authorization` entry.  If:
        * it doesn't exist:
            1. use the `account` key to request an authorization for the given
               domain
            2. use the available `authenticators` and account public key to
               respond to the first combination of challenges from the server
            3. save the authorization URL so this step can be skipped in the
               future.
        * it does exist:
            1.  check if the authorization is still valid.
                * if it isn't:
                    1. obtain a new authorization as above.
    2. look for a `key` entry.  If:
        * it doesn't exist:
            1. generate a new private key for the domain as `<domain>_key`
            2. save the key path and key type so this step can be skipped.
    3. look for a `certificate` entry.  If:
        * it doesn't exist:
            1. generate a new CSR for the domain and request the server to sign
               it
            2. save the certificate URL so this step can be skipped
        * it does exist:
            1. check if its expiry is within `renewal` number of days.  If:
                * it is:
                    1. generate a new CSR and obtain a new certificate.

The optional `quieter` entry will cause `shaman` to only log important events:
terms of service acceptance and certificate expiry.

### Authenticators

Since `shaman` defers to 'authenticators' it doesn't need any special
privileges to prove domain ownership, however it does mean that some additional
set up is required.  An authenticator is invoked with no arguments.  Data is
supplied to its standard input as follows:

```
<token>LF
<key_authorization>LF
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

`shaman` logs its actions to '/dev/log' using the 'syslog' protocol.

## Commandline tool

The commandline tool is purposefully a stateless and tedious tool to use,
because it does not read any configuration files.  It is strongly recommended
to use `shaman` and only use the commandline tool if something manual needs to
be done.

The tool has built-in help, but an overview of its commands are listed below:

```
concorde acct create
concorde acct status <acct>
concorde acct update <acct>
concorde authz create
concorde authz status <authz>
concorde approve <token>
concorde challenge respond <challenge> <key authorization>
concorde cert sign-req <csr>
concorde cert fetch <cert>
concorde cert chain <cert>
concorde cert revoke <cert>
```

Many of the above commands require additional arguments, they can be some of:

```
--server <url>
--key-type [ PEM | DER ]
--key <path>
--pubkey <path>
```

## Installation

Install the latest tagged release:

```bash
$ pip install git+https://github.com/frutiger/concorde.git@latest
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

