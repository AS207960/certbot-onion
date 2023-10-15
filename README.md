# certbot-onion

`onion-csr-01` Authenticator plugin for Certbot

This plugin allows certbot to request certificates for `.onion` domains using the `onion-csr-01` challenge type,
signing the request with the key of the hidden service.

## Installation

```shell
pip install certbot-onion
```

## Usage

```shell
certbot --server https://acme.api.acmeforonions.org/directory certonly -d 5anebu2glyc235wbbop3m2ukzlaptpkq333vdtdvcjpigyb7x2i2m2qd.onion --authenticator onion-csr
```

The important arguments here is:  `--authenticator onion-csr`

### Configuration arguments

* `--onion-csr-torrc-file /etc/tor/torrc` - Provides the path to the `torrc` file, hidden service directories are discovered from this file.
* `--onion-csr-hs-dir /var/lib/tor/example_hs/` - Provides the path to the hidden service directory, this can be specified multiple times for multiple domains.

If your `torrc` is in the standard location of `/etc/tor/torrc` then you do not need to specify any configuration arguments.