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
certbot --server https://acme.api.acmeforonions.org/directory certonly -d 5anebu2glyc235wbbop3m2ukzlaptpkq333vdtdvcjpigyb7x2i2m2qd.onion --authenticator onion-csr --onion-csr-hs-dir /var/lib/tor/example_hs/
```

The important arguments here are:

* `--authenticator onion-csr` - Tells certbot to use this plugin for domain authentication
* `--onion-csr-hs-dir /var/lib/tor/example_hs/` - Provides the path to the hidden service directory, this can be specified multiple times for multiple domains.