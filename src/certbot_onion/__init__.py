import dataclasses
import datetime
import typing
import josepy
import functools
import os
import acme.challenges
import acme.messages
import acme.client
import OpenSSL.crypto
import certbot.errors
import certbot.interfaces
import certbot.plugins.common
import certbot.achallenges
import certbot_onion._rust
from certbot.compat import os


class OnionCAA(josepy.JSONObjectWithFields):
    caa: typing.Union[str, None] = josepy.field('caa')
    expiry: int = josepy.field('expiry')
    signature: bytes = josepy.field('signature', encoder=josepy.encode_b64jose, decoder=josepy.decode_b64jose)


class CertificateRequest(josepy.JSONObjectWithFields):
    csr: josepy.ComparableX509 = josepy.field('csr', decoder=josepy.decode_csr, encoder=josepy.encode_csr)
    onion_caa: typing.Dict[str, OnionCAA] = josepy.field('onionCAA', omitempty=True)


class OnionCSR01Response(acme.challenges.ChallengeResponse):
    typ = "onion-csr-01"

    csr: bytes = josepy.field("csr", encoder=josepy.encode_b64jose, decoder=josepy.decode_b64jose)


@acme.challenges.Challenge.register
class OnionCSR01(acme.challenges.Challenge):
    response_cls = OnionCSR01Response
    typ = response_cls.typ

    TOKEN_SIZE = 14

    nonce: bytes = josepy.field(
        "nonce", encoder=josepy.encode_b64jose,
        decoder=functools.partial(josepy.decode_b64jose, size=TOKEN_SIZE, minimum=True)
    )


@dataclasses.dataclass
class HS:
    domain: str
    private_key: certbot_onion._rust.PrivateKey
    caa: typing.Optional[typing.List[str]] = None


class Authenticator(certbot.plugins.common.Plugin, certbot.interfaces.Authenticator):
    name = "onion-csr"
    description = "onion-csr-01 authentication plugin"

    _header_priv = b"== ed25519v1-secret: type0 ==\x00\x00\x00"

    def __init__(self, *args, **kwargs):
        self.hs = []

        super().__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add: typing.Callable[..., None]) -> None:
        add("torrc-file", help="Path to Tor configuration file", required=False)
        add("hs-dir", help="Path to a Tor hidden service directory", nargs="+", required=False)

    def read_hs_dir(self, hs_dir: str) -> HS:
        if not os.path.isdir(hs_dir):
            raise certbot.errors.PluginError(f"Hidden service directory path {hs_dir} is not a directory")

        hostname_path = os.path.join(hs_dir, "hostname")
        private_key_path = os.path.join(hs_dir, "hs_ed25519_secret_key")

        if not os.path.isfile(hostname_path):
            raise certbot.errors.PluginError(f"Hidden service directory {hs_dir} is not valid")
        if not os.path.isfile(private_key_path):
            raise certbot.errors.PluginError(f"Hidden service directory {hs_dir} is not valid")

        try:
            hostname = open(hostname_path, "r").read().strip()
        except IOError as e:
            raise certbot.errors.PluginError(f"Unable to read hidden service directory {hs_dir}: {e}")
        try:
            private_key_bytes = open(private_key_path, "rb").read()
        except IOError as e:
            raise certbot.errors.PluginError(f"Unable to read hidden service directory {hs_dir}: {e}")

        if not private_key_bytes.startswith(self._header_priv):
            raise certbot.errors.PluginError(f"Hidden service directory {hs_dir} private key does not seems to"
                                             f" be a valid ed25519 tor key")
        private_key = private_key_bytes[32:]
        private_key = certbot_onion._rust.PrivateKey(private_key)

        return HS(domain=hostname, private_key=private_key)

    def make_caa(self, identifiers: typing.List[acme.messages.Identifier]) -> typing.Dict[str, OnionCAA]:
        expiry = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())
        out = {}

        for i in identifiers:
            if i.typ != acme.messages.IDENTIFIER_FQDN:
                continue

            hs = next(filter(lambda x: self.__match_hs(x.domain, i.value), self.hs), None)
            if hs.domain in out:
                continue

            caa = hs.caa if hs.caa else []
            caa = "\n".join(caa)

            tbs = f"onion-caa|{expiry}|{caa}".encode("utf-8")
            signature = hs.private_key.sign(tbs)

            out[hs.domain] = OnionCAA(
                caa=caa,
                expiry=expiry,
                signature=signature
            )

        return out

    def _begin_finalization(
            self,
            acme_client: acme.client.ClientV2,
            order: acme.messages.OrderResource
    ) -> acme.messages.OrderResource:
        onion_caa = self.make_caa(order.body.identifiers)

        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, order.csr_pem
        )
        wrapped_csr = CertificateRequest(
            csr=josepy.ComparableX509(csr),
            onion_caa=onion_caa
        )
        res = acme_client._post(order.body.finalize, wrapped_csr)
        order = order.update(body=acme.messages.Order.from_json(res.json()))
        return order

    def prepare(self) -> None:
        # This is BAD, one should not just vampire their way into a class and change its methods
        # But I don't see any other way to do this
        acme.client.ClientV2.begin_finalization = lambda client, order: self._begin_finalization(client, order)

        hs_dirs = self.conf("hs-dir")
        torrc_file = self.conf("torrc-file")

        if torrc_file is None and hs_dirs is None:
            if os.path.isfile("/etc/tor/torrc"):
                torrc_file = "/etc/tor/torrc"
            else:
                raise certbot.errors.PluginError("Either --onion-csr-torrc-file or --onion-csr-hs-dir must be specified")

        if torrc_file is not None:
            try:
                with open(torrc_file, "r") as f:
                    lines = f.readlines()
            except IOError as e:
                raise certbot.errors.PluginError(f"Unable to read Tor configuration file {torrc_file}: {e}")

            pending_hs = None
            for line in lines:
                line = line.strip()
                if line.startswith("#"):
                    continue

                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                key, rest = parts

                if key == "HiddenServiceDir":
                    if pending_hs is not None:
                        self.hs.append(pending_hs)

                    pending_hs = self.read_hs_dir(rest)
                    pending_hs.caa = []

                if key == "HiddenServiceCAA":
                    if pending_hs is None:
                        raise certbot.errors.PluginError("HiddenServiceCAA without HiddenServiceDir")
                    pending_hs.caa.append(rest)

            if pending_hs is not None:
                self.hs.append(pending_hs)

        hs_dirs = hs_dirs if hs_dirs is not None else []
        for hs_dir in hs_dirs:
            self.hs.append(self.read_hs_dir(hs_dir))

    def more_info(self) -> str:
        return ""

    def get_chall_pref(self, domain: str) -> typing.Iterable[typing.Type[acme.challenges.Challenge]]:
        if domain.endswith(".onion"):
            return [OnionCSR01]
        else:
            return []

    @staticmethod
    def __match_hs(hs_domain: str, chall_domain: str) -> bool:
        match_domain = ".".join(chall_domain.rsplit(".", 2)[-2:])
        return hs_domain == match_domain

    def perform(self, achalls: typing.List[certbot.achallenges.AnnotatedChallenge]) -> \
            typing.List[OnionCSR01Response]:
        out = []
        for achall in achalls:
            hs = next(filter(lambda x: self.__match_hs(x.domain, achall.domain), self.hs), None)
            if not hs:
                raise certbot.errors.PluginError(f"Unable to find hidden service key for domain {achall.domain}")

            csr = hs.private_key.make_csr(achall.nonce)
            out.append(OnionCSR01Response(csr=csr))

        return out

    def cleanup(self, achalls: typing.List[certbot.achallenges.AnnotatedChallenge]) -> None:
        pass
