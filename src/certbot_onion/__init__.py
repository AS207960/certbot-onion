import typing
import josepy
import functools
import base64
import acme.challenges
import certbot.errors
import certbot.interfaces
import certbot.plugins.common
import certbot.achallenges
import certbot_onion._rust
from certbot.compat import os


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


class HS:
    def __init__(self, domain: str, private_key: bytes):
        self.domain = domain
        self.private_key = private_key


class Authenticator(certbot.plugins.common.Plugin, certbot.interfaces.Authenticator):
    name = "onion-csr"
    description = "onion-csr-01 authentication plugin"

    _header_priv = b"== ed25519v1-secret: type0 ==\x00\x00\x00"

    def __init__(self, *args, **kwargs):
        self.hs = []

        super().__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add: typing.Callable[..., None]) -> None:
        add("hs-dir", help="Path to a Tor hidden service directory", nargs="+", required=True)

    def prepare(self) -> None:
        for hs_dir in self.conf("hs-dir"):
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

            self.hs.append(HS(hostname, private_key))

    def more_info(self) -> str:
        return ""

    def get_chall_pref(self, domain: str) -> typing.Iterable[typing.Type[acme.challenges.Challenge]]:
        if domain.endswith(".onion"):
            return [OnionCSR01]
        else:
            return []

    def perform(self, achalls: typing.List[certbot.achallenges.AnnotatedChallenge]) -> \
            typing.List[OnionCSR01Response]:
        out = []
        for achall in achalls:
            hs = next(filter(lambda x: x.domain == achall.domain, self.hs), None)
            if not hs:
                raise certbot.errors.PluginError(f"Unable to find hidden service key for domain {achall.domain}")

            csr = certbot_onion._rust.make_csr(hs.private_key, achall.nonce)
            out.append(OnionCSR01Response(csr=bytes(csr)))

        return out

    def cleanup(self, achalls: typing.List[certbot.achallenges.AnnotatedChallenge]) -> None:
        pass
