import os.path
import dataclasses
import typing
import datetime
import acme.messages
import certbot.errors
import certbot.achallenges
import certbot_onion._rust
from . import util


@dataclasses.dataclass
class HS:
    domain: str
    private_key: certbot_onion._rust.PrivateKey
    caa: typing.Optional[typing.List[str]] = None


class CTorAuthenticator:
    _header_priv = b"== ed25519v1-secret: type0 ==\x00\x00\x00"

    def __init__(self):
        self.hs = []

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

    def make_caa(self, identifier: acme.messages.Identifier) -> typing.Optional[typing.Tuple[str, util.OnionCAA]]:
        hs = next(filter(lambda x: self.__match_hs(x.domain, identifier.value), self.hs), None)
        if not hs:
            return

        expiry = int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp())

        caa = hs.caa if hs.caa else []
        caa = "\n".join(caa)

        tbs = f"onion-caa|{expiry}|{caa}".encode("utf-8")
        signature = hs.private_key.sign(tbs)

        return hs.domain, util.OnionCAA(
            caa=caa,
            expiry=expiry,
            signature=signature
        )

    def prepare(self, torrc_file: typing.Optional[str], hs_dirs: typing.Optional[typing.List[str]]):
        if torrc_file is None and hs_dirs is None:
            if os.path.isfile("/etc/tor/torrc"):
                torrc_file = "/etc/tor/torrc"
            else:
                raise certbot.errors.PluginError(
                    "Can't find torrc in default location; "
                    "either --onion-csr-torrc-file or --onion-csr-hs-dir must be specified, "
                    "or use --onion-csr-arti for experimental Arti RPC support"
                )

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
                    pending_hs.caa.append(f"caa {rest}")

            if pending_hs is not None:
                self.hs.append(pending_hs)

        hs_dirs = hs_dirs if hs_dirs is not None else []
        for hs_dir in hs_dirs:
            self.hs.append(self.read_hs_dir(hs_dir))

    @staticmethod
    def __match_hs(hs_domain: str, chall_domain: str) -> bool:
        match_domain = ".".join(chall_domain.rsplit(".", 2)[-2:])
        return hs_domain == match_domain

    def perform(self, challenge: certbot.achallenges.AnnotatedChallenge) -> util.OnionCSR01Response:
        hs = next(filter(lambda x: self.__match_hs(x.domain, challenge.domain), self.hs), None)
        if not hs:
            raise certbot.errors.PluginError(f"Unable to find hidden service key for domain {challenge.domain}")

        csr = hs.private_key.make_csr(challenge.nonce)
        return util.OnionCSR01Response(csr=csr)

    def cleanup(self):
        self.hs = []