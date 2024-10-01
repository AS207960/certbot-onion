import typing
from csv import excel

import acme.messages
import certbot.achallenges
import certbot_onion._rust
from . import util

class ArtiAuthenticator:
    arti_client: certbot_onion._rust.ArtiClient
    onion_services: typing.Dict[str, certbot_onion._rust.ArtiOnionService]

    def __init__(self, connection_string: typing.Optional[str]):
        try:
            self.arti_client = certbot_onion._rust.ArtiClient(connection_string)
        except Exception as e:
            raise certbot.errors.PluginError(
                f"Can't connect to Arti RPC socket - {e}; "
                "use --onion-csr-arti-connection-string to specify the Arti RPC socket"
            )
        self.onion_services = {}

    def get_onion_service(self, domain: str):
        if domain in self.onion_services:
            return self.onion_services[domain]
        else:
            onion_service = self.arti_client.get_onion_service(domain)
            self.onion_services[domain] = onion_service
            return onion_service

    def perform(self, challenge: certbot.achallenges.AnnotatedChallenge) -> util.OnionCSR01Response:
        onion_service = self.get_onion_service(challenge.domain)
        csr = onion_service.make_csr(challenge.nonce)
        return util.OnionCSR01Response(csr=csr)

    def make_caa(self, identifier: acme.messages.Identifier) -> typing.Optional[typing.Tuple[str, util.OnionCAA]]:
        try:
            onion_service = self.get_onion_service(identifier.value)
        except ValueError:
            return

        caa = onion_service.sign_caa(3600)  # 1 hour
        return onion_service.onion_name(), util.OnionCAA(
            caa=caa.caa,
            expiry=caa.expiry,
            signature=caa.signature,
        )

    def cleanup(self):
        self.onion_services.clear()