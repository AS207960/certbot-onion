import typing
import josepy
import acme.challenges
import acme.messages
import acme.client
import OpenSSL.crypto
import certbot.interfaces
import certbot.plugins.common
import certbot.achallenges
import certbot_onion._rust
from . import util, c_tor, arti


class Authenticator(certbot.plugins.common.Plugin, certbot.interfaces.Authenticator):
    name = "onion-csr"
    description = "onion-csr-01 authentication plugin"

    backend: typing.Union[c_tor.CTorAuthenticator, arti.ArtiAuthenticator]

    @classmethod
    def add_parser_arguments(cls, add: typing.Callable[..., None]) -> None:
        add("torrc-file", help="Path to Tor configuration file", required=False)
        add("hs-dir", help="Path to a Tor hidden service directory", nargs="+", required=False)
        add("arti", help="Use Arti's RPC socket to request certificates", action='store_true', required=False)
        add("arti-connection-string", help="Connection string for the Arti client; e.g. unix:<path>", required=False)

    def _begin_finalization(
            self,
            acme_client: acme.client.ClientV2,
            order: acme.messages.OrderResource
    ) -> acme.messages.OrderResource:
        onion_caa = {}

        for i in order.body.identifiers:
            if i.typ != acme.messages.IDENTIFIER_FQDN:
                continue

            caa = self.backend.make_caa(i)
            if caa:
                domain, caa = caa
                if domain not in onion_caa:
                    onion_caa[domain] = caa

        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, order.csr_pem
        )
        wrapped_csr = util.CertificateRequest(
            csr=josepy.ComparableX509(csr),
            onion_caa=onion_caa
        )
        res = acme_client._post(order.body.finalize, wrapped_csr)
        order = order.update(body=acme.messages.Order.from_json(res.json()))
        return order

    def prepare(self) -> None:
        # This is BAD, one should not just vampire their way into a class and change its methods
        # However, I don't see any other way to do this so ¯\_(ツ)_/¯
        acme.client.ClientV2.begin_finalization = lambda client, order: self._begin_finalization(client, order)

        use_arti = self.conf("arti")

        if use_arti:
            self.backend = arti.ArtiAuthenticator(self.conf("arti-connection-string"))
        else:
            self.backend = c_tor.CTorAuthenticator()
            self.backend.prepare(self.conf("torrc-file"), self.conf("hs-dir"))

    def more_info(self) -> str:
        return ""

    def get_chall_pref(self, domain: str) -> typing.Iterable[typing.Type[acme.challenges.Challenge]]:
        if domain.endswith(".onion"):
            return [util.OnionCSR01]
        else:
            return []

    def perform(
            self, achalls: typing.List[certbot.achallenges.AnnotatedChallenge]
    ) -> typing.List[util.OnionCSR01Response]:
        out = []
        for chall in achalls:
            out.append(self.backend.perform(chall))

        return out

    def cleanup(self, achalls: typing.List[certbot.achallenges.AnnotatedChallenge]) -> None:
        self.backend.cleanup()
