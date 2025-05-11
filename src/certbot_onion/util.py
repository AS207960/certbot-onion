import josepy
import typing
import functools
import acme.challenges
import cryptography.x509

class OnionCAA(josepy.JSONObjectWithFields):
    caa: typing.Union[str, None] = josepy.field('caa')
    expiry: int = josepy.field('expiry')
    signature: bytes = josepy.field('signature', encoder=josepy.encode_b64jose, decoder=josepy.decode_b64jose)

class CertificateRequest(josepy.JSONObjectWithFields):
    csr: cryptography.x509.CertificateSigningRequest = josepy.field('csr', decoder=josepy.decode_csr, encoder=josepy.encode_csr)
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

