import base64
import json
import time
import uuid
from typing import Any, Optional, TypedDict, Union, Iterator

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate, load_der_x509_certificate
from typing_extensions import NotRequired

from python_ishare.exceptions import IShareInvalidTokenX5C

ENCRYPTION_ALGORITHM = "RS256"


class Payload(TypedDict, total=False):
    # The iss claim is the EORI number of the client.
    iss: str
    # The sub claim is (also) the EORI number of the client.
    sub: str
    # The aud claim contains only the EORI number of the server.
    aud: str
    # The jti is an identifier to track the JWT for audit or logging purposes.
    jti: NotRequired[str]


class CertificateInfo(TypedDict, total=False):
    # rfc4514 string of the certificate subject
    subject: str
    # The fingerprint of the certificate, the HEX representation of the SHA256, upper...
    finger_print: str


def x5c_b64_to_certificate(b64_certs: list[str]) -> Iterator[Certificate]:
    """Revert the certificate from a x5c header."""
    for cert in b64_certs:
        yield load_der_x509_certificate(data=base64.b64decode(cert))


def x5c_certificates_to_b64(certs: list[Certificate]) -> Iterator[str]:
    """Convert the certificate to a x509 header."""
    for cert in certs:
        yield str(
            base64.b64encode(
                cert.public_bytes(
                    encoding=Encoding.DER
                )
            ),
            encoding="utf8"
        )


def get_b64_x5c_fingerprints(json_web_token: str) -> list[CertificateInfo]:
    """
    Extracts the x5c header certificate metadata.
    """
    headers = jwt.get_unverified_header(jwt=json_web_token)
    x5c = headers.get("x5c")

    if not isinstance(x5c, list):
        raise IShareInvalidTokenX5C("Extracted x5c header is not a list.")

    _hash = hashes.SHA256()
    _finger_prints: list[CertificateInfo] = []

    for cert in x5c_b64_to_certificate(x5c):
        _finger_print = cert.fingerprint(algorithm=_hash).hex().upper()
        _finger_prints.append(
            dict(
                finger_print=_finger_print,
                subject=cert.subject.rfc4514_string(),
            )
        )

    return _finger_prints


def create_jwt(
    payload: Payload,
    private_key: RSAPrivateKey,
    x5c_certificate_chain: list[Certificate],
    **kwargs: dict[str, Union[json.JSONEncoder, bool]]
) -> str:
    """
    Create a valid JWT for iShare specific use. As per the "private_key_jwt"
    methodology in openid connect.

    Note: iShare spec dictates a lifetime of 30 seconds.

    https://openid.net/specs/openid-connect-core-1_0.html

    :param payload: the payload to be included into the JWT;
        {"iss": "eori", "sub": "eori_number", "aud": "eori_number"}
    :param private_key: The RSAPrivateKey instance of the private key to be used to
        encrypt the payload.
    :param x5c_certificate_chain: An array of the complete certificate chain that should
        be used to validate the JWT signature. Up until the issuing CA from the
        trust_list from the relevant iShare Satellite.
    """
    headers = {
        "alg": ENCRYPTION_ALGORITHM,
        "typ": "JWT",
        "x5c": [c for c in x5c_certificates_to_b64(certs=x5c_certificate_chain)]
    }

    _payload = {**payload}

    if "jti" not in _payload:
        _payload["jti"] = str(uuid.uuid4())

    unix_epoch = time.time()
    _payload["iat"] = unix_epoch
    _payload["exp"] = unix_epoch + 30

    return jwt.encode(
        payload=_payload,
        key=private_key,  # type: ignore[arg-type,unused-ignore]
        headers=headers,
        algorithm=ENCRYPTION_ALGORITHM,
        **kwargs  # type: ignore[arg-type]
    )


def decode_jwt(
    json_web_token: Union[str, bytes],
    public_x509_cert: list[Certificate],
    audience: Optional[str] = None,
    **kwargs: Any
) -> Any:
    """
    Raises specific exception if IShare JWT is not valid.

    :param json_web_token:
    :param public_x509_cert:
        The public X509 certificate uploaded to an iShare Satellite.
    :param audience: eori of the party receiving the json web token
    :return: they payload of the decoded json_web_token.
    :raises IShareAuthenticationException: if JWT token not valid
    """
    return jwt.decode(
        jwt=json_web_token,
        key=public_x509_cert[0].public_key(),  # type: ignore[arg-type,unused-ignore]
        audience=audience,
        algorithms=[ENCRYPTION_ALGORITHM],
        **kwargs
    )
