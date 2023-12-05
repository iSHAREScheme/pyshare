from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

from python_ishare.authentication import create_jwt
from python_ishare.clients import CommonBaseClient, IShareSatelliteClient


@pytest.fixture(scope="session")
def registry_key_and_certs(
    test_data_directory, get_key_and_certs
) -> tuple[RSAPrivateKey, list[Certificate], list[str]]:
    """
    testing certificates

    python utils/generate_key_and_certificate.py './tests/data' participant_registry

    :return:
    """
    return get_key_and_certs(
        key_file=test_data_directory / "participant_registry_rsa_key.pem",
        cert_file=test_data_directory / "participant_registry_certificate.pem",
    )


@pytest.fixture(scope="session")
def satellite_key_and_certs(
    test_data_directory, get_key_and_certs
) -> tuple[RSAPrivateKey, list[Certificate], list[str]]:
    """
    testing certificates

    python utils/generate_key_and_certificate.py './tests/data' participant_satellite

    :return:
    """
    return get_key_and_certs(
        key_file=test_data_directory / "participant_satellite_rsa_key.pem",
        cert_file=test_data_directory / "participant_satellite_certificate.pem",
    )


@pytest.fixture(scope="session")
def consumer_one_key_and_certs(
    test_data_directory, get_key_and_certs
) -> tuple[RSAPrivateKey, list[Certificate], list[str]]:
    """
    testing certificates

    python utils/generate_key_and_certificate.py './tests/data' participant_consumer_one

    :return:
    """
    return get_key_and_certs(
        key_file=test_data_directory / "participant_consumer_one_rsa_key.pem",
        cert_file=test_data_directory / "participant_consumer_one_certificate.pem",
    )


@pytest.fixture(scope="module")
def test_client_arguments(satellite_key_and_certs):
    """Make sure clients don't execute web requests."""
    _, x509_cert, _ = satellite_key_and_certs

    return {
        "target_domain": "https://localhost",
        "target_public_key": x509_cert,
        "client_eori": "NL123456789",
        "json_web_token": "fake",
    }


@pytest.fixture()
def common_auth_client(test_client_arguments) -> CommonBaseClient:
    """CommonBaseClient with test configuration."""
    return CommonBaseClient(**test_client_arguments)


@pytest.fixture()
def satellite_client(test_client_arguments) -> IShareSatelliteClient:
    """IShareSatelliteClient with test configuration."""
    return IShareSatelliteClient(**test_client_arguments)


@pytest.fixture(scope="session")
def trusted_fingerprints(
    satellite_key_and_certs, consumer_one_key_and_certs, registry_key_and_certs
) -> list[dict[str, Any]]:
    """
    Returns all the fingerprints in the expected format as returned by a Satellite.

    The content of the "trusted_list" in the decoded payload.

    https://dev.ishare.eu/scheme-owner/trusted-list.html
    """
    _, satellite_public_key, _ = satellite_key_and_certs
    _, consumer_public_key, _ = consumer_one_key_and_certs
    _, registry_public_key, _ = registry_key_and_certs
    _algorithm = hashes.SHA256()

    return [
        {
            "subject": satellite_public_key[0].subject.rfc4514_string(),
            "certificate_fingerprint": satellite_public_key[0].fingerprint(
                algorithm=_algorithm
            ),
            "validity": "valid",
            "status": "granted",
        },
        {
            "subject": consumer_public_key[0].subject.rfc4514_string(),
            "certificate_fingerprint": consumer_public_key[0].fingerprint(
                algorithm=_algorithm
            ),
            "validity": "valid",
            "status": "granted",
        },
        {
            "subject": registry_public_key[0].subject.rfc4514_string(),
            "certificate_fingerprint": registry_public_key[0].fingerprint(
                algorithm=_algorithm
            ),
            "validity": "valid",
            "status": "granted",
        },
    ]


@pytest.fixture()
def create_jwt_response(satellite_key_and_certs, test_client_arguments):
    rsa_key, x509_certs, _ = satellite_key_and_certs

    def _create(payload, iss="NL123", sub="NL123"):
        audience: str = test_client_arguments["client_eori"]

        _payload = {"iss": iss, "sub": sub, "aud": audience, **payload}
        return create_jwt(
            payload=_payload,
            private_key=rsa_key,
            x5c_certificate_chain=x509_certs,
        )

    return _create
