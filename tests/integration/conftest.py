import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)

from python_ishare.authentication import create_jwt
from python_ishare.clients import CommonBaseClient, IShareSatelliteClient

PB_CLIENT_EORI = "EU.EORI.PBADAPTER"


@pytest.fixture(scope="session")
def integration_data_directory(test_data_directory):
    return test_data_directory / "integration"


@pytest.fixture(scope="session")
def private_key_bytes(integration_data_directory) -> bytes:
    """
    from project root:
        openssl genrsa -des3 -out ./tests/data/jwt-key.pem 4048
    """
    path = integration_data_directory / "pb_adapter_private.key"

    with path.open(mode="rb") as f:
        return f.read()


@pytest.fixture(scope="session")
def rsa_private_key(private_key_bytes) -> RSAPrivateKey:
    """
    from project root:
        openssl genrsa -des3 -out ./tests/data/jwt-key.pem 4048
    """
    return serialization.load_pem_private_key(private_key_bytes, password=b"pw123")


@pytest.fixture(scope="session")
def rsa_private_key_password() -> bytes:
    return b"pw123"


@pytest.fixture(scope="session")
def rsa_private_key_unencrypted(
    rsa_private_key: bytes,
    rsa_private_key_password,
) -> RSAPrivateKey:
    return serialization.load_pem_private_key(
        data=rsa_private_key,
        password=rsa_private_key_password,
        backend=default_backend(),
    )


@pytest.fixture(scope="session")
def pb_public_x509_chain(
    read_file_bytes, integration_data_directory
) -> list[Certificate]:
    return [
        load_der_x509_certificate(
            read_file_bytes(integration_data_directory / "pb_public_cert_1.der"),
        ),
        load_der_x509_certificate(
            read_file_bytes(integration_data_directory / "pb_public_cert_2.der"),
        ),
        load_der_x509_certificate(
            read_file_bytes(integration_data_directory / "pb_public_cert_3.der"),
        ),
    ]


@pytest.fixture(scope="session")
def satellite_public_certificate(
    integration_data_directory,
) -> Certificate:
    with (integration_data_directory / "certificate.pem").open("rb") as file:
        return load_pem_x509_certificate(file.read())


@pytest.fixture()
def pb_jwt_for_satellite(
    rsa_private_key, pb_public_x509_chain, rsa_private_key_password
):
    _payload = {
        "iss": PB_CLIENT_EORI,
        "sub": PB_CLIENT_EORI,
        "aud": "EU.EORI.NLDILSATTEST1",
    }

    return create_jwt(
        payload=_payload,
        private_key=rsa_private_key,
        x5c_certificate_chain=pb_public_x509_chain,
    )


@pytest.fixture()
def pb_jwt_invalid(integration_data_directory, get_key_and_certs):
    rsa_key, pb_public_x509_chain, _ = get_key_and_certs(
        key_file=integration_data_directory / "participant_invalid_cert_rsa_key.pem",
        cert_file=integration_data_directory
        / "participant_invalid_cert_certificate.pem",
    )

    _payload = {
        "iss": "EU.EORI.WEIRD",
        "sub": "EU.EORI.WEIRD",
        "aud": "EU.EORI.NLDILSATTEST1",
    }

    return create_jwt(
        payload=_payload,
        private_key=rsa_key,
        x5c_certificate_chain=pb_public_x509_chain,
    )


@pytest.fixture()
def integration_client_settings(pb_jwt_for_satellite, satellite_public_certificate):
    return {
        "target_domain": "https://dilsat1-mw.pg.bdinetwork.org",
        "target_public_key": [satellite_public_certificate],
        "client_eori": PB_CLIENT_EORI,
        "json_web_token": pb_jwt_for_satellite,
    }


@pytest.fixture()
def integrated_common_auth_client(integration_client_settings) -> CommonBaseClient:
    """
    CommonBaseClient with integration configuration.

    TODO: In time, when we have a working IShareAuthorizationRegistryClient
        (e.g. a working Registry) this should be replaced with that client.
    """
    return CommonBaseClient(**integration_client_settings)


@pytest.fixture()
def integrated_ishare_satellite_client(
    integration_client_settings,
) -> IShareSatelliteClient:
    """IShareSatelliteClient with integration configuration."""
    return IShareSatelliteClient(**integration_client_settings)
