import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, load_pem_x509_certificates


@pytest.fixture(scope="session")
def test_data_directory() -> Path:
    """
    Fixture to retrieve a file for testing purposes from the /tests/data directory.
    :return:
    """
    return Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def read_file_bytes():
    """
    Read a given file from a given file_path as bytes .open("rb").
    :return:
    """

    def _read_file_bytes(file_path: Path) -> bytes:
        with file_path.open("rb") as file:
            return file.read()

    return _read_file_bytes


@pytest.fixture(scope="session")
def get_key_and_certs(read_file_bytes):
    """
    Load the RSA key and certificate file from the given paths, add certificate base64.
    :return:
    """

    def _get_key_and_certs(
        key_file: Path, cert_file: Path
    ) -> tuple[RSAPrivateKey, list[Certificate], list[str]]:
        key = load_pem_private_key(read_file_bytes(file_path=key_file), password=None)
        x509_bytes = read_file_bytes(file_path=cert_file)
        x509 = load_pem_x509_certificates(x509_bytes)

        x509_b64 = []
        for cert in x509:
            x509_b64.append(
                str(base64.b64encode(cert.public_bytes(encoding=Encoding.DER)), encoding="utf8"))

        return key, x509, x509_b64

    return _get_key_and_certs
