"""
This function will generate the required files necessary to successfully call the
various functions in the ishare_auth package.

source: https://cryptography.io/en/latest/x509/tutorial/

example from root dir:

    python utils/generate_key_and_certificate.py \
        './ishare_adapter/tests/data' \
        participant_new

NOTE: This generates a self-signed certificate. This cannot be used as a certificate in
iShare context and can only be used for local testing purposes. An iShare acceptable
certificate must be signed by a trusted CA.
"""
import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate

parser = argparse.ArgumentParser(
    description="""
    This function will generate the required files necessary to successfully call the
    various functions in the ishare_auth package.
    NOTE: This generates a self-signed certificate. This cannot be used as a certificate
    in iShare context and can only be used for local testing purposes. An iShare
    certificate must be signed by a trusted CA.
    """
)
parser.add_argument("directory")
parser.add_argument("name")
parser.add_argument("password", nargs="?", default=None)
parsed_args = parser.parse_args()


CA_CERT = Path(__name__).parent / "iSHARETestCA.cacert.pem"


def check_dir(directory: str) -> Path:
    path = Path(directory)

    if not path.exists() or not path.is_dir():
        raise Exception("Provided directory path doesn't exist or isn't a directory.")

    return path


def generate_rsa_key(directory: Path, basename: str, password: str) -> RSAPrivateKey:
    encryption = serialization.NoEncryption()
    key: RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    if password:
        encryption = serialization.BestAvailableEncryption(
            password=password.encode("utf8")
        )

    # Write our key to disk for safe keeping
    with (directory / f"{basename}_rsa_key.pem").open("wb") as file:
        file.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            )
        )

    return key


def generate_x509_certificate(
    key: RSAPrivateKey, directory: Path, basename: str
) -> Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Zuid-Holland"),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Rotterdam"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, basename),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    # Write our certificate out to disk.
    with (directory / f"{basename}_certificate.pem").open("wb") as file:
        file.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert


def run(arguments):
    directory: Path = check_dir(arguments.directory)
    key = generate_rsa_key(
        directory=directory, basename=arguments.name, password=arguments.password
    )
    generate_x509_certificate(directory=directory, basename=arguments.name, key=key)


if __name__ == "__main__":
    run(parsed_args)
