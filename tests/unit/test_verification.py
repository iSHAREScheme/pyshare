from datetime import datetime

import jwt
import pytest
from python_ishare.authentication import create_jwt
from python_ishare.exceptions import (
    IShareInvalidAudience,
    IShareInvalidClientAssertionType,
    IShareInvalidClientId,
    IShareInvalidGrantType,
    IShareInvalidScope,
    IShareInvalidTokenAlgorithm,
    IShareInvalidTokenIssuerOrSubscriber,
    IShareInvalidTokenJTI,
    IShareInvalidTokenType,
    IShareTokenExpirationInvalid,
    IShareTokenExpired,
    IShareTokenNotValidYet,
)
from python_ishare.verification import validate_client_assertion

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def test_invalid_grant_type():
    with pytest.raises(IShareInvalidGrantType):
        validate_client_assertion(
            grant_type="",
            client_id="",
            client_assertion_type="",
            scope="",
            client_assertion="",
            audience="",
        )


def test_invalid_scope():
    with pytest.raises(IShareInvalidScope):
        validate_client_assertion(
            grant_type="client_credentials",
            client_assertion_type="",
            scope="",
            client_id="",
            client_assertion="",
            audience="",
        )


def test_audience_mismatch(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509 = satellite_key_and_certs
    audience = "my-super-eori"

    token = create_jwt(
        payload={"aud": audience},
        private_key=rsa_key,
        x5c_certificate_chain=public_cert_chain,
    )

    with pytest.raises(IShareInvalidAudience):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="not-my-super-eori",
        )


def test_no_client_id(satellite_key_and_certs):
    rsa_key, public_cert_chain, _ = satellite_key_and_certs
    audience = "my-super-eori"

    token = create_jwt(
        payload={"aud": audience},
        private_key=rsa_key,
        x5c_certificate_chain=public_cert_chain,
    )

    with pytest.raises(IShareInvalidClientId):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience=audience,
        )


def test_invalid_client_id(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509 = satellite_key_and_certs

    token = create_jwt(
        payload={"aud": "test"},
        private_key=rsa_key,
        x5c_certificate_chain=public_cert_chain,
    )

    with pytest.raises(IShareInvalidClientId):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="test",
        )


def test_invalid_client_assertion_type():
    with pytest.raises(IShareInvalidClientAssertionType):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type="",
            client_assertion="",
            audience="",
        )


def test_invalid_algorithm(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509_b64 = satellite_key_and_certs
    token_headers = {"alg": "RS384", "typ": "oops", "x5c": [x509_b64]}

    token = jwt.encode(
        payload={}, key=rsa_key, headers=token_headers, algorithm="RS384"
    )

    with pytest.raises(IShareInvalidTokenAlgorithm):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="",
        )


def test_invalid_token_type(satellite_key_and_certs):
    rsa_key, public_cert_chain, _ = satellite_key_and_certs

    token_headers = {"alg": "RS256", "typ": "oops", "x5c": [""]}
    token = jwt.encode(
        payload={}, key=rsa_key, headers=token_headers, algorithm="RS256"
    )

    with pytest.raises(IShareInvalidTokenType):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="",
        )


def test_invalid_issuer_or_subscriber(satellite_client, satellite_key_and_certs):
    rsa_key, public_cert_chain, _ = satellite_key_and_certs
    client_id = "EU.EORI.NL123456"

    token = create_jwt(
        payload={
            "aud": "test",
            "sub": client_id,
            "iss": "EU.EORI.NL654321",
        },
        private_key=rsa_key,
        x5c_certificate_chain=public_cert_chain,
    )

    with pytest.raises(IShareInvalidTokenIssuerOrSubscriber):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id=client_id,
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="test",
        )


def test_invalid_jti(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509_cert = satellite_key_and_certs
    client_id = "EU.EORI.NL000000001"

    headers = {"alg": "RS256", "typ": "JWT", "x5c": x509_cert}
    token = jwt.encode(
        payload={
            "aud": "test",
            "iss": client_id,
            "sub": client_id,
        },
        key=rsa_key,
        headers=headers,
        algorithm="RS256",
    )

    with pytest.raises(IShareInvalidTokenJTI):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id=client_id,
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="test",
        )


def test_invalid_expiration(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509_cert = satellite_key_and_certs
    client_id = "EU.EORI.NL000000001"

    headers = {"alg": "RS256", "typ": "JWT", "x5c": x509_cert}
    token = jwt.encode(
        payload={
            "aud": "test",
            "iss": client_id,
            "sub": client_id,
            "jti": "A",
            "exp": datetime.now().timestamp() + 30,
            "iat": 0,
        },
        key=rsa_key,
        headers=headers,
        algorithm="RS256",
    )

    with pytest.raises(IShareTokenExpirationInvalid):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id=client_id,
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="test",
        )


def test_token_not_valid_yet(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509_cert = satellite_key_and_certs
    client_id = "EU.EORI.NL000000001"

    headers = {"alg": "RS256", "typ": "JWT", "x5c": x509_cert}
    token = jwt.encode(
        payload={
            "aud": "test",
            "iss": client_id,
            "sub": client_id,
            "jti": "A",
            "exp": datetime.now().timestamp() + 40,
            "iat": datetime.now().timestamp() + 10,
        },
        key=rsa_key,
        headers=headers,
        algorithm="RS256",
    )

    with pytest.raises(IShareTokenNotValidYet):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id=client_id,
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="test",
        )


def test_token_expired(satellite_key_and_certs):
    rsa_key, public_cert_chain, x509_cert = satellite_key_and_certs

    headers = {"alg": "RS256", "typ": "JWT", "x5c": x509_cert}
    token = jwt.encode(
        payload={
            "aud": "test",
            "iss": "EU.EORI.NL000000001",
            "sub": "EU.EORI.NL000000001",
            "jti": "A",
            "exp": datetime.now().timestamp(),
            "iat": datetime.now().timestamp() - 30,
        },
        key=rsa_key,
        headers=headers,
        algorithm="RS256",
    )

    with pytest.raises(IShareTokenExpired):
        validate_client_assertion(
            grant_type="client_credentials",
            scope="iSHARE",
            client_id="",
            client_assertion_type=CLIENT_ASSERTION_TYPE,
            client_assertion=token,
            audience="test",
        )


def test_valid_token(satellite_key_and_certs):
    rsa_key, public_cert_chain, _ = satellite_key_and_certs
    client_id = "EU.EORI.NL000000001"

    print(public_cert_chain)

    token = create_jwt(
        payload={
            "aud": "test",
            "iss": client_id,
            "sub": client_id,
        },
        private_key=rsa_key,
        x5c_certificate_chain=public_cert_chain,
    )

    validate_client_assertion(
        grant_type="client_credentials",
        scope="iSHARE",
        client_id=client_id,
        client_assertion_type=CLIENT_ASSERTION_TYPE,
        client_assertion=token,
        audience="test",
    )
