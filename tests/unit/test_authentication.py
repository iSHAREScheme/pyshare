import pytest

from python_ishare.authentication import (
    create_jwt,
    decode_jwt,
    get_b64_x5c_fingerprints,
)


@pytest.mark.parametrize(
    "key_and_certs",
    [
        "registry_key_and_certs",
        "satellite_key_and_certs",
        "consumer_one_key_and_certs",
    ],
)
def test_create_jwt_with_rsa_key(key_and_certs, request):
    rsa_key, x509_cert, _ = request.getfixturevalue(key_and_certs)

    my_tracker = "sabertooth"
    audience = "louis"

    token = create_jwt(
        payload={
            "iss": "something",
            "sub": "something",
            "aud": audience,
            "jti": my_tracker,
        },
        private_key=rsa_key,
        x5c_certificate_chain=x509_cert,
    )

    assert "sabertooth" not in token
    assert "something" not in token

    decoded = decode_jwt(
        json_web_token=token,
        audience=audience,
        public_x509_cert=x509_cert,
    )

    assert decoded["aud"] == audience
    assert decoded["jti"] == my_tracker


@pytest.mark.parametrize(
    "key_and_certs,subject",
    [
        (
            "registry_key_and_certs",
            "CN=localhost,O=participant_registry,L=Rotterdam,ST=Zuid-Holland,C=NL",
        ),
        (
            "satellite_key_and_certs",
            "CN=localhost,O=participant_satellite,L=Rotterdam,ST=Zuid-Holland,C=NL",
        ),
        (
            "consumer_one_key_and_certs",
            "CN=localhost,O=participant_consumer_one,L=Rotterdam,ST=Zuid-Holland,C=NL",
        ),
    ],
)
def test_get_x5c_fingerprints(key_and_certs, subject, request):
    rsa_key, x509_cert, _ = request.getfixturevalue(key_and_certs)

    audience = "louis"

    token = create_jwt(
        payload={
            "iss": "something",
            "sub": "something",
            "aud": audience,
            "jti": "123",
        },
        private_key=rsa_key,
        x5c_certificate_chain=x509_cert,
    )

    prints = get_b64_x5c_fingerprints(json_web_token=token)
    # The following subject is set when creating a (self-signed) certificate.
    assert prints[0]["subject"] == subject
