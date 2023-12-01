import pytest

from python_ishare.exceptions import (
    IShareInvalidCertificateIssuer,
    ISharePartyStatusInvalid,
)


def test_trusted_list(integrated_ishare_satellite_client):
    """Test connection with the satellite, using a satellite specific endpoint."""
    trusted_list = integrated_ishare_satellite_client.get_trusted_list()

    assert "trusted_list" in trusted_list.keys()
    assert "aud" in trusted_list.keys()


def test_verify_party(integrated_ishare_satellite_client, integration_client_settings):
    """Test whether we can verify our own ishare party status."""
    result = integrated_ishare_satellite_client.verify_party(
        party_eori=integration_client_settings["client_eori"]
    )

    assert "parties_info" in result
    assert len(result["parties_info"]["data"]) == 1
    assert result["parties_info"]["data"][0]["adherence"]["status"] == "Active"


def test_verify_invalid_party(
    integrated_ishare_satellite_client, integration_client_settings
):
    """Test whether a pre-existing inactive party fails."""
    eori_existing_invalid_party = "EU.EORI.TESTENTPARTY127"

    with pytest.raises(ISharePartyStatusInvalid):
        integrated_ishare_satellite_client.verify_party(
            party_eori=eori_existing_invalid_party
        )


def test_verify_certificate(integrated_ishare_satellite_client, pb_jwt_for_satellite):
    """Test whether we can verify our own certificate using the satellite."""
    try:
        integrated_ishare_satellite_client.verify_ca_certificate(
            json_web_token=pb_jwt_for_satellite
        )
    except IShareInvalidCertificateIssuer:
        pytest.fail(
            "This should be a valid CA check. If this fails the certificate is not "
            "signed by a correct CA *or* the CA was removed from the trusted_list."
        )


def test_verify_invalid_certificate(integrated_ishare_satellite_client, pb_jwt_invalid):
    """Test whether we can verify our own certificate using the satellite."""
    with pytest.raises(IShareInvalidCertificateIssuer):
        integrated_ishare_satellite_client.verify_ca_certificate(
            json_web_token=pb_jwt_invalid
        )


def test_verify_json_web_token(
    integrated_ishare_satellite_client, integration_client_settings
):
    """
    Test whether we can fully verify our own json web token.
    """
    integrated_ishare_satellite_client.verify_json_web_token(
        client_id=integration_client_settings["client_eori"],
        client_assertion=integration_client_settings["json_web_token"],
        audience="EU.EORI.NLDILSATTEST1",
        grant_type="client_credentials",
        scope="iSHARE",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    )
