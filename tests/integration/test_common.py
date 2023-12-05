import pytest


@pytest.mark.parametrize(
    "client",
    [
        "integrated_common_auth_client",
        "integrated_ishare_satellite_client",
    ],
)
def test_access_token(client, request):
    test_client = request.getfixturevalue(client)
    token_response = test_client.request_access_token()
    assert "access_token" in token_response


@pytest.mark.parametrize(
    "client",
    [
        "integrated_common_auth_client",
        "integrated_ishare_satellite_client",
    ],
)
def test_authed_capabilities(client, request):
    test_client = request.getfixturevalue(client)
    capabilities = test_client.get_capabilities(use_token=True)
    assert "capabilities_info" in capabilities.keys()


@pytest.mark.parametrize(
    "client",
    [
        "integrated_common_auth_client",
        "integrated_ishare_satellite_client",
    ],
)
def test_no_auth_capabilities(client, request):
    test_client = request.getfixturevalue(client)
    capabilities = test_client.get_capabilities(use_token=False)
    assert "capabilities_info" in capabilities.keys()
    assert "sub" in capabilities.keys()
    # No access token means no audience token verification.
    assert "aud" not in capabilities.keys()
