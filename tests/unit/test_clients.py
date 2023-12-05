import pytest
import responses
from requests import HTTPError
from responses import matchers

from python_ishare.clients import CommonBaseClient


@pytest.mark.parametrize(
    "client",
    [
        "common_auth_client",
        "satellite_client",
    ],
)
def test_common_token_flow_first_time_setup(client, request):
    test_client = request.getfixturevalue(client)
    assert test_client.is_valid_access_token is False
    assert test_client.json_web_token == "fake"


@pytest.mark.parametrize(
    "client",
    [
        "common_auth_client",
        "satellite_client",
    ],
)
@responses.activate
def test_access_token(client, request):
    test_client = request.getfixturevalue(client)

    endpoint = f"{test_client.target_domain}/connect/token"
    responses.post(
        url=endpoint,
        json={"access_token": "test"},
        match=[matchers.header_matcher({"Authorization": "Bearer Fake"})],
    )
    token = test_client.request_access_token()
    assert token == {"access_token": "test"}
    responses.assert_call_count(url=endpoint, count=1)


@responses.activate
def test_callable_access_token_fake_jwt(test_client_arguments, request):
    def get_test_jwt():
        return "super-fake-jwt"

    test_client_arguments["json_web_token"] = get_test_jwt()
    test_client = CommonBaseClient(**test_client_arguments)

    endpoint = f"{test_client.target_domain}/connect/token"
    responses.post(
        url=endpoint,
        json={"access_token": "test"},
        match=[matchers.header_matcher({"Authorization": "Bearer super-fake-jwt"})],
    )

    token = test_client.request_access_token()
    assert token == {"access_token": "test"}
    responses.assert_call_count(url=endpoint, count=1)


@responses.activate
def test_callable_access_token(test_client_arguments, request):
    def get_test_jwt():
        return "super-fake-jwt"

    test_client_arguments["json_web_token"] = get_test_jwt()
    test_client = CommonBaseClient(**test_client_arguments)

    endpoint = f"{test_client.target_domain}/connect/token"
    responses.post(url=endpoint, json={"access_token": "test"})

    token = test_client.request_access_token()
    assert token == {"access_token": "test"}
    responses.assert_call_count(url=endpoint, count=1)


@pytest.mark.parametrize(
    "client",
    [
        "common_auth_client",
        "satellite_client",
    ],
)
@responses.activate
def test_access_token_post_return_error(monkeypatch, request, client):
    test_client = request.getfixturevalue(client)

    endpoint = f"{test_client.target_domain}/connect/token"
    responses.post(url=endpoint, status=401, json={"access_token": "abc"})

    with pytest.raises(HTTPError) as e:
        test_client.request_access_token()

    assert "401 Client Error" in str(e)


@pytest.mark.parametrize(
    "client",
    [
        "common_auth_client",
        "satellite_client",
    ],
)
@responses.activate
def test_token_reuse(client, create_jwt_response, request):
    """
    If use_token is true
        > retrieve access token
        > get capabilities
    if use_token is False
        > get capabilities
    """
    test_client = request.getfixturevalue(client)

    access_token = f"{test_client.target_domain}/connect/token"
    responses.post(url=access_token, json={"access_token": "test"})

    test_client._get_auth(use_token=True)
    test_client._get_auth(use_token=True)
    test_client._get_auth(use_token=True)
    responses.assert_call_count(url=access_token, count=1)


@pytest.mark.parametrize(
    "client,use_token",
    [
        ("common_auth_client", True),
        ("satellite_client", True),
    ],
)
@responses.activate
def test_capabilities(client, use_token, create_jwt_response, request):
    """
    If use_token is true
        > retrieve access token
        > get capabilities
    if use_token is False
        > get capabilities
    """
    test_client = request.getfixturevalue(client)

    access_token = f"{test_client.target_domain}/connect/token"
    responses.post(
        url=access_token, json={"access_token": "test", "aud": test_client.client_eori}
    )

    jwt = create_jwt_response(payload={"test": "this"})
    capabilities = f"{test_client.target_domain}/capabilities"
    responses.get(url=capabilities, json={"capabilities_token": jwt})

    capabilities_result = test_client.get_capabilities(use_token=use_token)
    assert capabilities_result["test"] == "this"
    responses.assert_call_count(url=access_token, count=int(use_token))
    responses.assert_call_count(url=capabilities, count=1)
