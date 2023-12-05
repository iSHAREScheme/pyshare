import logging
from typing import Any, Callable, Literal, Optional, TypedDict, Union
from urllib.parse import urljoin

import requests
from cryptography.x509 import Certificate

from python_ishare.authentication import decode_jwt, get_b64_x5c_fingerprints
from python_ishare.exceptions import (
    IShareInvalidCertificateIssuer,
    ISharePartyStatusInvalid,
)
from python_ishare.verification import validate_client_assertion

logger = logging.getLogger("ishare_auth.authentication")

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
GRANT_TYPE = "client_credentials"
SCOPE = "iSHARE"


class AccessToken(TypedDict):
    access_token: str
    token_type: str
    expires_in: int


class CommonBaseClient:
    """
    Standalone base client that can be extended for role specific methods.

    - Implements the common auth flow for all iShare participants / roles.
    - Implements common api methods
    - Can be extended for different access_token/jwt flow.

    Common endpoint documentation:
        - https://dev.ishare.eu/common/token.html
        - https://dev.ishare.eu/common/capabilities.html

    The base class handles two important things;
        - basic authentication flow (transforming an JWS into an access_token)
        - decryption of the json response token
    """

    _access_token: Optional[AccessToken]
    _json_web_token: Union[str, Callable[[], str]]

    def __init__(
        self,
        target_domain: str,
        target_public_key: list[Certificate],
        client_eori: str,
        json_web_token: Union[str, Callable[[], str]],
        timeout: float = 10.0,
        extra: Optional[Any] = None,
    ) -> None:
        """
        :param target_domain: Domain part of the target service, including scheme
        :param target_public_key: Public key to verify the received json web tokens
        :param client_eori: ishare participant eori of the client
        :param json_web_token:
            - type str: pre-made jwt for ishare (see authentication.create_jwt)
            - type Callable: a function/class that returns a jwt on demand
        :param timeout: used to stop the web requests to avoid hanging requests
        :param extra: If methods below are overriden this can be used to pass arguments.
        """
        self.target_domain = target_domain
        self.target_public_key = target_public_key
        self.client_eori = client_eori
        self.timeout = timeout
        self.extra = extra

        self._json_web_token = json_web_token
        self._access_token: Optional[AccessToken] = None

    @property
    def access_token(self) -> Optional[str]:
        if self._access_token:
            return self._access_token["access_token"]
        return None

    @property
    def json_web_token(self) -> str:
        """
        Subclass this method if an alternative method is required for generating the JWS
        f.e. for security purposes or when it needs refreshing *or* use pass a Callable
        argument for the json_web_token.
        """
        if callable(self._json_web_token):
            return self._json_web_token()
        return self._json_web_token

    @property
    def is_valid_access_token(self) -> bool:
        """
        Assumed here is that the access_token of the target has indefinite lifespan.

        If not, subclass this class and override this method.
        """
        return self._access_token is not None

    def _get_auth(self, use_token: bool) -> Optional[dict[str, str]]:
        """
        Returns an access_token if variable use_token resolves to true;
            - returns existing one if already retrieved
            - returns the result of requesting a new one
                (as long as the jwt of the constructor is still valid)
        """
        if not use_token:
            return None

        if not self.is_valid_access_token:
            self._access_token = self.request_access_token()

        return {"Authorization": f"Bearer {self.access_token}"}

    def request_access_token(self) -> Any:
        """
        Request the target_domain for an access_token for use in api requests.

        - https://dev.ishare.eu/common/token.html

        :raises HTTPError: originating from requests library
        :raises requests.exceptions.JSONDecodeError: if json body is invalid
        :return:
        """
        response = requests.post(
            urljoin(self.target_domain, "/connect/token"),
            data={
                "grant_type": GRANT_TYPE,
                "scope": SCOPE,
                "client_id": self.client_eori,  # EORI number
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": self.json_web_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.timeout,
        )

        # Raise exceptions here, let client handle them.
        response.raise_for_status()
        return response.json()

    def _get_request(
        self,
        endpoint_path: str,
        decode_key: str,
        use_token: bool = True,
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        """

        :param endpoint_path:
        :param use_token:
        :param decode_key:
            Key to pop from the results and decode the jwt inside the json response body
        :raises HTTPError: originating from requests library
        :raises requests.exceptions.JSONDecodeError: if json body is invalid
        :return: json as dict of the request *or*
            decoded jws token as dict if decode_key given
        """
        response = requests.get(
            url=urljoin(self.target_domain, endpoint_path),
            headers=self._get_auth(use_token=use_token),
            timeout=self.timeout,
            params=params,
        )
        response.raise_for_status()
        json: dict[str, Any] = response.json()

        _audience = self.client_eori if use_token else None

        return decode_jwt(
            json_web_token=json[decode_key],
            public_x509_cert=self.target_public_key,
            audience=_audience,
        )

    def get_capabilities(self, use_token: bool = True) -> Any:
        """
        https://dev.ishare.eu/common/capabilities.html

        :param use_token: If False the token will not be used and the unauthenticated
            response is returned as per specification.
        :return:
        """
        return self._get_request(
            endpoint_path="/capabilities",
            use_token=use_token,
            decode_key="capabilities_token",
        )


class IShareSatelliteClient(CommonBaseClient):
    """
    Responsible for communicating with an iShare Satellite/Scheme Owner.
    """

    def get_trusted_list(self) -> Any:  # pragma: no cover
        """
        https://dev.ishare.eu/scheme-owner/trusted-list.html
        :return:
        """
        return self._get_request(
            endpoint_path="/trusted_list", decode_key="trusted_list_token"
        )

    def get_parties(self, params: dict[str, Any]) -> Any:  # pragma: no cover
        """
        https://dev.ishare.eu/scheme-owner/parties.html
        :return:
        """
        return self._get_request(
            endpoint_path="/parties", decode_key="parties_token", params=params
        )

    def get_versions(self, use_token: bool) -> Any:  # pragma: no cover
        """
        https://dev.ishare.eu/scheme-owner/versions.html

        :param use_token: If False the token will not be used and the unauthenticated
            response is returned as per specification.
        :return:
        """
        return self._get_request(
            endpoint_path="/versions", use_token=use_token, decode_key="versions_token"
        )

    def verify_party(self, party_eori: str, certified_only: bool = True) -> Any:
        """Implements the verification logic for a participant's status."""
        result = self.get_parties(
            params=dict(
                eori=party_eori, certified_only=certified_only, active_only=True
            )
        )

        parties_info = result.get("parties_info")
        parties_count = parties_info.get("count", 0)

        if not parties_info or parties_count != 1:
            raise ISharePartyStatusInvalid(
                f"Invalid result, received {parties_count} parties."
            )

        parties_data = parties_info.get("data", {})
        only_party = parties_data[0]

        if only_party["party_id"] != party_eori:
            raise ISharePartyStatusInvalid("Invalid party returned.")

        adherence = only_party.get("adherence", {})
        if not adherence or adherence["status"] != "Active":
            raise ISharePartyStatusInvalid("Inactive party returned.")

        return result

    def verify_ca_certificate(self, json_web_token: str) -> None:
        """
        Verify whether the given certificate is signed by an CA trusted by iShare.
        :param json_web_token:
        :return:
        """
        x5c_finger_print = get_b64_x5c_fingerprints(json_web_token=json_web_token)[-1]
        trusted_ca_list = self.get_trusted_list()
        certificates = trusted_ca_list.get("trusted_list", [])

        for cert in certificates:
            if (
                cert["subject"] == x5c_finger_print["subject"]
                and cert["certificate_fingerprint"] == x5c_finger_print["finger_print"]
            ):
                return
        else:
            raise IShareInvalidCertificateIssuer("No trusted CA found.")

    def verify_json_web_token(
        self,
        client_id: str,
        client_assertion: str,
        audience: str,
        grant_type: Literal["client_credentials"],
        scope: Literal["iSHARE"],
        client_assertion_type: Literal[
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ],
    ) -> None:
        """
        :param client_id: iShare identifier of the Service Consumer.
        :param client_assertion: the json web token as per iShare specification.
        :param audience: ishare participant eori of the target service
        :param grant_type:
        :param scope:
        :param client_assertion_type:
        :raises IShareAuthenticationException: and all it's inheriting classes
        :return:
        """
        # TODO: Method flow needs to check the revocation list
        # TODO: Method flow cert also needs a check in the verify_party (undocumented?)
        validate_client_assertion(
            client_id=client_id,
            client_assertion=client_assertion,
            audience=audience,
            grant_type=grant_type,
            scope=scope,
            client_assertion_type=client_assertion_type,
        )
        self.verify_ca_certificate(json_web_token=client_assertion)
        self.verify_party(party_eori=client_id, certified_only=True)


class IShareAuthorizationRegistryClient(CommonBaseClient):
    """Responsible for communicating with an iShare Authorization Registry."""

    def request_delegation(self, use_token: bool) -> Any:  # pragma: no cover
        """
        https://dev.ishare.eu/delegation/endpoint.html

        :param use_token: If False the token will not be used and the unauthenticated
            response is returned as per specification.
        :return:
        """
        return self._get_request(
            endpoint_path="/delegation",
            use_token=use_token,
            decode_key="delegation_token",
        )
