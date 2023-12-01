class IShareAuthenticationException(Exception):
    """
    Base class exception to be able to catch *all* other types of sub exception raised
    by this package.
    """

    pass


class IShareInvalidGrantType(IShareAuthenticationException):
    pass


class IShareInvalidScope(IShareAuthenticationException):
    pass


class IShareInvalidAudience(IShareAuthenticationException):
    pass


class IShareInvalidClientId(IShareAuthenticationException):
    pass


class IShareInvalidClientAssertionType(IShareAuthenticationException):
    pass


class IShareInvalidToken(IShareAuthenticationException):
    pass


class IShareInvalidTokenAlgorithm(IShareInvalidToken):
    pass


class IShareInvalidTokenType(IShareInvalidToken):
    pass


class IShareInvalidTokenX5C(IShareInvalidToken):
    pass


class IShareInvalidTokenIssuerOrSubscriber(IShareInvalidToken):
    pass


class IShareInvalidTokenJTI(IShareInvalidToken):
    pass


class IShareTokenExpirationInvalid(IShareInvalidToken):
    pass


class IShareTokenExpired(IShareInvalidToken):
    pass


class IShareTokenNotValidYet(IShareInvalidToken):
    pass


class IShareInvalidTokenSigner(IShareInvalidToken):
    pass


class IShareInvalidCertificate(IShareAuthenticationException):
    pass


class IShareCertificateExpired(IShareInvalidCertificate):
    pass


class IShareInvalidCertificateIssuer(IShareInvalidCertificate):
    pass


class ISharePartyStatusInvalid(IShareAuthenticationException):
    pass
