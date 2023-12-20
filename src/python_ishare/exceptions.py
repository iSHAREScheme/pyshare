class ISHAREAuthenticationException(Exception):
    """
    Base class exception to be able to catch *all* other types of sub exception raised
    by this package.
    """

    pass


class ISHAREInvalidGrantType(ISHAREAuthenticationException):
    pass


class ISHAREInvalidScope(ISHAREAuthenticationException):
    pass


class ISHAREInvalidAudience(ISHAREAuthenticationException):
    pass


class ISHAREInvalidClientId(ISHAREAuthenticationException):
    pass


class ISHAREInvalidClientAssertionType(ISHAREAuthenticationException):
    pass


class ISHAREInvalidToken(ISHAREAuthenticationException):
    pass


class ISHAREInvalidTokenAlgorithm(ISHAREInvalidToken):
    pass


class ISHAREInvalidTokenType(ISHAREInvalidToken):
    pass


class ISHAREInvalidTokenX5C(ISHAREInvalidToken):
    pass


class ISHAREInvalidTokenIssuerOrSubscriber(ISHAREInvalidToken):
    pass


class ISHAREInvalidTokenJTI(ISHAREInvalidToken):
    pass


class ISHARETokenExpirationInvalid(ISHAREInvalidToken):
    pass


class ISHARETokenExpired(ISHAREInvalidToken):
    pass


class ISHARETokenNotValidYet(ISHAREInvalidToken):
    pass


class ISHAREInvalidTokenSigner(ISHAREInvalidToken):
    pass


class ISHAREInvalidCertificate(ISHAREAuthenticationException):
    pass


class ISHARECertificateExpired(ISHAREInvalidCertificate):
    pass


class ISHAREInvalidCertificateIssuer(ISHAREInvalidCertificate):
    pass


class ISHAREPartyStatusInvalid(ISHAREAuthenticationException):
    pass
