"""Provides the ability to easily sign requests against Acquia's HTTP Hmac signature services.

To use, create an instance of the included Signer class with the request details."""


class BaseSigner(object):
    def __init__(self, digest):
        """Initializes a signer object.

        Keyword arguments:
        digest -- A callable which, when called, returns a hasher object.
        """
        self.digest = digest

    def sign(self, request, authheaders, secret):
        """Returns the signature appropriate for the request. The request is not changed by this function.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        return ''

    def parse_auth_headers(self, authorization):
        """Parses the authorization headers from the authorization header taken from a request.
        Returns a dict that is accepted by all other API functions which expect authorization headers in a dict format.

        Keyword arguments:
        authorization -- The authorization header of any request. The header must be in a format understood by the signer.
        """
        return {}

    def get_response_signer(self):
        """Returns the response signer for this version of the signature.

        Returns None if the signature version does not specify signatures for responses.
        """
        return None

    def matches(self, header):
        """Returns True if the provided authorization header matches the format expected by the implementing signer.

        Keyword arguments:
        header -- A string representing the authorization header of a request.
        """
        return False

    def check(self, request, secret):
        """Verifies whether or not the request bears an authorization appropriate and valid for this version of the signature.
        This verifies every element of the signature, including headers other than Authorization.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        return False

    def sign_direct(self, request, authheaders, secret):
        """Signs a request directly with an appropriate signature. The request's Authorization header will change.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        return request


class BaseResponseSigner(object):
    def __init__(self, digest):
        """Initializes a response signer object.

        Keyword arguments:
        digest -- A callable which, when called, returns a hasher object.
        """
        self.digest = digest

    def sign(self, request, authheaders, response_body, secret):
        """Returns the response signature for the response to the request.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        response_body -- A string or bytes-like object which represents the body of the response.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        return ''

    def check(self, request, response, secret):
        """Checks the response for the appropriate signature. Returns True if the signature matches the expected value.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        response -- A requests response object or compatible signed response object.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        return False