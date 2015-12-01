"""Provides the ability to easily sign requests against Acquia's HTTP Hmac signature services.

To use, create an instance of the included Signer class with the request details."""


class BaseSigner:
    def __init__(self, digest):
        self.digest = digest

    def sign(self, request, authheaders, secret):
        return ''

    def parse_auth_headers(self, authorization):
        return {}

    def get_response_signer(self):
        return None

    def matches(self, header):
        return False

class BaseResponseSigner:
    def __init__(self, digest):
        self.digest = digest

    def sign(self, request, authheaders, response_body, secret):
        return ''

    def parse_auth_headers(self, authorization):
        return {}
