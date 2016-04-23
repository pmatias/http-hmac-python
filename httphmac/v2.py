from .base_signer import BaseSigner, BaseResponseSigner

import base64
import collections
import hashlib
import hmac
import re
import time
# from urllib import parse as urlparse

try:
    import urllib.parse as urlparse
    from urllib.parse import quote as urlquote
except:
    import urlparse as urlparse
    from urllib import quote as urlquote

class V2Signer(BaseSigner):
    """Implements a signer for the 2.0 version of the Acquia HTTP HMAC spec

    Reference: https://github.com/acquia/http-hmac-spec/tree/2.0
    """

    def __init__(self, digest=hashlib.sha256):
        """Initializes a V2Signer object.

        Keyword arguments:
        digest -- A callable which, when called, returns a hasher object.
            For example (and default value): hashlib.sha256
        """
        super(V2Signer, self).__init__(digest)
        self.preset_time = None

    def signable(self, request, authheaders, bodyhash=None):
        """Creates the signable string for a request and returns it.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        bodyhash -- The hash for the body of the request. None if the request contains no body.
            This is expected for internal reasons, otherwise the body would be hashed multiple times, degrading performance.
        """
        method = request.method.upper()
        host = request.get_header("host")
        path = request.url.canonical_path()
        query = request.url.encoded_query()

        timestamp = request.get_header("x-authorization-timestamp")
        auth_headers = self.unroll_auth_headers(authheaders, exclude_signature=True, sep='&', quote=False)
        base = '{0}\n{1}\n{2}\n{3}\n{4}'.format(method, host, path, query, auth_headers)

        cheaders = []
        cheaders_sign = '\n'
        if "headers" in authheaders and authheaders["headers"] != "":
            cheaders = authheaders["headers"].split(";")
        cheaders.sort()
        for cheader in cheaders:
            cheaders_sign += '{0}: {1}\n'.format(cheader.lower(), request.get_header(cheader))
        base += cheaders_sign
        base += '{0}'.format(timestamp)

        if bodyhash is not None:
            base += '\n{0}\n{1}'.format(request.get_header('content-type'), bodyhash)

        return base

    def parse_auth_headers(self, authorization):
        """Parses the authorization headers from the authorization header taken from a request.
        Returns a dict that is accepted by all other API functions which expect authorization headers in a dict format.
        parse_auth_headers(unroll_auth_headers(A)) should return a dict that is equal to A.

        Keyword arguments:
        authorization -- The authorization header of any request. The header must be in a format understood by v2.
        """
        matches = re.findall(r'(\w+)="(.*?)"', authorization)
        return dict(matches)

    def sign(self, request, authheaders, secret):
        """Returns the v2 signature appropriate for the request. The request is not changed by this function.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        if "id" not in authheaders or authheaders["id"] == '':
            raise KeyError("id required in authorization headers.")
        if "nonce" not in authheaders or authheaders["nonce"] == '':
            raise KeyError("nonce required in authorization headers.")
        if "realm" not in authheaders or authheaders["realm"] == '':
            raise KeyError("realm required in authorization headers.")
        if request.get_header('x-authorization-timestamp') == '':
            raise KeyError("X-Authorization-Timestamp is required.")
        bodyhash = None
        if request.body is not None and request.body != b'':
            sha256 = hashlib.sha256()
            sha256.update(request.body)
            bodyhash = base64.b64encode(sha256.digest()).decode('utf-8')

        try:
            mac = hmac.HMAC(base64.b64decode(secret.encode('utf-8'), validate=True), digestmod=self.digest)
        except TypeError:
            s = secret.encode('utf-8')
            if not re.match(b'^[A-Za-z0-9+/]*={0,2}$', s):
                raise binascii.Error('Non-base64 digit found')
            mac = hmac.HMAC(base64.b64decode(s), digestmod=self.digest)
        mac.update(self.signable(request, authheaders, bodyhash).encode('utf-8'))
        digest = mac.digest()
        return base64.b64encode(digest).decode('utf-8')

    def get_response_signer(self):
        """Returns the response signer for this version of the signature.
        """
        if not hasattr(self, "response_signer"):
            self.response_signer = V2ResponseSigner(self.digest, orig=self)
        return self.response_signer

    def matches(self, header):
        """Returns True if the provided authorization header matches the format expected by this signer.

        Keyword arguments:
        header -- A string representing the authorization header of a request.
        """
        if re.match(r'(?i)^\s*acquia-http-hmac.*?version=\"2\.0\".*?$', header) is not None:
            return True
        return False

    def check(self, request, secret):
        """Verifies whether or not the request bears an authorization appropriate and valid for this version of the signature.
        This verifies every element of the signature, including the timestamp's value.
        Does not alter the request.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        if request.get_header("Authorization") == "":
            return False
        ah = self.parse_auth_headers(request.get_header("Authorization"))
        if "signature" not in ah:
            return False
        if request.get_header('x-authorization-timestamp') == '':
            raise KeyError("X-Authorization-Timestamp is required.")
        timestamp = int(float(request.get_header('x-authorization-timestamp')))
        if timestamp == 0:
            raise ValueError("X-Authorization-Timestamp must be a valid, non-zero timestamp.")
        if self.preset_time is None:
            curr_time = time.time()
        else:
            curr_time = self.preset_time
        if timestamp > curr_time + 900:
            raise ValueError("X-Authorization-Timestamp is too far in the future.")
        if timestamp < curr_time - 900:
            raise ValueError("X-Authorization-Timestamp is too far in the past.")
        if request.body is not None and request.body != b'':
            content_hash = request.get_header("x-authorization-content-sha256")
            if content_hash == '':
                raise KeyError("X-Authorization-Content-SHA256 is required for requests with a request body.")
            sha256 = hashlib.sha256()
            sha256.update(request.body)
            if content_hash != base64.b64encode(sha256.digest()).decode('utf-8'):
                raise ValueError("X-Authorization-Content-SHA256 must match the SHA-256 hash of the request body.")
        return ah["signature"] == self.sign(request, ah, secret)

    def unroll_auth_headers(self, authheaders, exclude_signature=False, sep=",", quote=True):
        """Converts an authorization header dict-like object into a string representing the authorization.

        Keyword arguments:
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        """
        res = ""
        ordered = collections.OrderedDict(sorted(authheaders.items()))
        form = '{0}=\"{1}\"' if quote else '{0}={1}'
        if exclude_signature:
            return sep.join([form.format(k, urlquote(str(v), safe='')) for k, v in ordered.items() if k != 'signature'])
        else:
            return sep.join([form.format(k, urlquote(str(v), safe='') if k != 'signature' else str(v)) for k, v in ordered.items()])
        # legacy bad code
        # for k, v in ordered.items():
        #     if res != "":
        #        res += ","
        #     value = str(v)
        #     if k != "signature":
        #         value = urlquote(str(v), safe='')
        #     res += "{0}=\"{1}\"".format(k, value)
        # return res

    def sign_direct(self, request, authheaders, secret):
        """Signs a request directly with a v2 signature. The request's Authorization header will change.
        This function may also add the required X-Authorization-Timestamp and X-Authorization-Content-SHA256 headers.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        if request.get_header('x-authorization-timestamp') == '':
            request.with_header("X-Authorization-Timestamp", str(time.time()))
        if request.body is not None and request.body != b'':
            if request.get_header("x-authorization-content-sha256") == '':
                sha256 = hashlib.sha256()
                sha256.update(request.body)
                request.with_header("X-Authorization-Content-SHA256", base64.b64encode(sha256.digest()).decode('utf-8'))
        sig = self.sign(request, authheaders, secret)
        authheaders["signature"] = sig
        return request.with_header("Authorization", "acquia-http-hmac {0}".format(self.unroll_auth_headers(authheaders)))


class V2ResponseSigner(BaseResponseSigner):
    def __init__(self, digest=hashlib.sha256, orig=None):
        """Initializes a V2ResponseSigner object

        Keyword arguments:
        digest -- A callable which, when called, returns a hasher object.
            For example (and default value): hashlib.sha256
        orig -- A V2Signer object whose get_response_signer() returns this object.
            If None is provided, one such object is created internally.
        """
        super(V2ResponseSigner, self).__init__(digest)
        if orig is None:
            self.orig = V2Signer(digest)
            self.orig.response_signer = self
        else:
            self.orig = orig

    def check(self, request, response, secret):
        """Checks the response for the appropriate signature. Returns True if the signature matches the expected value.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        response -- A requests response object or compatible signed response object.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        auth = request.get_header('Authorization')
        if auth == '':
            raise KeyError('Authorization header is required for the request.')
        ah = self.orig.parse_auth_headers(auth)
        act = response.headers['X-Server-Authorization-HMAC-SHA256']
        if act == '':
            raise KeyError('Response is missing the signature header X-Server-Authorization-HMAC-SHA256.')
        sig = self.sign(request, ah, response.text, secret)
        return sig == act

    def signable(self, request, authheaders, response_body):
        """Creates the signable string for a response and returns it.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        response_body -- A string or bytes-like object which represents the body of the response.
        """
        nonce = authheaders["nonce"]
        timestamp = request.get_header("x-authorization-timestamp")
        try:
            body_str = response_body.decode('utf-8')
        except:
            body_str = response_body
        return '{0}\n{1}\n{2}'.format(nonce, timestamp, body_str)

    def sign(self, request, authheaders, response_body, secret):
        """Returns the response signature for the response to the request.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        response_body -- A string or bytes-like object which represents the body of the response.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        if "nonce" not in authheaders or authheaders["nonce"] == '':
            raise KeyError("nonce required in authorization headers.")
        if request.get_header('x-authorization-timestamp') == '':
            raise KeyError("X-Authorization-Timestamp is required.")

        try:
            mac = hmac.HMAC(base64.b64decode(secret.encode('utf-8'), validate=True), digestmod=self.digest)
        except TypeError:
            s = secret.encode('utf-8')
            if not re.match(b'^[A-Za-z0-9+/]*={0,2}$', s):
                raise binascii.Error('Non-base64 digit found')
            mac = hmac.HMAC(base64.b64decode(s), digestmod=self.digest)
        mac.update(self.signable(request, authheaders, response_body).encode('utf-8'))
        digest = mac.digest()
        return base64.b64encode(digest).decode('utf-8')
