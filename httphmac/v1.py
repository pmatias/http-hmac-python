from .base_signer import BaseSigner

import base64
import hashlib
import hmac
import re


class V1Signer(BaseSigner):
    def __init__(self, digest):
        """Initializes a V1Signer object.

        Keyword arguments:
        digest -- A callable which, when called, returns a hasher object.
            For example (and default value): hashlib.sha256
        """
        super(V1Signer, self).__init__(digest)

    def signable(self, request, authheaders):
        """Creates the signable string for a request and returns it.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        """
        method = request.method.upper()
        md5 = hashlib.md5()
        if request.body is not None:
            md5.update(request.body)
        bodyhash = md5.hexdigest()
        ctype = request.get_header("content-type")
        date = request.get_header("date")
        cheaders = []
        cheader_first = True
        cheaders_sign = ''
        if "headers" in authheaders:
            cheaders = authheaders["headers"].split(";")
        cheaders.sort()
        for cheader in cheaders:
            if cheader_first:
                cheader_first = False
            else:
                cheaders_sign += '\n'
            cheaders_sign += '{0}: {1}'.format(cheader.lower(), request.get_header(cheader))
        requri = request.url.request_uri()

        return '{0}\n{1}\n{2}\n{3}\n{4}\n{5}'.format(method, bodyhash, ctype, date, cheaders_sign, requri)

    def sign(self, request, authheaders, secret):
        """Returns the signature appropriate for the request. The request is not changed by this function.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        mac = hmac.HMAC(secret.encode('utf-8'), digestmod=self.digest)
        mac.update(self.signable(request, authheaders).encode('utf-8'))
        digest = mac.digest()
        return base64.b64encode(digest).decode('utf-8')

    def matches(self, header):
        """Returns True if the provided authorization header matches the format expected by the implementing signer.

        Keyword arguments:
        header -- A string representing the authorization header of a request.
        """
        if re.match(r'(?i)^\s*Acquia\s*[^:]+\s*:\s*[0-9a-zA-Z\\+/=]+\s*$', header) is not None:
            return True
        return False

    def parse_auth_headers(self, authorization):
        """Parses the authorization headers from the authorization header taken from a request.
        Returns a dict that is accepted by all other API functions which expect authorization headers in a dict format.

        Keyword arguments:
        authorization -- The authorization header of any request. The header must be in a format understood by the signer.
        """
        m = re.match(r'^(?i)Acquia\s+(.*?):(.+)$', authorization)
        if m is not None:
            return {"id": m.group(1), "signature": m.group(2)}
        return {}

    def check(self, request, secret):
        """Verifies whether or not the request bears an authorization appropriate and valid for this version of the signature.
        This verifies every element of the signature, including headers other than Authorization.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        if request.get_header("Authorization") == "":
            return False
        ah = self.parse_auth_headers(request.get_header("Authorization"))
        if "id" not in ah:
            return False
        if "signature" not in ah:
            return False
        return ah["signature"] == self.sign(request, ah, secret)

    def sign_direct(self, request, authheaders, secret):
        """Signs a request directly with an appropriate signature. The request's Authorization header will change.

        Keyword arguments:
        request -- A request object which can be consumed by this API.
        authheaders -- A string-indexable object which contains the headers appropriate for this signature version.
        secret -- The base64-encoded secret key for the HMAC authorization.
        """
        sig = self.sign(request, authheaders, secret)
        return request.with_header("Authorization", "Acquia {0}:{1}".format(authheaders["id"], sig))
