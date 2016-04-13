from .v1 import V1Signer
from .v2 import V2Signer
import hashlib


def get_signer_by_version(digest, ver):
    """Returns a new signer object for a digest and version combination.

    Keyword arguments:
    digest -- a callable that may be passed to the initializer of any Signer object in this library.
        The callable must return a hasher object when called with no arguments.
    ver -- the version of the signature. This may be any value convertible to an int.
    """
    if int(ver) == 1:
        return V1Signer(digest)
    elif int(ver) == 2:
        return V2Signer(digest)
    else:
        return None


class SignatureIdentifier(object):
    """An object that represents a compatibility layer across signature versions.
    It is capable of identifying the version range of signatures that is provided to it.
    """
    def __init__(self, digest=hashlib.sha256, minver=1, maxver=2):
        """Initializes a SignatureIdentifier object.

        Keyword arguments:
        digest -- a callable that may be passed to the initializer of any Signer object in this library.
            The callable must return a hasher object when called with no arguments.
        minver -- the minimum (inclusive) version of signature that this identifier should be able to identify.
        maxver -- the maximum (inclusive) version of signature that this identifier should be able to identify.
        """
        self.signers = {}
        for ver in range(minver, maxver + 1):
            signer = get_signer_by_version(digest, ver)
            if signer is not None:
                self.signers[str(ver)] = signer

    def identify(self, header):
        """Identifies a signature and returns the appropriate Signer object.
        This is done by reading an authorization header and matching it to signature characteristics.
        None is returned if the authorization header does not match the format of any signature identified by this identifier.

        Keyword arguments:
        header -- the Authorization header of a request.
        """
        for ver, signer in self.signers.items():
            if signer.matches(header):
                return signer
        return None
