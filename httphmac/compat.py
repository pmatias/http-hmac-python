from .v1 import V1Signer
from .v2 import V2Signer
import hashlib


def get_signer_by_version(digest, ver):
    if ver == 1:
        return V1Signer(digest)
    elif ver == 2:
        return V2Signer(digest)
    else:
        return None


class SignatureIdentifier:
    def __init__(self, digest=hashlib.sha256, minver=1, maxver=2):
        self.signers = {}
        for ver in range(minver, maxver + 1):
            signer = get_signer_by_version(digest, ver)
            if signer is not None:
                self.signers[str(ver)] = signer

    def identify(self, header):
        for ver, signer in self.signers.items():
            if signer.matches(header):
                return signer
        return None
