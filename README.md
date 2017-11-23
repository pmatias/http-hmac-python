# HTTP HMAC Signer in Python

An implementation of the [HTTP HMAC Spec](https://github.com/acquia/http-hmac-spec) in Python.

## Bare bones example

```
import httphmac
import uuid

acquia_api_key = "YOUR-ACQUIA-API-KEY"
acquia_api_secret = "YOUR-ACQUIA-API-TOKEN"
acquia_base_url = "https://cloud.acquia.com/api"

r = httphmac.Request()
signer = httphmac.V2Signer()
auth_headers = {
    "realm": "HTTP HMAC Signer",
    "id": acquia_api_key,
    "nonce": uuid.uuid4().hex,
    "version": "2.0",
}

httphmac_request.with_url(acquia_base_url)
signer.sign_direct(r, auth_headers, acquia_api_secret)

print(httphmac_request.do().text)
```