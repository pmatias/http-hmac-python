from httphmac.compat import SignatureIdentifier
from httphmac.request import Request
from httphmac.v1 import V1Signer
from httphmac.v2 import V2Signer
try:
    import urllib.parse as urlparse
except:
    import urlparse as urlparse
import hashlib
import base64


def get_version(version):
    v = version.lower()
    if v == "v1":
        return V1Signer
    elif v == "v2":
        return V2Signer
    else:
        raise ValueError("Unknown signer version {0}".format(version))


def get_digest(digest):
    d = digest.upper().replace('-', '')
    if d == "SHA1":
        return hashlib.sha1
    elif d == "SHA256":
        return hashlib.sha256
    elif d == "MD5":
        return hashlib.md5
    else:
        raise ValueError("Unknown digester {0}".format(digest))


@given('a new request')
def step_impl(context):
    context.request = Request()
    context.auth_headers = {}


@given('the endpoint "{method}" "{uri}"')
def step_impl(context, method, uri):
    context.request.with_method(method).with_url(uri)


@given('the header "{key}" ""')
def step_impl(context, key):
    pass

@given('the header "{key}" "{value}"')
def step_impl(context, key, value):
    context.request.with_header(key, value)


@given('the headers "" in query format')
def step_impl(context):
    pass


@given('the headers "{headers}" in query format')
def step_impl(context, headers):
    res = urlparse.parse_qs(headers, strict_parsing=1)
    for key, value in res.items():
        context.request.with_header(key, ', '.join(value))


@given('the body "{body}"')
def step_impl(context, body):
    context.request.with_body(body.encode('utf-8'))


@given('the response body "{body}"')
def step_impl(context, body):
    context.response_body = body.encode('utf-8')


@given('the calculated {digest} hash of the body as the header "{key}"')
def step_impl(context, digest, key):
    digester = get_digest(digest)()
    digester.update(context.request.body)
    context.request.with_header(key, base64.b64encode(digester.digest()).decode('utf-8'))


@given('parsed auth headers')
def step_impl(context):
    context.auth_headers = context.signer.parse_auth_headers(context.request)


@given('the auth header "{key}" "{value}"')
def step_impl(context, key, value):
    context.auth_headers[key] = value


@given('the auth header "{key}" ""')
def step_impl(context, key):
    pass


@given('a {version} signer with the "{digest}" digest')
def step_impl(context, version, digest):
    classname = get_version(version)
    digester = get_digest(digest)
    context.signer = classname(digester)


@given('a compatibility layer spanning from version {v1} to {v2} with the "{digest}" digest')
def step_impl(context, v1, v2, digest):
    v1i = int(float(v1))
    v2i = int(float(v2))
    context.compat = SignatureIdentifier(get_digest(digest), v1i, v2i)


@given('the fixed server time "{timestamp}"')
def step_impl(context, timestamp):
    if hasattr(context.signer, "preset_time"):
        context.signer.preset_time = int(float(timestamp))


@when('I sign the request with the secret key "{key}"')
def step_impl(context, key):
    context.signature = context.signer.sign(context.request, context.auth_headers, key)


@when('I sign the response with the secret key "{key}"')
def step_impl(context, key):
    resp_signer = context.signer.get_response_signer()
    context.signature = resp_signer.sign(context.request, context.auth_headers, context.response_body, key)


@when('I try to identify the "{header}" header')
def step_impl(context, header):
    context.id_signer = context.compat.identify(header)


@then('I should see the signature "{signature}"')
def step_impl(context, signature):
    assert context.signature == signature


@then('I should get an instance of the {version} signer')
def step_impl(context, version):
    exp_class = get_version(version)
    print(context.id_signer)
    print(exp_class)
    assert isinstance(context.id_signer, exp_class)


@then('I should get no hits for a matching signer')
def step_impl(context):
    assert context.id_signer is None