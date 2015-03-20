from httphmac import signer
import hashlib

@given('the endpoint "{method}" "{path}"')
def step_impl(context, method, path):
	context.method = method
	context.path = path

@given('the header "{key}" "{value}"')
def step_impl(context, key, value):
	if 'headers' not in context:
		context.headers = {}
	context.headers[key] = value

@given('the custom header "{key}" "{value}"')
def step_impl(context, key, value):
	if 'headers' not in context:
		context.headers = {}
	context.headers[key] = value
	if 'cheaders 'not in context:
		context.cheaders = {}
	context.cheaders[key] = value

@given('the body "{body}"')
def step_impl(context, body):
	context.body = body

@when('I sign the request with the "{digest}" digest and secret key "{key}"')
def step_impl(context, digest, key):
	body = ""
	headers = {}
	cheaders = {}
	if 'body' in context:
		body = context.body
	if 'headers' in context:
		headers = context.headers
	if 'cheaders' in context:
		cheaders = context.cheaders
	hmaccer = signer.Signer(context.method, body, headers, cheaders, context.path)
	if digest == "SHA-1" or digest == "SHA1":
		digester = hashlib.sha1
	elif digest == "SHA-256" or digest == "SHA256":
		digester = hashlib.sha256
	context.signature = hmaccer.sign(digester, key)

@then('I should see the signature "{signature}"')
def step_impl(context, signature):
	assert context.signature == signature.encode('utf-8')