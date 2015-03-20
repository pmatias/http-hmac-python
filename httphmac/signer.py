"""Provides the ability to easily sign requests against Acquia's HTTP Hmac signature services.

To use, create an instance of the included Signer class with the request details."""

import base64
import hashlib
import hmac

class Signer:
	def __init__(self, method, body = '', headers = {}, customheaders = {}, path = '/'):
		"""Initialize a signer object with the data specific to the request.

		Keyword arguments:
		method -- The HTTP request method.
		body -- If applicable, the body of the HTTP request.
		headers -- A dict of all headers included in the HTTP request.
		customheaders -- A dict of headers to be included into the signature. Content-Type and Date are included by default and should not be passed as a custom header.
		path -- The path of the request, relative to the root of the API. For example: /query."""
		md5 = hashlib.md5()
		md5.update(body.encode('utf-8'))
		bodyhash = md5.hexdigest()
		ct = ''
		date = ''
		if 'Content-Type' in headers:
			ct = headers['Content-Type']
		if 'Date' in headers:
			date = headers['Date']
		data = "{0}\n{1}\n{2}\n{3}\n".format(method.upper(), bodyhash, ct, date)
		if len(customheaders):
			for k,v in customheaders.items():
				data = data + "{0}: {1}\n".format(k.lower(), v)
		else:
			data = data + "\n"
		data = data + path
		self.signable = data

	def sign(self, hasher, secret):
		"""Sign the request with a hashing algorithm, using the provided secret key. Returns the base64 encoded hmac digest.

		Keyword arguments:
		hasher -- A hasher constructor or a module adhering to the appropriate standards. For more information, see the digestmod parameter of the hmac.hmac initializer.
		secret -- The secret key used to sign the request. This is an arbitrary string."""
		mac = hmac.HMAC(secret.encode('utf-8'), digestmod=hasher)
		mac.update(self.signable.encode('utf-8'))
		digest = mac.digest()
		return base64.b64encode(digest)



