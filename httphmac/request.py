from urllib import parse
import base64
import hashlib
import requests
import json
import time


class URL:
    def __init__(self, url):
        m_url = parse.urlparse(url)
        self.scheme = m_url.scheme
        self.host = m_url.netloc
        self.path = m_url.path
        self.rawquery = m_url.query
        self.query = parse.parse_qs(self.rawquery) if self.rawquery is not None else None
        self.fragment = m_url.fragment
        self.form = {}

    def validate(self):
        if (self.scheme is None or self.scheme != '') \
          and (self.host is None or self.host == ''):
            return False
        return True

    def parse_form(self):
        self.form = parse.parse_qs(self.query)

    def __str__(self):
        if not self.validate():
            raise AttributeError()
        result = ''
        if self.scheme is not None and self.scheme != '':
            result += '{0}://{1}/'.format(self.scheme, self.host)
        elif self.host is not None and self.host != '':
            result += 'http://{0}/'.format(self.host)
        result += self.path.lstrip('/')
        if self.query is not None and self.query != '':
            result += '?{0}'.format(self.encoded_query())
        if self.fragment is not None and self.fragment != '':
            result += '#{0}'.format(self.fragment)
        return result

    def __repr__(self):
        return str(self)

    def request_uri(self):
        result = '/{0}'.format(self.path.lstrip('/'))
        if self.query is not None and self.query != '':
            result += '?{0}'.format(self.encoded_query())
        if self.fragment is not None and self.fragment != '':
            result += '#{0}'.format(self.fragment)
        return result

    def canonical_path(self):
        return '/{0}'.format(self.path.strip('/'))

    def encoded_query(self):
        if self.query is not None and self.query != '':
            return parse.urlencode(self.query, doseq=True, quote_via=parse.quote)
        else:
            return ''


def canonicalize_header(key):
    bits = key.split('-')
    for idx, b in enumerate(bits):
        bits[idx] = b.capitalize()
    return '-'.join(bits)


class Request:
    def __init__(self):
        self.method = "GET"
        self.url = URL("http://localhost")
        self.header = {}
        self.body = b''

    def with_method(self, method):
        self.method = method
        return self

    def with_url(self, url):
        self.url = URL(url)
        self.header["Host"] = self.url.host
        return self

    def with_header(self, key, value):
        self.header[canonicalize_header(key)] = value
        return self

    def with_headers(self, headers):
        for key, value in headers.items():
            self.with_header(key, value)
        return self

    def with_time(self):
        self.header["X-Authorization-Timestamp"] = str(int(time.time()))
        self.header["Date"] = str(int(time.time()))
        return self

    def with_body(self, body):
        if isinstance(body, bytes):
            self.body = body
        elif isinstance(body, str):
            self.body = body.encode('utf-8')
        else:
            raise ValueError("Request body must be a string or bytes object.")
        hasher = hashlib.sha256()
        hasher.update(self.body)
        digest = base64.b64encode(hasher.digest()).decode('utf-8')
        self.with_header("X-Authorization-Content-Sha256", digest)
        return self

    def with_json_body(self, body):
        if isinstance(body, dict):
            try:
                self.with_body(json.dumps(body))
            except ValueError:
                raise ValueError("Request body must be a string, bytes object, or a dict structure corresponding to a valid JSON.")
        else:
            self.with_body(body)
        self.header["Content-Type"] = "application/json"
        return self

    def get_header(self, key):
        key = canonicalize_header(key)
        if key in self.header:
            return self.header[key]
        return ''

    def do(self):
        data = None
        if self.body is not None and self.body != b'':
            data = self.body
        return requests.request(self.method, str(self.url), data=data, headers=self.header)
