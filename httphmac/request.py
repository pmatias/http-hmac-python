from urllib import parse
import requests


class URL:
    def __init__(self, url):
        m_url = parse.urlparse(url)
        self.scheme = m_url.scheme
        self.host = m_url.netloc
        self.path = m_url.path
        self.query = m_url.query
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
            result += '?{0}'.format(self.query)
        if self.fragment is not None and self.fragment != '':
            result += '#{0}'.format(self.fragment)
        return result

    def __repr__(self):
        return str(self)

    def request_uri(self):
        result = '/{0}'.format(self.path.lstrip('/'))
        if self.query is not None and self.query != '':
            result += '?{0}'.format(self.query)
        if self.fragment is not None and self.fragment != '':
            result += '#{0}'.format(self.fragment)
        return result

    def canonical_path(self):
        return '/{0}'.format(self.path.strip('/'))


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
        return self

    def with_header(self, key, value):
        self.header[self.canonicalize_header(key)] = value
        return self

    def with_headers(self, headers):
        for key, value in headers.items():
            self.with_header(key, value)
        return self

    def with_body(self, body):
        if isinstance(body, bytes):
            self.body = body
        elif isinstance(body, str):
            self.body = body.encode('utf-8')
        else:
            raise ValueError("Request body must be a string or bytes object.")
        return self

    def canonicalize_header(self, key):
        bits = key.split('-')
        for idx, b in enumerate(bits):
            bits[idx] = b.capitalize()
        return '-'.join(bits)

    def get_header(self, key):
        key = self.canonicalize_header(key)
        if key in self.header:
            return self.header[key]
        return ''

    def do(self):
        data = None
        if self.body is not None and self.body != b'':
            data = self.body
        return requests.request(self.method, str(self.url), data=data, headers=self.header)
