try:
    import urllib.parse as urlparse
    from urllib.parse import urlencode, quote as urlquote
except:
    import urlparse as urlparse
    from urllib import urlencode, quote as urlquote
import sys
import base64
import collections
import hashlib
import requests
import json
import time


class URL(object):
    """A class that represents an absolute URL.
    """

    def __init__(self, url):
        """Initializes a URL object. The passed url must be an absolute url that can be parsed by urllib.

        Keyword arguments:
        url -- An absolute URL.
        """
        m_url = urlparse.urlparse(url)
        self.scheme = m_url.scheme
        self.host = m_url.netloc
        if not self.validate():
            raise ValueError("This class may only represent absolute URLs.")
        self.path = m_url.path
        self.rawquery = m_url.query
        self.query = collections.OrderedDict(sorted(urlparse.parse_qs(self.rawquery).items())) if self.rawquery is not None and self.rawquery != '' else None
        self.fragment = m_url.fragment
        self.form = {}

    def validate(self):
        """Validates the URL object. The URL object is invalid if it does not represent an absolute URL.
        Returns True or False based on this.
        """
        if (self.scheme is None or self.scheme != '') \
          and (self.host is None or self.host == ''):
            return False
        return True

    def __str__(self):
        """Returns the string representation of the URL. The string representation is a fully qualified URL.
        """
        if not self.validate():
            raise AttributeError()
        result = ''
        if self.scheme is not None and self.scheme != '':
            result += '{0}://{1}/'.format(self.scheme, self.host)
        elif self.host is not None and self.host != '':
            result += 'http://{0}/'.format(self.host)
        result += self.path.lstrip('/')
        if self.query is not None and self.query != '' and self.query != {}:
            result += '?{0}'.format(self.encoded_query())
        if self.fragment is not None and self.fragment != '':
            result += '#{0}'.format(self.fragment)
        return result

    def __repr__(self):
        """Returns the python representation of the URL.
        """
        return 'URL({0})'.format(repr(str(self)))

    def request_uri(self):
        """Returns the request URL element of the URL.
        This request URL is the path, the query and the fragment appended as a relative URL to the host.
        The request URL always contains at least a leading slash.
        """
        result = '/{0}'.format(self.path.lstrip('/'))
        if self.query is not None and self.query != '' and self.query != {}:
            result += '?{0}'.format(self.encoded_query())
        if self.fragment is not None and self.fragment != '':
            result += '#{0}'.format(self.fragment)
        return result

    def canonical_path(self):
        """Returns the canonical path of the URL, which is guaranteed to have a leading slash.
        """
        return '/{0}'.format(self.path.strip('/'))

    def encoded_query(self):
        """Returns the encoded query string of the URL. This may be different from the rawquery element,
        as that contains the query parsed by urllib but unmodified.
        The return value takes the form of key=value&key=value, and it never contains a leading question mark.
        """
        if self.query is not None and self.query != '' and self.query != {}:
            try:
                return urlencode(self.query, doseq=True, quote_via=urlquote)
            except TypeError:
                return '&'.join(["{0}={1}".format(urlquote(k), urlquote(self.query[k][0])) for k in self.query])
        else:
            return ''


def canonicalize_header(key):
    """Returns the canonicalized header name for the header name provided as an argument.
    The canonicalized header name according to the HTTP RFC is Kebab-Camel-Case.

    Keyword arguments:
    key -- the name of the header
    """
    bits = key.split('-')
    for idx, b in enumerate(bits):
        bits[idx] = b.capitalize()
    return '-'.join(bits)


class Request(object):
    def __init__(self):
        """Initializes a request object.
        """
        self.method = "GET"
        self.url = URL("http://localhost")
        self.header = {}
        self.body = b''

    def with_method(self, method):
        """Sets the request's method and returns the request itself.

        Keyword arguments:
        method -- the case-insensitive method to set for the request
        """
        self.method = method
        return self

    def with_url(self, url):
        """Sets the request's URL and returns the request itself.
        Automatically sets the Host header according to the URL.

        Keyword arguments:
        url -- a string representing the URL the set for the request
        """
        self.url = URL(url)
        self.header["Host"] = self.url.host
        return self

    def with_header(self, key, value):
        """Sets a header on the request and returns the request itself.
        The header key will be canonicalized before use. (see also: canonicalize_header)

        Keyword arguments:
        key -- the header's name
        value -- the string value for the header
        """
        self.header[canonicalize_header(key)] = value
        return self

    def with_headers(self, headers):
        """Sets multiple headers on the request and returns the request itself.

        Keyword arguments:
        headers -- a dict-like object which contains the headers to set.
        """
        for key, value in headers.items():
            self.with_header(key, value)
        return self

    def with_time(self):
        """Sets the time headers used by Acquia signature versions to the appropriate value and returns the request itself.
        These headers are X-Authorization-Timestamp (v2) and Date (v1).
        """
        self.header["X-Authorization-Timestamp"] = str(int(time.time()))
        self.header["Date"] = str(int(time.time()))
        return self

    def with_body(self, body):
        # @todo take encoding into account
        """Sets the request body to the provided value and returns the request itself.

        Keyword arguments:
        body -- A UTF-8 string or bytes-like object which represents the request body.
        """
        try:
            self.body = body.encode('utf-8')
        except:
            try:
                self.body = bytes(body)
            except:
                raise ValueError("Request body must be a string or bytes-like object.")
        hasher = hashlib.sha256()
        hasher.update(self.body)
        digest = base64.b64encode(hasher.digest()).decode('utf-8')
        self.with_header("X-Authorization-Content-Sha256", digest)
        return self

    def with_json_body(self, body):
        """Sets the request body to the provided value and returns the request itself.
        Also sets the Content-Type header to application/json.

        Keyword arguments:
        body -- A body that is either accepted by with_body or is convertible to (or is) a dict object.
            If a dict-like object is provided, it will be converted to a json string using json.dumps.
        """
        try:
            self.with_body(json.dumps(dict(body)))
        except:
            try:
                self.with_body(body)
            except:
                raise ValueError("Request body must be a string, bytes object, or a dict structure corresponding to a valid JSON.")
        self.header["Content-Type"] = "application/json"
        return self

    def get_header(self, key):
        """Returns the requested header, or an empty string if the header is not set.

        Keyword arguments:
        key -- The header name. It will be canonicalized before use.
        """
        key = canonicalize_header(key)
        if key in self.header:
            return self.header[key]
        return ''

    def do(self):
        """Executes the request represented by this object. The requests library will be used for this purpose.
        Returns an instance of requests.Response.
        """
        data = None
        if self.body is not None and self.body != b'':
            data = self.body
        return requests.request(self.method, str(self.url), data=data, headers=self.header)
