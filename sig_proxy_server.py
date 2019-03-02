import cgi
import logging
import re
import string
import sys
import urllib
import unicodedata
from http.server import BaseHTTPRequestHandler, HTTPServer
#from socketserver import ThreadingMixIn
import enforce
enforce.config({'enabled': True, 'mode': 'covariant'})
import config
from get_seclay_request import get_seclay_request


def main():
    c = config.SigProxyConfig
    print(f'starting {__file__} at {c.host}:{c.port}')
    httpd = HTTPServer((c.host, c.port), RequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


class InvalidArgs(Exception):
    pass


#@enforce.runtime_validation
class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.cfg = config.SigProxyConfig
        super().__init__(*args, **kwargs)

    def do_GET(self):
        logging.info(f"GET {self.path}")
        try:
            if self.path.startswith(self.cfg.loadsigproxyclient_path):
                self._loadsigproxyclient()
            else:
                self.send_error(404, 'no service at this path')
        except InvalidArgs as e:
            self.send_error(422, str(e))
        except Exception as e:
            self.send_error(400, str(e))

    def _loadsigproxyclient(self):
        sigproxyclient_html = self._render_sigproxyclient_html()
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(sigproxyclient_html)

    def _render_sigproxyclient_html(self):
        sigproxyclient_js = self._render_sigproxyclient_js()
        with self.cfg.sig_proxy_html_template.open('r') as fd:
            html_template = string.Template(fd.read())
        html = html_template.substitute({'javascript': sigproxyclient_js})
        return html.encode('utf-8')

    def _render_sigproxyclient_js(self):
        urlparts = urllib.parse.urlparse(self.path)
        urlparams_sane = self._sanitize(urlparts.query)
        js_params = {
            'getsignedxmldoc_url': self.cfg.rooturl + self.cfg.getsignedxmldoc_path,
            'sigservice_url': config.SigServiceConfig.url,
            **urlparams_sane,
        }
        with self.cfg.sig_proxy_js_template.open('r') as fd:
            js_template = string.Template(fd.read())
        js = js_template.substitute(js_params)
        return js

    def _sanitize(self, query_part: str) -> dict:
        mandatoryparams = {'result_to', 'return', 'sigtype', 'unsignedxml_url', }
        urlparams = dict(urllib.parse.parse_qsl(query_part))
        if 'sigtype' not in urlparams:
            urlparams['sigtype'] = self.cfg.SIGTYPE_SAMLED
        if set(urlparams.keys()) != mandatoryparams:
            raise InvalidArgs(f"URL parameters must be these: {mandatoryparams}")
        if urlparams['sigtype'] not in self.cfg.SIGTYPE_VALUES:
            raise InvalidArgs(f"URL parameters must be on of: {self.cfg.SIGTYPE_VALUES}")
        urlparams_sane = {}
        valid_chars = "-_.+/%s%s" % (string.ascii_letters, string.digits)   # restrictive charset
        for k,v1 in urlparams.items():
            v2 = unicodedata.normalize('NFKD', v1)
            v3 = v2.encode('ascii', 'ignore').decode('ascii')
            v4 = ''.join(c for c in v3 if c in valid_chars)
            urlparams_sane[k] = v4
        return urlparams_sane

    def do_POST(self):
        logging.info(f"POST {self.path}")
        self.post_vars = self._parse_postvars()
        try:
            if self.path == self.cfg.make_cresigrequ_path:
                self._make_cresigrequ()
            elif self.path == self.cfg.getsignedxmldoc_path:
                self._get_signedxmldoc()
            else:
                self.send_error(404, 'no POST service at this path')
        except InvalidArgs as e:
            self.send_error(422, str(e))
        except Exception as e:
            self.send_error(400, str(e))

    def _make_cresigrequ(self):
        sigtype = str(self.post_vars[b'sigtype'][0]) if b'sigtype' in self.post_vars else self.cfg.SIGTYPE_SAMLED
        unsignedxml = self.post_vars[b'unsignedxml'][0]
        #unsignedxml = urllib.parse.unquote(unsignedxml_qt)
        create_xml_signature_request = self._get_CreateXMLSignatureRequest(sigtype, unsignedxml)
        self._send_response_xml(create_xml_signature_request )

    def _get_CreateXMLSignatureRequest(self, sigtype: str, unsignedxml: bytes) -> bytes:
        if sigtype == self.cfg.SIGTYPE_ENVELOPING:
            xml = get_seclay_request(self.cfg.SIGTYPE_ENVELOPING, unsignedxml)
            return xml
        elif sigtype == self.cfg.SIGTYPE_SAMLED:
            ns_prefix = self._get_namespace_prefix(unsignedxml)
            sigpos = f"/{ns_prefix}:EntityDescriptor"
            xml = get_seclay_request(self.cfg.SIGTYPE_ENVELOPED, unsignedxml, sigPosition=sigpos)
            return xml
        else:
            raise InvalidArgs('sigtype argument value must be in ' + ', '.join(self.cfg.SIGTYPE_VALUES))

    def _get_namespace_prefix(self, unsignedxml: bytes) -> str:
        """ Due to a limitation in the XML signer (SecurityLayer 1.2) the XPath expression for the
            enveloped signature is specified as namespace prefix.
            getNamespacePrefix extracts the prefix to be used in the XPath when calling the signature.
            This functions is using a regular expression.
            YMMV in corner cases, like having different prefixes for the same ns.
        """
        p = re.compile(bytes(r'\sxmlns:(\w+)\s*=\s*"urn:oasis:names:tc:SAML:2.0:metadata"'.encode('ascii')))
        m = p.search(unsignedxml)
        return m.group(1).decode('ascii')

    def _get_signedxmldoc(self):
        post_data = self.post_vars[b'sigresponse'][0]
        # sig_response = urllib.parse.unquote(post_data.decode('utf-8'))
        # Strip xml root element (CreateXMLSignatureResponse), making disg:Signature the new root:
        # (keeping namespace prefixes + whitespace - otherwise the signature would break. Therefore NOT parsing xml.)
        r1 = re.sub(r'<sl:CreateXMLSignatureResponse [^>]*>'.encode('ascii'), b'', post_data)
        r2 = re.sub(r'</sl:CreateXMLSignatureResponse>'.encode('ascii'), b'', r1)
        self._send_response_xml(r2)

    def _send_response_xml(self, xml: bytes):
        self.send_response(200)
        self.send_header('Content-type', 'application/xml')
        self.end_headers()
        self.wfile.write(xml)
        return

    def _parse_postvars(self) -> dict:
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['content-length'])
            postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}
        return postvars


if __name__ == '__main__':
    if sys.version_info < (3, 6):
        raise "must use python 3.6 or higher"
    main()
