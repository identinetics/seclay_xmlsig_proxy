import re
import string
import sys
import unicodedata
import enforce
enforce.config({'enabled': True, 'mode': 'covariant'})
import lxml.etree
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import HTTPException, NotFound
import config
from config import SigProxyConfig as cfg
from get_seclay_request import get_seclay_request


class InvalidArgs(Exception):
    pass


class InvalidPath(Exception):
    pass


class SeclayError(Exception):
    ''' Error reported in response content with HTTP code 200 '''
    pass


#@enforce.runtime_validation
class AppHandler():
    # --- GET handler ---
    def do_GET(self, req: Request) -> Response:
        if req.path.startswith(cfg.loadsigproxyclient_path):
            return self._loadsigproxyclient(req)
        else:
            raise NotFound

    def _loadsigproxyclient(self, req: Request) -> Response:
        sigproxyclient_html = self._render_sigproxyclient_html(req)
        response = Response(sigproxyclient_html)
        response.headers['content-type'] = 'text/html'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    def _render_sigproxyclient_html(self, req: Request) -> str:
        sigproxyclient_js = self._render_sigproxyclient_js(req)
        with cfg.sig_proxy_html_template.open('r') as fd:
            html_template = string.Template(fd.read())
        html = html_template.substitute({'javascript': sigproxyclient_js})
        return html

    def _render_sigproxyclient_js(self, req: Request) -> str:
        urlparams_sane = self._sanitize(dict(req.args))
        js_params = {
            'getsignedxmldoc_url': cfg.rooturl + cfg.getsignedxmldoc_url,
            'make_cresigrequ_url': cfg.rooturl + cfg.make_cresigrequ_url,
            'sigservice_url': config.SigServiceConfig.url,
            **urlparams_sane,
        }
        with cfg.sig_proxy_js_template.open('r') as fd:
            js_template = string.Template(fd.read())
        js = js_template.substitute(js_params)
        return js

    def _sanitize(self, urlparams: dict) -> dict:
        mandatoryparams = set(cfg.mandatoryparamtypes.keys())
        if 'sigtype' not in urlparams:
            urlparams['sigtype'] = cfg.SIGTYPE_SAMLED
        if len(set(urlparams.keys()).difference(mandatoryparams)) > 0:
            raise InvalidArgs(f"URL parameters must be these: {mandatoryparams}. {set(urlparams.keys()).difference(mandatoryparams)}?")
        if urlparams['sigtype'] not in cfg.SIGTYPE_VALUES:
            raise InvalidArgs(f"URL parameters must be on of: {cfg.SIGTYPE_VALUES}")
        urlparams_sane = {}
        valid_chars = "-_.:+/%s%s" % (string.ascii_letters, string.digits)   # restrictive charset
        for k,v1 in urlparams.items():
            if not self.is_allowed_host(k, v1):
                raise InvalidArgs(f"URL parameter {k} is not an allowed_host: {v1}")
            v2 = unicodedata.normalize('NFKD', v1)
            v3 = v2.encode('ascii', 'ignore').decode('ascii')
            v4 = ''.join(c for c in v3 if c in valid_chars)
            urlparams_sane[k] = v4
        return urlparams_sane

    def is_allowed_host(self, param_name, param_value) -> bool:
        if cfg.mandatoryparamtypes[param_name] != 'url':
            return True
        for url in cfg.allowed_urls:
            if param_value.startswith(url) or url == '*':
                return True
        return False

    # --- POST handler ---
    def do_POST(self, req: Request) -> Response:
        if req.path == cfg.make_cresigrequ_url:
            return self._make_cresigrequ(req)
        elif req.path == cfg.getsignedxmldoc_url:
            return self._get_signedxmldoc(req)
        else:
            raise NotFound

    def _make_cresigrequ(self, req: Request) -> Response:
        sigtype = req.args[b'sigtype'][0].decode('utf-8') if b'sigtype' in req.args else cfg.SIGTYPE_SAMLED
        unsignedxml = req.form['unsignedxml']
        #unsignedxml = urllib.parse.unquote(unsignedxml_qt)
        create_xml_signature_request = self._get_CreateXMLSignatureRequest(sigtype, unsignedxml)
        response = Response(create_xml_signature_request)
        response.headers['content-type'] = 'application/xml'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    def _get_CreateXMLSignatureRequest(self, sigtype: str, unsignedxml: str) -> str:
        if sigtype == cfg.SIGTYPE_ENVELOPING:
            xml = get_seclay_request(cfg.SIGTYPE_ENVELOPING, unsignedxml)
            return xml
        elif sigtype == cfg.SIGTYPE_SAMLED:
            unsignedxml_tidy = AppHandler._tidy_saml_entitydescriptor(unsignedxml)
            ns_prefix = self._get_namespace_prefix(unsignedxml_tidy)
            sigpos = f"/{ns_prefix}:EntityDescriptor"
            xml = get_seclay_request(cfg.SIGTYPE_ENVELOPED, unsignedxml_tidy, sigPosition=sigpos)
            return xml
        else:
            raise InvalidArgs('sigtype argument value must be in ' + ', '.join(cfg.SIGTYPE_VALUES))

    @staticmethod
    def _tidy_saml_entitydescriptor(xml: str) -> str:
        xslt_filename = cfg.tidy_samlentityescriptor_xslt
        xslt = lxml.etree.parse(xslt_filename)
        transform = lxml.etree.XSLT(xslt)
        dom = lxml.etree.fromstring(xml.encode('utf-8'))
        newdom = transform(dom)
        return lxml.etree.tostring(newdom, pretty_print=True).decode('utf-8')

    def _get_namespace_prefix(self, unsignedxml: str) -> str:
        """ Due to a limitation in the XML signer (SecurityLayer 1.2) the XPath expression for the
            enveloped signature is specified as namespace prefix.
            getNamespacePrefix extracts the prefix to be used in the XPath when calling the signature.
            This functions is using a regular expression.
            YMMV in corner cases, like having different prefixes for the same ns.
        """
        p = re.compile(r'\sxmlns:(\w+)\s*=\s*"urn:oasis:names:tc:SAML:2.0:metadata"')
        m = p.search(unsignedxml)
        return m.group(1)

    def _get_signedxmldoc(self, req: Request) -> Response:
        post_data = req.form['sigresponse']
        # Strip xml root element (CreateXMLSignatureResponse), making disg:Signature the new root:
        # (keeping namespace prefixes + whitespace - otherwise the signature would break. Therefore NOT parsing xml.)
        if re.search(r'<sl:CreateXMLSignatureResponse [^>]*>', post_data):
            r1 = re.sub(r'<sl:CreateXMLSignatureResponse [^>]*>', '', post_data)
            r2 = re.sub(r'</sl:CreateXMLSignatureResponse>', '', r1)
            response = Response(r2)
            response.headers['content-type'] = 'application/xml'
            response.headers['Cache-Control'] = 'no-cache'
            return response
        elif re.search(r'<sl:ErrorCode>', post_data):  # SL error now handled by AJAX client
            post_data_b: bytes = post_data.encode('utf-8')   # seclay should always return UTF-8
            root_tree = lxml.etree.fromstring(post_data_b).getroottree()
            err_code = root_tree.find('//sl:ErrorCode', namespaces={
                'sl': 'http://www.buergerkarte.at/namespaces/securitylayer/1.2#'}).text
            err_msg = root_tree.find('//sl:Info', namespaces={
                'sl': 'http://www.buergerkarte.at/namespaces/securitylayer/1.2#'}).text
            error_json = '{"name": "SecurityLayer %s", "message": "%s"}' % (err_code, err_msg)
            raise SeclayError(error_json)

    # --- WSGI handler ---
    def application(self, environ, start_response):
        req = Request(environ)
        try:
            if req.method == 'POST':
                response = self.do_POST(req)
            elif req.method == 'GET':
                response = self.do_GET(req)
            else:
                response = Response(status='405 HTTP method not supported')
        except NotFound as e:
            #return Response(str(e), status=404)
            response = Response(status='404 ' + str(e))
        except InvalidArgs as e:
            response = Response(status='422 ' + str(e))
        except SeclayError as e:
            response = Response(str(e))
            response.status_code = 200
            response.headers['content-type'] = 'application/json'
            response.headers['Cache-Control'] = 'no-cache'
        except Exception as e:
            response = Response(status='400 ' + str(e))
        return response(environ, start_response)


if __name__ == '__main__':
    if sys.version_info < (3, 6):
        raise "must use python 3.6 or higher"
    try:
        from werkzeug.serving import run_simple
        application = AppHandler().application
        run_simple(cfg.host, cfg.port, application, use_debugger=True, use_reloader=True, )
    except Exception as e:
        print(str(e))
