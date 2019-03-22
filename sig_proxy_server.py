import logging
import os
import re
import string
import sys
import unicodedata
import urllib
import enforce
import gunicorn.app.base
import lxml.etree
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import BadRequest, NotFound
import seclay_xmlsig_proxy_config
from seclay_xmlsig_proxy_config import SigProxyConfig as Cfg
from csrf_token import CsrfToken
from get_seclay_request import get_seclay_request

enforce.config({'enabled': True, 'mode': 'covariant'})


class InvalidArgs(Exception):
    pass


class InvalidPath(Exception):
    pass


class MissingCsrfToken(Exception):
    pass


class SeclayError(Exception):
    """ Error reported in response content with HTTP code 200 """
    pass


# @enforce.runtime_validation
class AppHandler:
    # --- GET handler ---
    def do_GET(self, req: Request) -> Response:
        AppHandler.require_remote_user(req)
        if req.path.startswith(Cfg.loadsigproxyclient_path):
            return self._loadsigproxyclient(req)
        elif req.path == Cfg.getmycsrftoken_path:  # for unit test
                csrf_token = CsrfToken.create_token(req.headers['REMOTE_USER'])
                response = Response(csrf_token)
                response.headers['content-type'] = 'text/plain'
                response.headers['Cache-Control'] = 'no-cache'
                return response
        else:
            raise NotFound

    @staticmethod
    def require_remote_user(req):
        if not 'REMOTE_USER' in req.headers:
            raise InvalidArgs('missing HTTP request header "REMOTE_USER"')

    def _loadsigproxyclient(self, req: Request) -> Response:
        sigproxyclient_html = self._render_sigproxyclient_html(req)
        response = Response(sigproxyclient_html)
        response.headers['content-type'] = 'text/html'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    def _render_sigproxyclient_html(self, req: Request) -> str:
        sigproxyclient_js = self._render_sigproxyclient_js(req)
        with Cfg.sig_proxy_html_template.open('r') as fd:
            html_template = string.Template(fd.read())
        html = html_template.substitute({'javascript': sigproxyclient_js})
        return html

    def _render_sigproxyclient_js(self, req: Request) -> str:
        urlparams_sane = AppHandler._sanitize(dict(req.args))
        js_params = {
            'getsignedxmldoc_url': Cfg.ext_origin + Cfg.getsignedxmldoc_url,
            'make_cresigrequ_url': Cfg.ext_origin + Cfg.make_cresigrequ_url,
            'sigservice_url': seclay_xmlsig_proxy_config.SigServiceConfig.url,
            'csrftoken4proxy': CsrfToken.create_token(req.headers['REMOTE_USER']),
            **urlparams_sane,
        }
        with Cfg.sig_proxy_js_template.open('r') as fd:
            js_template = string.Template(fd.read())
        js = js_template.substitute(js_params)
        return js

    @staticmethod
    def _sanitize(urlparams: dict) -> dict:
        mandatoryparams = set(Cfg.mandatoryparamtypes.keys())
        if 'sigtype' not in urlparams:
            urlparams['sigtype'] = Cfg.SIGTYPE_SAMLED
        if len(set(mandatoryparams).difference(urlparams.keys())) > 0:
            raise InvalidArgs(f"URL parameters must be these: {mandatoryparams}."
                              f" {set(urlparams.keys()).difference(mandatoryparams)}?")
        if urlparams['sigtype'] not in Cfg.SIGTYPE_VALUES:
            raise InvalidArgs(f"URL parameters must be on of: {Cfg.SIGTYPE_VALUES}")
        urlparams_sane = {}
        valid_chars = "-_.:+/%s%s" % (string.ascii_letters, string.digits)   # restrictive charset
        for k, v1 in urlparams.items():
            if Cfg.mandatoryparamtypes[k] == 'url' and not AppHandler.is_allowed_host(k, v1):
                raise InvalidArgs(f"URL parameter {k} is not an allowed_host: {v1}")
            v2 = unicodedata.normalize('NFKD', v1)
            v3 = v2.encode('ascii', 'ignore').decode('ascii')
            v4 = ''.join(c for c in v3 if c in valid_chars)
            urlparams_sane[k] = v4
        return urlparams_sane

    @staticmethod
    def is_allowed_host(param_name, param_value) -> bool:
        if Cfg.mandatoryparamtypes[param_name] != 'url':
            return True
        for url in Cfg.allowed_urls:
            if param_value.startswith(url) or url == '*':
                return True
        return False

    # --- POST handler ---
    def do_POST(self, req: Request) -> Response:
        AppHandler._validate_csrf(req)
        if req.path == Cfg.make_cresigrequ_url:
            return self._make_cresigrequ(req)
        elif req.path == Cfg.getsignedxmldoc_url:
            return self._get_signedxmldoc(req)
        else:
            raise NotFound

    @staticmethod
    def _validate_csrf(req):
        try:
            CsrfToken.validate_token(req.form['csrftoken4proxy'], req.headers['REMOTE_USER'])
        except KeyError:
            raise MissingCsrfToken('Missing CSRF token in POST request')
        except ValueError as e:
            raise e

    def _make_cresigrequ(self, req: Request) -> Response:
        sigtype = req.args[b'sigtype'][0].decode('utf-8') if b'sigtype' in req.args else Cfg.SIGTYPE_SAMLED
        unsignedxml = req.form['unsignedxml']
        # unsignedxml = urllib.parse.unquote(unsignedxml_qt)
        create_xml_signature_request = self._get_CreateXMLSignatureRequest(sigtype, unsignedxml)
        response = Response(urllib.parse.quote_plus(create_xml_signature_request))
        response.headers['content-type'] = 'application/xml'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    def _get_CreateXMLSignatureRequest(self, sigtype: str, unsignedxml: str) -> str:
        if sigtype == Cfg.SIGTYPE_ENVELOPING:
            xml = get_seclay_request(Cfg.SIGTYPE_ENVELOPING, unsignedxml)
            return xml
        elif sigtype == Cfg.SIGTYPE_SAMLED:
            unsignedxml_tidy = AppHandler._tidy_saml_entitydescriptor(unsignedxml)
            ns_prefix = self._get_namespace_prefix(unsignedxml_tidy)
            sigpos = f"/{ns_prefix}:EntityDescriptor"
            xml = get_seclay_request(Cfg.SIGTYPE_ENVELOPED, unsignedxml_tidy, sigPosition=sigpos)
            return xml
        else:
            raise InvalidArgs('sigtype argument value must be in ' + ', '.join(Cfg.SIGTYPE_VALUES))

    @staticmethod
    def _tidy_saml_entitydescriptor(xml: str) -> str:
        xslt_filename = Cfg.tidy_samlentityescriptor_xslt
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

    def _save_cresigresponse_for_debug(self, xml: str) -> None:
        if getattr(Cfg, 'siglog_path', False):
            try:
                Cfg.siglog_path.mkdir(parents=True, exist_ok=True)
            except FileExistsError as e:
                pass
            fp = Cfg.siglog_path / 'createxmlsigresponse.xml'
            with fp.open('w') as fd:
                fd.write(xml)
                logging.debug('saved CreateXMLSignatureResponse in ' + str(fp))

    def _save_signedxmldoc_for_debug(self, xml: bytes) -> None:
        if getattr(Cfg, 'siglog_path', False):
            fp = Cfg.siglog_path / 'signedxml.xml'
            with (fp).open('wb') as fd:
                fd.write(xml)
                logging.debug('saved CreateXMLSignatureResponse in ' + str(fp))

    def _get_signedxmldoc(self, req: Request) -> Response:
        post_data = req.form['sigresponse']
        self._save_cresigresponse_for_debug(post_data)
        # Strip xml root element (CreateXMLSignatureResponse), making disg:Signature the new root:
        # (keeping namespace prefixes + whitespace - otherwise the signature would break. Therefore NOT parsing xml.)
        if re.search(r'<sl:CreateXMLSignatureResponse [^>]*>', post_data):
            r1 = re.sub(r'<sl:CreateXMLSignatureResponse [^>]*>', '', post_data)
            r2 = re.sub(r'</sl:CreateXMLSignatureResponse>', '', r1)
            response = Response(r2)
            response.headers['content-type'] = 'application/xml'
            response.headers['Cache-Control'] = 'no-cache'
            self._save_signedxmldoc_for_debug(response.data)
            return response
        elif re.search(r'<sl:ErrorCode>', post_data):  # SL error now handled by AJAX client
            self._save_signedxmldoc_for_debug(post_data)
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
        logging.info(req.method + ' ' + req.path)
        try:
            if req.method == 'POST':
                response = self.do_POST(req)
            elif req.method == 'GET':
                response = self.do_GET(req)
            else:
                response = Response(status='405 only GET and POST allowed')
                logging.error('  status: {}'.format(response.status))
        except BadRequest as e:
            logging.error('  405: ' + str(e))
            raise e
        except InvalidArgs as e:
            response = Response(status='422 ' + str(e))
            logging.error('  status: {}'.format(response.status))
        except MissingCsrfToken as e:
            response = Response(status='400 ' + str(e))
            logging.error('  status: {}'.format(response.status))
        except NotFound as e:
            response = Response(status='404 ' + str(e))
            logging.info('  status: {}'.format(response.status))
        except Exception as e:
            response = Response(status='500 ' + str(e))
            logging.error('  status: {}'.format(response.status))
        else:
            logging.info('  status: {}'.format(response.status))
        return response(environ, start_response)


class StandaloneApplication(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super(StandaloneApplication, self).__init__()

    def load_config(self):
        config = dict([(key, value) for key, value in self.options.items()
                       if key in self.cfg.settings and value is not None])
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def number_of_workers():
    if 'DEBUG' in os.environ:
        return 1
    else:
        import multiprocessing
        return (multiprocessing.cpu_count() * 2) + 1


def get_application():
    return AppHandler().application


if __name__ == '__main__':
    if sys.version_info < (3, 6):
        raise Exception("must use python 3.6 or higher")
    try:
        application = AppHandler().application
        options = {
            'bind': '{}:{}'.format(Cfg.host, Cfg.port),
            'workers': number_of_workers(),
            'timeout': 18000,
        }
        StandaloneApplication(application, options).run()
    except Exception as e:
        print(str(e))

