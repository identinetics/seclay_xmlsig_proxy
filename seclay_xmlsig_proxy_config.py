import logging
import os
from pathlib import Path
from urllib.parse import urlencode
# addresses hard coded in sig_proxy.js

# Signature Service (Security Layer) address: https/3496 preferred, but requires client certificate installation
class SigServiceConfig:
    host = '127.0.0.1'
    if 'SECLAYPORT' in os.environ:
        port = int(os.environ['SECLAYPORT'])
    else:
        port = 3495
    scheme = 'http' if port == 3495 else 'https'
    url = '{}://{}:{}/http-security-layer-request'.format(scheme, host, port)

class SigProxyConfig:
    # Start this service at host/port:
    host = 'localhost'  # address (and non-default port) must be whitelisted in the external webapp's Access-Control-Allow-Origin
    port = 8001
    # External origin as seen by the browser
    ext_origin = 'http://localhost:8080'    # using the external proxy address
    userid_http_header = 'REMOTE_USER'
    #
    # each url parameter containing a url must left-match allowed_urls ('*' to match any):
    allowed_urls = ['http://localhost:8080', ]
    # CSRFSECRET and CSRFENCRYPTKEY must be 24 char cryptographic random ascii strings (`openssl rand -base64 16`)
    csrf_secret: bytes = os.environ['CSRFSECRET'].encode('ascii')
    csrf_encrypt_key: bytes = os.environ['CSRFENCRYPTKEY'].encode('ascii')
    csrf_token_maxage: int = 3600 * 8  # seconds

    # DO NOT CHANGE below for deployment
    rootpath = '/SigProxy'
    loadsigproxyclient_path = f'{rootpath}/loadsigproxyclient'
    make_cresigrequ_url = f'{rootpath}/makecresigrequ'
    getsignedxmldoc_url = f'{rootpath}/getsignedxmldoc'
    getmycsrftoken_path = f'{rootpath}/getmycsrftoken'

    sig_proxy_html_template = Path(__file__).parent / 'sig_proxy_client.html'
    sig_proxy_js_template = Path(__file__).parent / 'sig_proxy_client.js.template'
    SIGTYPE_ENVELOPING = 'enveloping'
    SIGTYPE_SAMLED = 'samled'  # enveloped + implicit signature position
    SIGTYPE_ENVELOPED = 'enveloped'
    SIGTYPE_VALUES = (SIGTYPE_ENVELOPING, SIGTYPE_SAMLED, )
    mandatoryparamtypes = {'result_to': 'url', 'return': 'url', 'sigtype': 'str', 'unsignedxml_url': 'url', }
    tidy_samlentityescriptor_xslt = str(Path(__file__).parent / 'tidy_samled.xslt')
    siglog_path = Path(__file__).parent / 'work/siglog/'
    # set to WARNING for production
    logging.getLogger().setLevel(logging.DEBUG)


# Debug helper
# mitmweb --listen-port 8080 --mode reverse:http://127.0.0.1:18080 --listen-host 127.0.0.1 --web-port 8081
# mitmweb --listen-port 13495 --mode reverse:http://127.0.0.1:3495 --listen-host 127.0.0.1 --web-port 8082