from pathlib import Path
from urllib.parse import urlencode
# addresses hard coded in sig_proxy.js

class SigProxyConfig:
    host = 'localhost'
    port = 8080
    rootpath = '/SigProxy'
    loadsigproxyclient_path = f'{rootpath}/loadsigproxyclient'
    make_cresigrequ_path = f'{rootpath}/makecresigrequ'
    getsignedxmldoc_path = f'{rootpath}/getsignedxmldoc'
    sig_proxy_js_template = Path(__file__).parent / 'sig_proxy.js.template'
    SIGTYPE_ENVELOPING = 'enveloping'
    SIGTYPE_SAMLED = 'samled'  # enveloped + implicit signature position
    SIGTYPE_ENVELOPED = 'enveloped'
    SIGTYPE_VALUES = (SIGTYPE_ENVELOPING, SIGTYPE_SAMLED, )
    rooturl = f"http://{host}:{port}"


# Signature Service (Security Layer) address
class SigServiceConfig:
    host = 'localhost'
    port = 3495
    url = 'http://{}:{}/http-security-layer-request'.format(host, port)


# Debug helper
# mitmweb --listen-port 8080 --mode reverse:http://127.0.0.1:18080 --listen-host 127.0.0.1 --web-port 8081
# mitmweb --listen-port 13495 --mode reverse:http://127.0.0.1:3495 --listen-host 127.0.0.1 --web-port 8082