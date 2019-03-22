from pathlib import Path
from urllib.parse import urlencode
from seclay_xmlsig_proxy_config import SigProxyConfig as Cfg

# mock-up for unit testing
class ExtWebappConfig:
    host = 'localhost'
    port = 8000
    initial_path = r'/?$'
    unsignedxml_path = '/sigproxyapi/getunsignedxml'
    returnsignedxml_path = '/sigproxyapi/postsignedxml'
    returnto_path = '/showresult'
    ext_origin = "http://localhost:8080"  # using the external proxy address
    test_unsignedxml = Path(__file__).parent / 'testdata' / 'unsigned_data.xml'
    test_expected_signedxml = Path(__file__).parent / 'testdata' / 'expected_signed_result.xml'

    @staticmethod
    def load_sigproxy_url(sigtype = Cfg.SIGTYPE_SAMLED) -> str:
        ''' return prepared Reqeust to invoke the signature proxy service '''
        c_prx = Cfg
        c_ext = ExtWebappConfig
        baseurl = f"{ExtWebappConfig.ext_origin}{c_prx.loadsigproxyclient_path}"
        request_params = {
            'unsignedxml_url': c_ext.ext_origin + c_ext.unsignedxml_path,
            'result_to': c_ext.ext_origin + c_ext.returnsignedxml_path,
            'return': c_ext.ext_origin + c_ext.returnto_path,
            'sigtype': sigtype,
        }
        return baseurl + '/?' + urlencode(request_params)


    @staticmethod
    def getmycsrftoken_url() -> str:
        url = Cfg.ext_origin + Cfg.getmycsrftoken_path
        return url


