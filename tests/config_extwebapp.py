from pathlib import Path
from urllib.parse import urlencode
import config

# mock-up for unit testing
class ExtWebappConfig:
    host = 'localhost'
    port = 8090
    initial_path = r'/?$'
    unsignedxml_path = '/getunsignedxml'
    returnsignedxml_path = '/postsignedxml'
    returnto_path = '/showresult'
    test_unsignedxml = Path(__file__).parent / 'testdata' / 'unsigned_data.xml'
    test_expexted_signedxml = Path(__file__).parent / 'testdata' / 'xmlsig_response.xml'

    @staticmethod
    def load_sigproxy_url(sigtype = config.SigProxyConfig.SIGTYPE_SAMLED) -> str:
        ''' return prepared Reqeust to invoke the signature proxy service '''
        c_prx = config.SigProxyConfig
        baseurl = f'http://{c_prx.host}:{c_prx.port}{c_prx.loadsigproxyclient_path}'
        request_params = {
            'unsignedxml_url': ExtWebappConfig.unsignedxml_path,
            'result_to': ExtWebappConfig.returnsignedxml_path,
            'return': ExtWebappConfig.returnto_path,
            'sigtype': sigtype,
        }
        return baseurl + '/?' + urlencode(request_params)
