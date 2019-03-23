import requests
from pathlib import Path
import urllib
import pytest
from seclay_xmlsig_proxy_config import SigProxyConfig as Cfg
from tests.config_extwebapp import ExtWebappConfig



@pytest.fixture(scope='module')
def csrf_token():
    url = ExtWebappConfig.getmycsrftoken_url()
    response = requests.get(url, headers={'Cfg.userid_http_header': 'user273'})
    return response.text


def test_loadsigproxyclient():
    url = ExtWebappConfig.load_sigproxy_url()
    response = requests.get(url, headers={'Cfg.userid_http_header': 'user273'})
    assert response.status_code == 200
    expected_result_path = Path('testdata/expected_sig_client.html')
    assert response.text.startswith(expected_result_path.read_text())


def test_loadsigproxyclient_parameter_value_not_allowed():
    url = ExtWebappConfig.load_sigproxy_url().replace('=http', '=https')
    response = requests.get(url)
    assert response.status_code == 422


def test_make_cresigrequ_missing_csrf_token():
    url = Cfg.ext_origin + Cfg.make_cresigrequ_url
    unsignedxml_path = Path('testdata/unsigned_data.xml')
    postdata = {'unsignedxml': unsignedxml_path.read_text()}
    try:
        response = requests.post(url, data=postdata, headers={'Cfg.userid_http_header': 'user273'})
    except Exception as e:
        raise e
    assert response.status_code == 400


def test_make_cresigrequ(csrf_token):
    url = Cfg.ext_origin + Cfg.make_cresigrequ_url
    unsignedxml_path = Path('testdata/unsigned_data.xml')
    postdata = {'unsignedxml': unsignedxml_path.read_text(),
                'csrftoken4proxy': csrf_token}
    response = requests.post(url, data=postdata, headers={'Cfg.userid_http_header': 'user273'})
    assert response.status_code == 200
    expected_result_path = Path('testdata/expected_create_sig_requ.xml')
    assert urllib.parse.unquote_plus(response.text) == expected_result_path.read_text()


# def test_get_signedxmldoc():
#     url = Cfg.ext_origin + Cfg.getsignedxmldoc_url
#     createxmlsigresp_path = Path('testdata/createxmlsignature_response.xml')
#     postdata = {'sigresponse': createxmlsigresp_path.read_text()}
#     response = requests.post(url, data=postdata, headers={'Cfg.userid_http_header': 'user273'})
#     assert response.status_code == 200
#     expected_result_path = Path('testdata/expected_signed_result.xml')
#     assert response.text == expected_result_path.read_text()
#
#
# def test_tidy_saml_entitydescriptor():
#     xml_path = (Path('testdata/81_signed_validuntil.xml'))
#     expected_result_path = (Path('testdata/81_tidied_result.xml'))
#     try:
#         tidy_xml = AppHandler._tidy_saml_entitydescriptor(xml_path.read_text())
#     except Exception as e:
#         raise e
#     else:
#         assert tidy_xml == expected_result_path.read_text()
