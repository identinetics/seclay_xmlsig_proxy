from pathlib import Path
import requests
import pytest
from config import SigProxyConfig as cfg
from tests.config_extwebapp import ExtWebappConfig


def test_loadsigproxyclient():
    url = ExtWebappConfig.load_sigproxy_url()
    response = requests.get(url)
    assert response.status_code == 200
    expected_result_path = Path('testdata/expected_sig_client.html')
    assert response.text.startswith(expected_result_path.read_text())


def test_loadsigproxyclient_parameter_value_not_allowed():
    url = ExtWebappConfig.load_sigproxy_url().replace('=http', '=https')
    response = requests.get(url)
    assert response.status_code == 422


def test_make_cresigrequ():
    url = cfg.rooturl + cfg.make_cresigrequ_path
    unsignedxml_path = Path('testdata/unsigned_data.xml')
    postdata = {'unsignedxml': unsignedxml_path.read_text()}
    response = requests.post(url, data=postdata)
    assert response.status_code == 200
    expected_result_path = Path('testdata/expected_create_sig_requ.xml')
    assert response.text == expected_result_path.read_text()


def test_get_signedxmldoc():
    url = cfg.rooturl + cfg.getsignedxmldoc_path
    createxmlsigresp_path = Path('testdata/createxmlsignature_response.xml')
    postdata = {'sigresponse': createxmlsigresp_path.read_text()}
    response = requests.post(url, data=postdata)
    assert response.status_code == 200
    expected_result_path = Path('testdata/expected_signed_result.xml')
    assert response.text == expected_result_path.read_text()

