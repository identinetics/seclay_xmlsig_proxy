from pathlib import Path
import requests

origin = 'http://localhost:8089'

def test_invalid_method():
    url = origin + '/'
    response = requests.request(method='HEAD', url=url)
    assert response.status_code == 405


def test_get_invalid_path():
    url = origin + '/invalidpath'
    response = requests.get(url)
    assert response.status_code == 404


def test_get_missing_mandatory_arg():
    url = origin + '/gettest'
    response = requests.get(url)
    assert response.status_code == 422


def test_get_with_invalid_arg1_value():
    url = origin + '/gettest?arg1=http://spoofedhost'
    response = requests.get(url)
    assert response.status_code == 422


def test_get_with_xss_arg():
    url = origin + '/gettest?arg1=http://localhost:8089&arg2=<SCRIPT>alert(“Cookie”+document.cookie)</SCRIPT>'
    response = requests.get(url)
    assert response.status_code == 200
    assert response.text == '<html><body>{"arg1": "http://localhost:8089", "arg2": "SCRIPTalertCookiedocument.cookie/SCRIPT"}</body></html>'


def test_get_OK():
    url = origin + '/gettest?arg1=http://localhost:8089&arg2=blah'
    response = requests.get(url)
    assert response.status_code == 200
    assert response.text == '<html><body>{"arg1": "http://localhost:8089", "arg2": "blah"}</body></html>'


