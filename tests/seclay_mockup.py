import cgi
import logging
import re
import urllib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import config

def main():
    (host, port) = (config.SigServiceConfig.host, config.SigServiceConfig.port)
    print(f'starting server at {host}:{port}')
    httpd = HTTPServer((host, port), RequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        with (Path(__file__).parent / 'testdata/expected_create_sig_requ.xml').open() as fd:
            text = fd.read().rstrip()
            self.expected_create_sig_requ = '\n'.join(text.splitlines())
        with (Path(__file__).parent / 'testdata/createxmlsignature_response.xml').open() as fd:
            self.xml_signed = fd.read()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        logging.info(f"GET request not supported for this service")
        self.send_response(400)
        self.end_headers()

    def do_POST(self):
        post_vars = self.parse_postvars()
        xmlrequest = post_vars[b'XMLRequest'][0]
        xmlrequest_lines = re.split(r'\r\n', xmlrequest.decode('utf-8').rstrip())
        xmlrequest_normalized_lineending = '\n'.join(xmlrequest_lines)
        if self.expected_create_sig_requ != xmlrequest_normalized_lineending:
            logging.error("CreateSignedXMLRequest not matching expected data")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(self.xml_signed.encode('utf-8'))

    def parse_postvars(self) -> dict:
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
    main()