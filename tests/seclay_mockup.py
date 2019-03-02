import cgi
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import re
import urllib
import config

def main():
    print(f'starting server at {config.sig_service_address[config.HOST]}:{config.sig_service_address[config.PORT]}')
    httpd = HTTPServer(config.sig_service_address, RequestHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        with open('testdata/expected_create_sig_requ.data') as fd:
            text = fd.read().rstrip()
            self.expected_create_sig_requ = '\n'.join(text.splitlines())
        with open('testdata/xmlsig_response.xml') as fd:
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