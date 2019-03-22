""" Demonstrate Werkzeug HTTP server component
    Run a simple server with basic input validation and error handling
"""
import json
import logging
import os
import string
import sys
import unicodedata
# import enforce
import gunicorn.app.base
from werkzeug.wrappers import Request, Response
from werkzeug.exceptions import BadRequest, MethodNotAllowed, NotFound

# enforce.config({'enabled': True, 'mode': 'covariant'})


class InvalidArgs(Exception):
    pass


class MissingCsrfToken(Exception):
    pass


# @enforce.runtime_validation
class AppHandler:
    mandatoryparamtypes = {'arg1': 'url', }
    allowed_url_origin = 'http://localhost:8089'

    # --- GET handler ---
    def do_GET(self, req: Request) -> Response:
        if req.path == '/gettest':
            return self._get_response(req)
        else:
            raise NotFound

    def _get_response(self, req: Request) -> Response:
        urlparams_sane = AppHandler._sanitize(dict(req.args))
        response = Response(f'<html><body>{json.dumps(urlparams_sane)}</body></html>')
        response.headers['content-type'] = 'text/html'
        response.headers['Cache-Control'] = 'no-cache'
        return response

    @staticmethod
    def _sanitize(urlparams: dict) -> dict:
        mandatoryparams = set(AppHandler.mandatoryparamtypes.keys())
        if len(set(mandatoryparams).difference(urlparams.keys())) > 0:
            raise InvalidArgs(f"URL parameters must be these: {mandatoryparams}.")
        if not urlparams['arg1'].startswith(AppHandler.allowed_url_origin):
            raise InvalidArgs('arg1 value must be a whitelisted host and port')
        urlparams_sane = {}
        valid_chars = "-_.:+/%s%s" % (string.ascii_letters, string.digits)  # restrictive charset
        for k, v1 in urlparams.items():
            v2 = unicodedata.normalize('NFKD', v1)
            v3 = v2.encode('ascii', 'ignore').decode('ascii')
            v4 = ''.join(c for c in v3 if c in valid_chars)
            urlparams_sane[k] = v4
        return urlparams_sane

    # --- POST handler ---
    def do_POST(self, req: Request) -> Response:
        self._validate_csrf(req)
        if req.path == '/posttest':
            return self._handle_postform(req)
        else:
            raise NotFound

    def _validate_csrf(self, req):
        try:
            req.form['csrftoken4proxy'] == 'fake_random_value'
        except KeyError:
            raise MissingCsrfToken('Missing CSRF token in POST request')
        except ValueError as e:
            raise e

    def _handle_postform(self, req: Request) -> Response:
        arg1 = req.args[b'arg1'][0].decode('utf-8') if b'arg1' in req.args else 'default'
        if b'arg2' in req.args:
            arg2 = req.args[b'arg2'][0].decode('utf-8')
        else:
            raise InvalidArgs
        response = Response(f'<html><body><p>arg1: {arg1}</p><p>arg2: {arg2}</p></body></html>')
        response.headers['content-type'] = 'application/xml'
        response.headers['Cache-Control'] = 'no-cache'
        return response


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
        except BadRequest as e:
            return e
        except InvalidArgs as e:
            response = Response(status='422 ' + str(e))
        except MissingCsrfToken as e:
            response = Response(status='400 ' + str(e))
        except NotFound as e:
            response = Response(status='404 ' + str(e))
        except Exception as e:
            response = Response(status='500 ' + str(e))
        logging.info('  status: {} {}'.format(response.status_code, response.status))
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
            'bind': '{}:{}'.format('localhost', 8089),
            'workers': number_of_workers(),
            'timeout': 18000,
        }
        StandaloneApplication(application, options).run()
    except Exception as e:
        print(str(e))

