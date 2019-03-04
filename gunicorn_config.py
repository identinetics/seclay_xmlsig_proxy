from config import SigProxyConfig as cfg

# Parameter description: see https://github.com/benoitc/gunicorn/blob/master/examples/example_config.py

bind = cfg.host + ':' + str(cfg.port)
accesslog = '-'
errorlog = '-'
loglevel = 'info'
# access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
# pidfile = '/tmp/hello-http-tcp.pid'
# daemon = True
# workers = 4
# worker_class = 'sync'
# worker_connections = 1000
# timeout = 30
# keepalive = 2
# threads = 2
# umask = 0
# user = None
# group = None
