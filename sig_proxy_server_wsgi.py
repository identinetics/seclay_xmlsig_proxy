"""
WSGI config to expose the WSGI callable as a module-level variable named ``application``.
"""

from sig_proxy_server import AppHandler

application = AppHandler().application

