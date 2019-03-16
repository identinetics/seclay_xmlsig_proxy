"""
1. Create an encrypted CSRF token comprising a configured secret, a nonce and a timestamp.
2. Verify that the secret was correctly established and the age is less than a given value
"""

import base64
import logging
import pickle
from datetime import datetime, timedelta
import enforce
enforce.config({'enabled': True, 'mode': 'covariant'})
from Crypto.Cipher import AES
from config import SigProxyConfig


#@enforce.runtime_validation
class CsrfToken:

    @staticmethod
    def create_token() -> str:
        cipher = AES.new(SigProxyConfig.csrf_encrypt_key, AES.MODE_EAX)
        timestamp: bytes = pickle.dumps(datetime.now())
        token_plain: bytes = SigProxyConfig.csrf_secret + b'|' + timestamp
        (ciphertext, tag) = cipher.encrypt_and_digest(token_plain)
        token_encrypt_pickled: bytes = pickle.dumps([cipher.nonce, tag, ciphertext])
        # base32 avoids urlencoding issues with + and blank:
        csrf_token: str = base64.b32encode(token_encrypt_pickled).decode('ascii')
        logging.debug('create_token: ' + csrf_token)
        return csrf_token

    @staticmethod
    def validate_token(csrf_token: str) -> None:
        logging.debug('validate_token: ' + csrf_token)
        token_encrypt_pickled = base64.b32decode(csrf_token)
        try:
            (nonce, tag, ciphertext) = pickle.loads(token_encrypt_pickled)
        except ValueError as e:
            raise e
        cipher = AES.new(SigProxyConfig.csrf_encrypt_key, AES.MODE_EAX, nonce)
        token_plain = cipher.decrypt_and_verify(ciphertext, tag)
        (csrf_secret, create_time_serialized) = token_plain.split(b'|')
        if csrf_secret != SigProxyConfig.csrf_secret:
            raise ValueError('Invalid CSRF token - decrypted secret did not match')
        create_time = pickle.loads(create_time_serialized)
        difference = (datetime.now() - create_time).total_seconds()
        if difference > SigProxyConfig.csrf_token_maxage:
            raise ValueError('CSRF token expired')

    @staticmethod
    def create_broken_token_invalid_secret() -> str:
        cipher = AES.new(SigProxyConfig.csrf_encrypt_key, AES.MODE_EAX)
        timestamp: bytes = pickle.dumps(datetime.now())
        token_plain: bytes = b'1234567890abcdef01234567' + b'|' + timestamp
        ciphertext, tag = cipher.encrypt_and_digest(token_plain)
        token_encrypt_pickled: bytes = pickle.dumps([cipher.nonce, tag, ciphertext])
        csrf_token: str = base64.b32encode(token_encrypt_pickled).decode('ascii')
        return csrf_token

    @staticmethod
    def create_expired_token() -> str:
        # create token from last year
        cipher = AES.new(SigProxyConfig.csrf_encrypt_key, AES.MODE_EAX)
        timestamp: bytes = pickle.dumps((datetime.now()) - timedelta(365))
        token: bytes = SigProxyConfig.csrf_secret + b'|' + timestamp
        ciphertext, tag = cipher.encrypt_and_digest(token)
        token_encrypt_pickled: bytes = pickle.dumps([cipher.nonce, tag, ciphertext])
        csrf_token: str = base64.b32encode(token_encrypt_pickled).decode('ascii')
        return csrf_token
