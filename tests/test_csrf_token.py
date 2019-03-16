import pytest
from csrf_token import CsrfToken


def test_OK():
    t = CsrfToken.create_token()
    CsrfToken.validate_token(t)
    pass


def test_invalid_secret():
    t = CsrfToken.create_broken_token_invalid_secret()
    with pytest.raises(ValueError, match=r'.*decrypted secret did not match.*'):
        CsrfToken.validate_token(t)


def test_expired():
    t = CsrfToken.create_expired_token()
    with pytest.raises(ValueError, match=r'.*CSRF token expired.*'):
        CsrfToken.validate_token(t)
