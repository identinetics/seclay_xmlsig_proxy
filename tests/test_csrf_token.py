import pytest
from csrf_token import CsrfToken


def test_OK():
    t = CsrfToken.create_token('user273')
    CsrfToken.validate_token(t, 'user273')
    pass


def test_invalid_secret():
    t = CsrfToken.create_broken_token_invalid_secret('user273')
    with pytest.raises(ValueError, match=r'.*decrypted secret does not match.*'):
        CsrfToken.validate_token(t, 'user273')


def test_expired():
    t = CsrfToken.create_expired_token('user273')
    with pytest.raises(ValueError, match=r'.*CSRF token expired.*'):
        CsrfToken.validate_token(t, 'user273')


def test_stolen_token():
    t = CsrfToken.create_token('user273')
    with pytest.raises(ValueError, match=r'.*userid does not match.*'):
        CsrfToken.validate_token(t, 'malroy')



