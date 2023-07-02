import hmac
import hashlib
from time import time

from urllib.parse import urljoin
from urllib.parse import unquote_plus
from django.utils.encoding import force_bytes
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse

from wordpress_auth import (WORDPRESS_LOGGED_IN_KEY, WORDPRESS_LOGGED_IN_SALT,
                            WORDPRESS_COOKIEHASH)
from wordpress_auth.models import WpOptions, WpUsers

def get_site_url():
    url = WpOptions.objects.using('wordpress') \
        .get(option_name='siteurl').option_value
    return url if url.endswith('/') else url + '/'


def get_login_url():
    return urljoin(get_site_url(), 'wp-login.php')

def get_logout_url():
    return urljoin(get_site_url(), 'wp-login.php?action=logout')

def get_wordpress_user(request):
    if WORDPRESS_COOKIEHASH is None:
        cookie_hash = hashlib.md5(force_bytes(get_site_url()[:-1])).hexdigest()
    else:
        cookie_hash = WORDPRESS_COOKIEHASH

    cookie_name = 'wordpress_logged_in_' + cookie_hash
    cookie = request.COOKIES.get(cookie_name)
    if cookie:
        cookie = unquote_plus(cookie)
        cookie_list = _parse_auth_cookie(cookie)
        if cookie_list:
            return _validate_auth_cookie(cookie_list)
    return False

def wordpress_context_processor(request):
    return {
        'WORDPRESS_SITE_URL': get_site_url(),
        'WORDPRESS_LOGIN_URL': get_login_url(),
        'WORDPRESS_USER': request.wordpress_user,
    }


def _parse_auth_cookie(cookie):
    elements = cookie.split('|')
    return elements if len(elements) == 4 else None


def _validate_auth_cookie(cookie_list):
    username, expiration, token, cookie_hmac = cookie_list

    # Quick check to see if an honest cookie has expired
    if float(expiration) < time():
        return False

    # Check if a bad username was entered in the user authentication process
    try:
        user = WpUsers.objects.using('wordpress').get(login=username)
    except WpUsers.DoesNotExist:
        return False

    # Check if a bad authentication cookie hash was encountered
    pwd_frag = user.password[8:12]
    key_salt = WORDPRESS_LOGGED_IN_KEY + WORDPRESS_LOGGED_IN_SALT
    key_msg = '{}|{}|{}|{}'.format(username, pwd_frag, expiration, token)
    key = hmac.new(force_bytes(key_salt), force_bytes(key_msg),
        digestmod=hashlib.md5).hexdigest()

    hash_msg = '{}|{}|{}'.format(username, expiration, token)
    hash = hmac.new(force_bytes(key), force_bytes(hash_msg),
        digestmod=hashlib.sha256).hexdigest()

    if hash != cookie_hmac:
        return False

    # *sigh* we're almost there
    # Check if the token is valid for the given user
    verifier = hashlib.sha256(force_bytes(token)).hexdigest()

    if verifier not in user.get_session_tokens():
        return False

    return user

class WPLoginRequiredMixin(LoginRequiredMixin):
    """Verify that the current user is authenticated."""
    def dispatch(self, request, *args, **kwargs):
        if not request.wordpress_user:            
            return reverse('login')
        return super().dispatch(request, *args, **kwargs)