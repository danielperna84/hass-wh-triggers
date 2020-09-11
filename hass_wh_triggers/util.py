import random
import six
import string


def validate_username(username):
    if not isinstance(username, six.string_types):
        return False

    if len(username) > 32:
        return False

    if not username.isalnum():
        return False

    return True


def validate_display_name(display_name):
    if not isinstance(display_name, six.string_types):
        return False

    if len(display_name) > 65:
        return False

    if not display_name.replace(' ', '').isalnum():
        return False

    return True


def generate_challenge(challenge_len):
    return ''.join([
        random.SystemRandom().choice(string.ascii_letters + string.digits)
        for i in range(challenge_len)
    ])


def generate_ukey():
    '''Its value's id member is required, and contains an identifier
    for the account, specified by the Relying Party. This is not meant
    to be displayed to the user, but is used by the Relying Party to
    control the number of credentials - an authenticator will never
    contain more than one credential for a given Relying Party under
    the same id.

    A unique identifier for the entity. For a relying party entity,
    sets the RP ID. For a user account entity, this will be an
    arbitrary string specified by the relying party.
    '''
    return generate_challenge(20)

class ReverseProxied(object):
    def __init__(self, app, script_name=None, scheme=None, server=None):
        self.app = app
        self.script_name = script_name
        self.scheme = scheme
        self.server = server

    def __call__(self, environ, start_response):
        script_name = environ.get('HTTP_X_SCRIPT_NAME', '') or self.script_name
        if script_name:
            environ['SCRIPT_NAME'] = script_name
            path_info = environ['PATH_INFO']
            if path_info.startswith(script_name):
                environ['PATH_INFO'] = path_info[len(script_name):]
        scheme = environ.get('HTTP_X_SCHEME', '') or self.scheme
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        server = environ.get('HTTP_X_FORWARDED_SERVER', '') or self.server
        if server:
            environ['HTTP_HOST'] = server
        return self.app(environ, start_response)
