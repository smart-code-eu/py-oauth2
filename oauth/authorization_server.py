import json
import random

import flask
from authlib.common.encoding import to_unicode
from authlib.common.security import UNICODE_ASCII_CHARACTER_SET
from authlib.integrations.flask_oauth2 import \
    AuthorizationServer as _AuthorizationServer
from authlib.oauth2.rfc6749 import (
    OAuth2Request,
    ClientAuthentication)
from werkzeug.wrappers import Response

from oauth.bearer_token import BearerToken

GRANT_TYPES_EXPIRES = {
    'authorization_code': 864000,
    'implicit': 3600,
    'password': 864000,
    'client_credentials': 864000
}


def create_oauth_request(request, request_cls):
    if isinstance(request, request_cls):
        return request

    if not request:
        request = flask.request

    if request.method == 'POST':
        body = request.form.to_dict(flat=True)
    else:
        body = None

    # query string in werkzeug Request.url is very weird
    # scope=profile%20email will be scope=profile email
    url = request.base_url
    if request.query_string:
        url = url + '?' + to_unicode(request.query_string)
    return request_cls(request.method, url, body, request.headers)


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = random.SystemRandom()
    return ''.join(rand.choice(chars) for _ in range(length))


class AuthorizationServer(_AuthorizationServer):
    def __init__(self, access_token_generator, refresh_token_generator, app,
                 query_client=None, save_token=None, **config):
        self.access_token_generator = access_token_generator
        self.refresh_token_generator = refresh_token_generator

        super(AuthorizationServer, self).__init__(
            app, query_client, save_token, **config)
        self.authenticate_client = ClientAuthentication(
            query_client=query_client)
        self.generate_token = self.generate_tokenn()

    def generate_tokenn(self):
        def access_token_generatorr(*args, **kwargs):
            return self.access_token_generator(*args, **kwargs)

        def refresh_token_generator(*args, **kwargs):
            return self.refresh_token_generator(*args, **kwargs)

        expires_generator = self.create_token_expires_in_generator(None)
        return BearerToken(
            access_token_generatorr,
            refresh_token_generator,
            expires_generator
        )

    def create_token_expires_in_generator(self, config):
        expires_conf = {}
        expires_conf.update(GRANT_TYPES_EXPIRES)

        def expires_in(client, grant_type):
            return expires_conf.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)

        return expires_in

    def create_oauth2_request(self, request):
        return create_oauth_request(request, OAuth2Request)

    def handle_response(self, status, payload, headers):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        return Response(payload, status=status, headers=headers)
