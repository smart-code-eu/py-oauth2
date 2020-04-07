import traceback

from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant)

import oauth
db = oauth.__DB__

import oauth
from oauth.models import OAuthAuthorizationCode


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def authenticate_user(self, username, password):
        return oauth.__GET_USER__(username, password)

    def save_authorization_code(self, code, request):
        client = request.client
        item = OAuthAuthorizationCode()

        item.code = code
        item.client_id = client.id
        item.redirect_uri = request.redirect_uri
        item.scope = request.scope
        item.user_id = request.user.id

        db.session.add(item)
        db.session.commit()

    def query_authorization_code(self, code, client):
        result = OAuthAuthorizationCode.query.filter_by(code=code, client_id=client.id).first()

        if result is not None:
            return result
        return None

    def delete_authorization_code(self, authorization_code):
        OAuthAuthorizationCode.query.filter_by(id=authorization_code.id).delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user