from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant)

import oauth
from oauth.models import OAuthAuthorizationCode

db = oauth.__DB__


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        client = request.client
        item = OAuthAuthorizationCode()

        item.code = code
        item.client_id = client.id
        item.redirect_uri = request.redirect_uri
        item.scope = request.scope
        item.user_id = request.user.id

        oauth.__DB_SESSION__.add(item)
        oauth.__DB_SESSION__.commit()

    def query_authorization_code(self, code, client):
        result = OAuthAuthorizationCode.query.filter_by(code=code,
                                                        client_id=client.id).first()

        if result is not None:
            return result
        return None

    def delete_authorization_code(self, authorization_code):
        OAuthAuthorizationCode.query.filter_by(
            id=authorization_code.id).delete()

    def authenticate_user(self, authorization_code):
        return authorization_code.user
