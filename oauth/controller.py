import datetime
import time

import flask
from flask import Blueprint, render_template

import oauth
from oauth.grants.authorization import AuthorizationCodeGrant

from oauth.authorization_server import AuthorizationServer
from oauth.grants.password import PasswordGrant
from oauth.grants.refresh_token import RefreshTokenGrant
from oauth.models import OAuthToken, OAuthClient
from oauth.models import OAuthTokenStatus

from authlib.jose import jwt

import uuid

db = oauth.__DB__


class OAuthController:
    def __init__(self, app):
        self.blueprint = Blueprint('oauth_controller', __name__)
        self.blueprint.add_url_rule('/oauth/authorize', 'authorize',
                                    self.authorize, methods=(['GET', 'POST']))
        self.blueprint.add_url_rule('/oauth/token', 'issue_token',
                                    self.issue_token, methods=(['GET', 'POST']))

        key = open(oauth.__JWT_PATH__, 'r').read()

        generate_token = OAuthController.__generate_token("ok", "ok", key)

        self.server = AuthorizationServer(generate_token,
                                          generate_token,
                                          app,
                                          OAuthController.__query_client,
                                          OAuthController.__store_token)
        self.server.register_grant(PasswordGrant)
        self.server.register_grant(RefreshTokenGrant)
        self.server.register_grant(AuthorizationCodeGrant)

    def authorize(self):
        request = flask.request
        # Login is required since we need to know the current resource owner.
        # It can be done with a redirection to the login page, or a login
        # form on this authorization page.
        if request.method == 'GET':
            grant = self.server.validate_consent_request(
                end_user=oauth.__GET_USER__("demo", "demo"))
            return render_template(
                'authorize.html',
                grant=grant,
                user=oauth.__GET_USER__("demo", "demo"),
            )
        confirmed = request.form['confirm']
        if confirmed:
            # granted by resource owner
            return self.server.create_authorization_response(
                grant_user=oauth.__GET_USER__("demo", "demo"))
        # denied by resource owner
        return self.server.create_authorization_response(grant_user=None)

    def issue_token(self, **kw):
        response = self.server.create_token_response()
        return response

    @staticmethod
    def __generate_token(iss, aud, key):
        def func(client, grant_type, user, scope):
            header = {'alg': 'RS256'}

            exp = datetime.datetime.now() + datetime.timedelta(seconds=3000)
            exp_iso = exp.isoformat()

            payload = {
                'iss': client.jwt_iss,
                'sub': user.email,
                'aud': client.jwt_aud,
                'exp': exp_iso,
                'scope': scope,
                'jti': str(uuid.uuid4())
            }

            s = jwt.encode(header, payload, key)
            return s.decode('utf-8'), payload

        return func

    @staticmethod
    def __query_client(client_id):
        result = OAuthClient.query.filter_by(client_id=client_id).first()
        return result

    @staticmethod
    def __store_token(token, request):
        print(token)
        oauth_token = OAuthToken()
        oauth_token.token_type = token["token_type"]
        oauth_token.access_token = token["access_token"]
        oauth_token.refresh_token = token.get("refresh_token")
        oauth_token.scope = token["scope"]
        oauth_token.issued_at = time.time()
        oauth_token.expires_in = token["expires_in"]
        oauth_token.client_id = request.client.id
        oauth_token.user_id = request.user.id
        oauth_token.status = OAuthTokenStatus.ACTIVE

        oauth_token.jwt_jti = token.get("access_token_payload").get("jti")

        oauth.__DB_SESSION__.add(oauth_token)
        oauth.__DB_SESSION__.commit()
        return None
