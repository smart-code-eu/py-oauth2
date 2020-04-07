import time

import flask
from flask import Blueprint, render_template

import oauth
from oauth.grants.authorization import AuthorizationCodeGrant

db = oauth.__DB__

from oauth.authorization_server import OAuthAuthorizationServer
from oauth.grants.password import PasswordGrant
from oauth.grants.refresh_token import RefreshTokenGrant
from oauth.models import OAuthToken, OAuthClient
from oauth.models import OAuthTokenStatus

from authlib.jose import jwt


def gen_access_token(client, grant_type, user, scope):
    print('Not used yet in the JWT:: {} \n{} \n{} \n{}'.format( client, grant_type, user, scope))
    header = {'alg': 'RS256'}
    payload = {
        'iss': 'http://127.0.0.1:5000/oauth/token',
        'sub': 'test client',
        'aud': 'profile'
    }

    key = open('/Users/darian/Desktop/wf-app-pub.pem', 'r').read()
    s = jwt.encode(header, payload, key)
    return s.decode('utf-8')

class OAuthController:
    def __init__(self, app):
        self.blueprint = Blueprint('oauth_controller', __name__)
        self.blueprint.add_url_rule('/oauth/authorize', 'authorize', self.authorize, methods=(['GET', 'POST']))
        self.blueprint.add_url_rule('/oauth/token', 'issue_token', self.issue_token, methods=(['GET', 'POST']))

        self.server = OAuthAuthorizationServer(gen_access_token,
                                               gen_access_token,
                                               app,
                                               self.query_client,
                                               self.save_token)
        self.server.register_grant(PasswordGrant)
        self.server.register_grant(RefreshTokenGrant)
        self.server.register_grant(AuthorizationCodeGrant)

    def authorize(self):
        request = flask.request
        # Login is required since we need to know the current resource owner.
        # It can be done with a redirection to the login page, or a login
        # form on this authorization page.
        if request.method == 'GET':
            grant = self.server.validate_consent_request(end_user=oauth.__GET_USER__("demo", "demo"))
            return render_template(
                'authorize.html',
                grant=grant,
                user=oauth.__GET_USER__("demo", "demo"),
            )
        confirmed = request.form['confirm']
        if confirmed:
            # granted by resource owner
            return self.server.create_authorization_response(grant_user=oauth.__GET_USER__("demo", "demo"))
        # denied by resource owner
        return self.server.create_authorization_response(grant_user=None)

    def query_client(self, client_id):
        result = OAuthClient.query.filter_by(client_id=client_id).first()
        return result

    def save_token(self, token, request):
        print("token: {}, request: {}".format(token, request))
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

        db.session.add(oauth_token)
        db.session.commit()
        return None

    def issue_token(self, **kw):
        response = self.server.create_token_response()
        return response