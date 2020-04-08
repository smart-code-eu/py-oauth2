import time

from authlib.specs.rfc6749.grants import (
    RefreshTokenGrant as _RefreshTokenGrant)

import oauth
from oauth.models import OAuthToken
from oauth.models import OAuthTokenStatus

db = oauth.__DB__


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token):
        time_now = time.time()
        result = OAuthToken.query.filter_by(
            refresh_token=refresh_token).filter_by(status="ACTIVE").filter(
            OAuthToken.issued_at + OAuthToken.expires_in >= time_now).first()
        if result is not None:
            return result
        return None

    def authenticate_user(self, credential):
        result = OAuthToken.query.filter_by(id=credential.id).first()

        if result is not None:
            return result.user
        return None

    def revoke_old_credential(self, credential):
        # Revoking on refresh.
        credential.status = OAuthTokenStatus.REVOKED
        oauth.__DB_SESSION__.commit()
