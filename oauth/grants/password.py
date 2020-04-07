import traceback

from authlib.specs.rfc6749.grants import (
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant)

import oauth


class PasswordGrant(_PasswordGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def authenticate_user(self, username, password):
        return oauth.__GET_USER__(username, password)