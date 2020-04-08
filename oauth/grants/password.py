from authlib.specs.rfc6749.grants import (
    ResourceOwnerPasswordCredentialsGrant as _PasswordGrant)

import oauth


class PasswordGrant(_PasswordGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def authenticate_user(self, username, password):
        return oauth.__GET_USER__(username, password)

    def create_token_response(self):
        client = self.request.client
        token = self.generate_token(
            client, self.GRANT_TYPE,
            user=self.request.user,
            scope=client.get_allowed_scope(self.request.scope),
            include_refresh_token=client.check_grant_type('refresh_token')
        )
        self.save_token(token)
        self.execute_hook('process_token', token=token)
        return 200, token, self.TOKEN_RESPONSE_HEADER