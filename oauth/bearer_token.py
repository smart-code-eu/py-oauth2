from authlib.oauth2.rfc6750.wrappers import BearerToken as _BearerToken


class BearerToken(_BearerToken):
    def __call__(self, client, grant_type, user=None, scope=None,
                 expires_in=None, include_refresh_token=True):
        access_token, access_token_payload = \
            self.access_token_generator(client, grant_type, user, scope)

        if expires_in is None:
            expires_in = self._get_expires_in(client, grant_type)

        token = {
            'token_type': 'Bearer',
            'access_token': access_token,
            'access_token_payload': access_token_payload,
            'expires_in': expires_in
        }

        if include_refresh_token and self.refresh_token_generator:
            refresh_token, refresh_token_payload = \
                self.refresh_token_generator(client, grant_type, user, scope)
            token['refresh_token'] = refresh_token
            token['refresh_token_payload'] = refresh_token_payload
        if scope:
            token['scope'] = scope
        return token
