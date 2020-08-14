from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator

from oauth.models import OAuthToken


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [str(s) for s in scope]
    elif scope is None:
        return None
    else:
        return scope.strip().split(" ")


class BearerTokenValidator(_BearerTokenValidator):
    def authenticate_token(self, token_string):
        result = OAuthToken.query \
            .filter_by(access_token=token_string) \
            .filter_by(status='ACTIVE').first()
        return result

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        return token.status == 'REVOKED'

    def scope_insufficient(self, token, scope, operator='AND'):
        # If the client has scope bypass just let anything through.
        if token.client.any_scope_is_allowed:
            return False

        if not scope:
            return False
        token_scopes = set(scope_to_list(token.get_scope()))
        resource_scopes = set(scope_to_list(scope))
        if operator == 'AND':
            return not token_scopes.issuperset(resource_scopes)
        if operator == 'OR':
            return not token_scopes & resource_scopes
        if callable(operator):
            return not operator(token_scopes, resource_scopes)
        raise ValueError('Invalid operator value')
