import functools
import json
from contextlib import contextmanager

import flask
from authlib.specs.rfc6749 import (
    ResourceProtector as _ResourceProtector,
    MissingAuthorizationError, HttpRequest,
    OAuth2Error)
from werkzeug.wrappers import Response


class ResourceProtector(_ResourceProtector):
    """A protecting method for resource servers. Creating a ``require_oauth``
    decorator easily with ResourceProtector::
        from authlib.flask.oauth2 import ResourceProtector
        require_oauth = ResourceProtector()
        # add bearer token validator
        from authlib.oauth2.rfc6750 import BearerTokenValidator
        from project.models import Token
        class MyBearerTokenValidator(BearerTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()
            def request_invalid(self, request):
                return False
            def token_revoked(self, token):
                return False
        require_oauth.register_token_validator(MyBearerTokenValidator())
        # protect resource with require_oauth
        @app.route('/user')
        @require_oauth('profile')
        def user_profile():
            user = User.query.get(current_token.user_id)
            return jsonify(user.to_dict())
    """

    def raise_error_response(self, error):
        """Raise HTTPException for OAuth2Error. Developers can re-implement
        this method to customize the error response.
        :param error: OAuth2Error
        :raise: HTTPException
        """
        status = error.status_code
        body = json.dumps(dict(error.get_body()))
        headers = error.get_headers()
        return Response(body, status=status, headers=headers)

    def acquire_token(self, scope=None, operator='AND'):
        """A method to acquire current valid token with the given scope.
        :param scope: string or list of scope values
        :param operator: value of "AND" or "OR"
        :return: token object
        """
        request = HttpRequest(
            flask.request.method,
            flask.request.full_path,
            flask.request.data,
            flask.request.headers
        )
        if not callable(operator):
            operator = operator.upper()
        print("AQUIRE: {0}".format(flask.request.headers))
        token = self.validate_request(scope, request, operator)
        print("TOKEN: {0}".format(token))
        # token_authenticated.send(self, token=token)
        # ctx = _app_ctx_stack.top
        # ctx.authlib_server_oauth2_token = token
        flask.request.api_token = token
        return token

    @contextmanager
    def acquire(self, scope=None, operator='AND'):
        """The with statement of ``require_oauth``. Instead of using a
        decorator, you can use a with statement instead::
            @app.route('/api/user')
            def user_api():
                with require_oauth.acquire('profile') as token:
                    user = User.query.get(token.user_id)
                    return jsonify(user.to_dict())
        """
        try:
            yield self.acquire_token(scope, operator)
        except OAuth2Error as error:
            self.raise_error_response(error)

    def __call__(self, scope=None, operator='AND', optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    self.acquire_token(scope, operator)
                except MissingAuthorizationError as error:
                    if optional:
                        return f(*args, **kwargs)
                    return self.raise_error_response(error)
                except OAuth2Error as error:
                    return self.raise_error_response(error)
                return f(*args, **kwargs)

            return decorated

        return wrapper