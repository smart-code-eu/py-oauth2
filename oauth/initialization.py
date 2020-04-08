import oauth


def init_oauth(flask_app):
    oauth.__DB__ = flask_app.config['SAPI_OAUTH2_DB']
    oauth.__DB_SESSION__ = oauth.__DB__.session
    oauth.__GET_USER__ = flask_app.config['SAPI_OAUTH2_VALIDATE_USER']

    from oauth.bearer_token_validator import BearerTokenValidator
    from oauth.resource_protector import ResourceProtector

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(BearerTokenValidator())

    from oauth.controller import OAuthController
    oauth_controller = OAuthController(flask_app)
    flask_app.register_blueprint(oauth_controller.blueprint)

    return require_oauth
