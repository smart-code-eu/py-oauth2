global __DB__
global __GET_USER__


def get_require_oauth():
    from oauth.bearer_token_validator import MyBearerTokenValidator
    from oauth.resource_protector import ResourceProtector

    require_oauth = ResourceProtector()
    require_oauth.register_token_validator(MyBearerTokenValidator())
    return require_oauth
