from authlib.specs.rfc6749 import AuthorizationCodeMixin

import oauth

db = oauth.__DB__


class OAuthAuthorizationCode(db.Model, AuthorizationCodeMixin):
    __tablename__ = 'oauth_authorization_code'

    id = db.Column(db.Integer, primary_key=True)

    redirect_uri = db.Column(db.Text)
    scope = db.Column(db.Text)
    code = db.Column(db.Text)

    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id'),
                        nullable=False)
    user = db.relationship("User")

    client_id = db.Column(db.Integer,
                          db.ForeignKey('oauth_client.id'),
                          nullable=False)
    client = db.relationship("OAuthClient")

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope