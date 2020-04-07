import enum

from authlib.specs.rfc6749 import TokenMixin
import oauth

db = oauth.__DB__


class OAuthTokenStatus(enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class OAuthToken(db.Model, TokenMixin):
    __tablename__ = 'oauth_token'

    id = db.Column(db.Integer, primary_key=True)

    token_type = db.Column(db.Text)
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    scope = db.Column(db.Text)
    issued_at = db.Column(db.Integer)
    expires_in = db.Column(db.Integer)

    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id'),
                        nullable=False)
    user = db.relationship("User")

    client_id = db.Column(db.Integer,
                          db.ForeignKey('oauth_client.id'),
                          nullable=False)
    client = db.relationship("OAuthClient")

    status = db.Column(db.Enum(OAuthTokenStatus))

    def get_client_id(self):
        return self.client.client_id

    def get_scope(self):
        """A method to get scope of the authorization code. For instance,
        the column is called ``scope``::
            def get_scope(self):
                return self.scope
        :return: scope string
        """
        return self.scope

    def get_expires_in(self):
        """A method to get the ``expires_in`` value of the token. e.g.
        the column is called ``expires_in``::
            def get_expires_in(self):
                return self.expires_in
        :return: timestamp int
        """
        return self.expires_in

    def get_expires_at(self):
        """A method to get the value when this token will be expired. e.g.
        it would be::
            def get_expires_at(self):
                return self.created_at + self.expires_in
        :return: timestamp int
        """
        return self.issued_at + self.expires_in