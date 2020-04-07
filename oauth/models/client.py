import enum

import oauth

db = oauth.__DB__

from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from authlib.specs.rfc6749 import ClientMixin
from oauth.models.grant import grant_association_table
from oauth.models.scope import scope_association_table


class OAuthClientType(enum.Enum):
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"


class OAuthClient(db.Model, ClientMixin):
    __tablename__ = 'oauth_client'

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.Text)
    client_id = db.Column(db.Text)
    client_secret = db.Column(db.Text)
    client_type = db.Column(db.Enum(OAuthClientType))

    any_scope_is_allowed = db.Column(db.Boolean)

    tokens = db.relationship("OAuthToken")

    grants = db.relationship(
        "OAuthClientGrant",
        secondary=grant_association_table,
        back_populates="clients",
        lazy="dynamic")
    scopes = db.relationship(
        "OAuthClientScope",
        secondary=scope_association_table,
        back_populates="clients")

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set([scope.name for scope in self.scopes])
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def get_client_id(self):
        # client_id
        return self.client_id

    def get_default_redirect_uri(self):
        # default_redirect_uri
        return self.client_secret

    def check_redirect_uri(self, redirect_uri):
        # redirect_uri in self.allowed_redirect_uris
        return True

    def has_client_secret(self):
        if self.client_secret is None:
            return True
        return False

    def check_client_secret(self, client_secret):
        if self.client_secret == client_secret:
            return True
        return False

    def check_token_endpoint_auth_method(self, method):
        return True

    def check_response_type(self, response_type):
        # return response_type in self.response_types
        return True

    def check_grant_type(self, grant_type):
        result = self.grants.filter_by(name=grant_type).first()
        return result is not None

    def check_requested_scopes(self, scopes):
        if self.any_scope_is_allowed:
            return True

        for scope in scopes:
            if not self.scopes_ids.search([('name', '=', scope)]).exists():
                return False
        return True

    def check_client_type(self, client_type):
        return self.client_type == client_type
