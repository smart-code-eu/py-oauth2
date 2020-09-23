import oauth

db = oauth.__DB__

scope_association_table = db.Table('oauth_clients_oauth_client_scopes',
                                   db.metadata,
                                   db.Column('oauth_client_id', db.Integer,
                                             db.ForeignKey('oauth_client.id')),
                                   db.Column('oauth_client_scope_id',
                                             db.Integer, db.ForeignKey(
                                           'oauth_client_scope.id'))
                                   )


class OAuthClientScope(db.Model):
    __tablename__ = 'oauth_client_scope'

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.Text)
    clients = db.relationship(
        "OAuthClient",
        secondary=scope_association_table,
        back_populates="scopes")
