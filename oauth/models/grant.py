import oauth

db = oauth.__DB__

grant_association_table = db.Table('oauth_clients_oauth_client_grants',
                                   db.metadata,
                                   db.Column('oauth_client_id', db.Integer,
                                             db.ForeignKey('oauth_client.id')),
                                   db.Column('oauth_client_grant_id',
                                             db.Integer, db.ForeignKey(
                                           'oauth_client_grant.id'))
                                   )


class OAuthClientGrant(db.Model):
    __tablename__ = 'oauth_client_grant'

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(255), unique=True)
    clients = db.relationship(
        "OAuthClient",
        secondary=grant_association_table,
        back_populates="grants")
