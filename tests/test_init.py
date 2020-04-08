import base64
import json
import os
import traceback

import pytest

import oauth
from tests.app import app as _app
from tests.app import db as _db
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker


def check_oauth(username, password):
    from .models import User
    try:
        user = User.query.filter_by(username=username).first()

        if user is not None:
            if user.password == password:
                return user

        return None
    except Exception as e:
        print(traceback.format_exc())
        return None


@pytest.fixture(scope="session")
def app(request):
    """
    Returns session-wide application.
    """
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "1"

    import oauth
    _app.config['SAPI_OAUTH2_DB'] = _db
    _app.config['SAPI_OAUTH2_VALIDATE_USER'] = check_oauth
    oauth.init_oauth(_app)
    return _app


@pytest.fixture(scope="session")
def db(app, request):
    """
    Returns session-wide initialised database.
    """
    with app.app_context():
        from .models import User
        import oauth.models

        _db.drop_all()
        _db.create_all()

        user = User()
        user.email = 'demo'
        user.username = 'demo'
        user.password = 'demo'
        _db.session.add(user)
        _db.session.commit()


@pytest.fixture(scope="function", autouse=True)
def session(app, db, request):
    """
    Returns function-scoped session.
    """
    with app.app_context():
        conn = _db.engine.connect()
        conn.isolation_level = None
        txn = conn.begin()

        options = dict(bind=conn, binds={}, autocommit=False)
        sess = _db.create_scoped_session(options=options)

        # establish  a SAVEPOINT just before beginning the test
        # (http://docs.sqlalchemy.org/en/latest/orm/session_transaction.html#using-savepoint)
        sess.begin_nested()

        @event.listens_for(sess(), 'after_transaction_end')
        def restart_savepoint(sess2, trans):
            # Detecting whether this is indeed the nested transaction of the test
            if trans.nested and not trans._parent.nested:
                # The test should have normally called session.commit(),
                # but to be safe we explicitly expire the session
                sess2.expire_all()
                sess.begin_nested()

        _db.session = sess
        oauth.__DB__ = db
        oauth.__DB_SESSION__ = sess
        yield sess

        # Cleanup
        sess.remove()
        # This instruction rollsback any commit that were executed in the tests.
        txn.rollback()
        conn.close()


@pytest.fixture(scope="function", autouse=True)
def test_client(app, session):
    yield app.test_client()


def create_grant(type):
    oauth_grant = oauth.models.OAuthClientGrant()
    oauth_grant.name = type
    _db.session.add(oauth_grant)
    _db.session.commit()
    return oauth_grant


def db_create_client(grants=["password"]):
    created_grants = [create_grant(x) for x in grants]

    oauth_client = oauth.models.OAuthClient()
    oauth_client.client_id = "demo"
    oauth_client.client_secret = "demo"
    oauth_client.client_type = oauth.models.OAuthClientType.PUBLIC
    oauth_client.any_scope_is_allowed = True
    oauth_client.name = "demo"
    oauth_client.grants = created_grants
    _db.session.add(oauth_client)
    _db.session.commit()

    oauth_scope = oauth.models.OAuthClientScope()
    oauth_scope.name = 'demo'
    oauth_scope.clients = [oauth_client]
    _db.session.add(oauth_scope)
    _db.session.commit()


def oauth_refresh_grant(test_client, refresh_token):
    response = test_client.post('/oauth/token',
                                data=dict(
                                    client_id='demo',
                                    client_secret='demo',
                                    refresh_token=refresh_token,
                                    grant_type='refresh_token',
                                    scope='demo'
                                ),
                                content_type='multipart/form-data',
                                headers=dict(
                                    Authorization='Basic %s' % base64.b64encode(
                                        "demo:demo".encode('utf-8'))
                                ))
    return response


def oauth_password_grant(test_client, username, password):
    response = test_client.post('/oauth/token',
                                data=dict(
                                    client_id='demo',
                                    client_secret='demo',
                                    username=username,
                                    password=password,
                                    grant_type='password',
                                    scope='demo'
                                ),
                                content_type='multipart/form-data',
                                headers=dict(
                                    Authorization='Basic %s' % base64.b64encode(
                                        "demo:demo".encode('utf-8'))
                                ))
    return response


def test_oauth_token_password_grant(test_client, session):
    """
    Verify that you can get a valid token using password grant type and valid
    username & password.

    Verify that token is saved to the database and matches correctly the
    returned token

    :param test_client:
    :param session:
    :return:
    """
    db_create_client(["password"])

    response = oauth_password_grant(test_client, 'demo', 'demo')

    assert response.status_code == 200

    data = json.loads(response.get_data(as_text=True))

    import oauth.models
    first_token: oauth.models.OAuthToken = \
        session.query(oauth.models.OAuthToken).first()

    # DB token should be the same as the returned token.
    assert first_token.access_token == data.get("access_token")

    # In this test suite, refresh tokens are not enabled and should not exist.
    assert first_token.refresh_token is None


def test_oauth_token_refresh_grant(test_client, session):
    """
    Verify:

    * that you can get a valid token using password grant type and valid
    username & password.
    * that token is saved to the database and matches correctly the
    returned token.
    * that you can get a new token using refresh token
    * when you refresh a token the old one is revoked

    :param test_client:
    :param session:
    :return:
    """
    db_create_client(["password", "refresh_token"])

    response = oauth_password_grant(test_client, 'demo', 'demo')

    assert response.status_code == 200
    data = json.loads(response.get_data(as_text=True))
    assert data.get("access_token") is not None
    assert data.get("refresh_token") is not None

    import oauth.models
    first_token: oauth.models.OAuthToken = \
        session.query(oauth.models.OAuthToken).first()

    # DB token should be the same as the returned token.
    assert first_token.access_token == data.get("access_token")

    # When refreshing we should get a refresh token that's also saved to the DB.
    assert first_token.refresh_token == data.get("refresh_token")

    # Getting a new token from a refresh token.
    response = oauth_refresh_grant(test_client, data.get("refresh_token"))

    assert response.status_code == 200
    data = json.loads(response.get_data(as_text=True))
    assert data.get("access_token") is not None
    assert data.get("refresh_token") is not None

    second_token: oauth.models.OAuthToken = \
        session.query(oauth.models.OAuthToken) \
            .filter_by(access_token=data.get("access_token")) \
            .first()

    # First token should be now revoked.
    assert first_token.status == oauth.models.OAuthTokenStatus.REVOKED
    assert second_token.status == oauth.models.OAuthTokenStatus.ACTIVE

    # There should be total of 2 tokens now: revoked and un-revoked.
    assert session.query(oauth.models.OAuthToken).count() == 2


def test_oauth_token_password_grant_wrong_user(test_client):
    db_create_client(["password", "refresh"])
    response = oauth_password_grant(test_client, 'wrong_user', 'demo')
    assert response.status_code == 400


def test_oauth_token_password_grant_wrong_password(test_client):
    db_create_client(["password", "refresh"])
    response = oauth_password_grant(test_client, 'demo', 'wrong_password')
    assert response.status_code == 400
