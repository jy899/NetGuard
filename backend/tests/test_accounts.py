from backend.tests.helpers import group_id


def test_admin_controls_and_disabled_account_tokens(client, auth):
    created = client.post('/api/accounts', headers=auth, json={
        'username': 'reviewer', 'password': 'reviewer-password', 'group_id': group_id(client, auth, 'Network Engineers')})
    assert created.status_code == 201
    account = created.json()
    assert 'password' not in str(account) and 'password_hash' not in account and 'email' not in account
    assert account['role'] == 'Network Engineers' and 'change.execute' in account['permissions']
    login = client.post('/api/auth/login', json={'username': 'reviewer', 'password': 'reviewer-password'}).json()
    other = {'Authorization': 'Bearer ' + login['access_token']}
    forbidden = client.get('/api/accounts', headers=other)
    assert forbidden.status_code == 403 and forbidden.json()['error'] == 'forbidden'
    assert client.put(f"/api/accounts/{account['id']}", headers=auth, json={'is_active': False}).status_code == 200
    assert client.get('/api/auth/me', headers=other).status_code == 401
    assert client.post('/api/auth/login', json={'username': 'reviewer', 'password': 'reviewer-password'}).status_code == 401
    assert client.put(f"/api/accounts/{account['id']}", headers=auth, json={'is_active': True}).status_code == 200
    assert client.post('/api/auth/login', json={'username': 'reviewer', 'password': 'reviewer-password'}).status_code == 200
    assert client.delete(f"/api/accounts/{account['id']}", headers=auth).status_code == 204


def test_profile_and_account_protection(client, auth):
    settings = client.get('/api/account/settings', headers=auth).json()
    assert settings['is_admin'] and settings['security']['encrypted_device_credentials']
    own_id = settings['profile']['id']
    assert 'email' not in settings['profile']
    assert client.put(f'/api/accounts/{own_id}', headers=auth, json={'is_active': False}).status_code == 422
    assert client.delete(f'/api/accounts/{own_id}', headers=auth).status_code == 422
    duplicate = client.post('/api/accounts', headers=auth, json={
        'username': 'admin', 'password': 'long-password', 'group_id': group_id(client, auth, 'Administrators')})
    assert duplicate.status_code == 409


def test_custom_groups_grant_exactly_their_permissions(client, auth):
    catalogue = {p['id'] for p in client.get('/api/permissions', headers=auth).json()}
    assert {'topology.view', 'discovery.run', 'change.approve', 'change.execute', 'credentials.manage',
            'users.manage', 'network.import_export', 'change.propose'} <= catalogue
    created = client.post('/api/groups', headers=auth, json={'name': 'Auditors', 'description': 'Read only',
                                                            'permissions': ['topology.view']})
    assert created.status_code == 201, created.text
    gid = created.json()['id']
    assert client.post('/api/groups', headers=auth, json={'name': 'auditors', 'permissions': []}).status_code == 409
    assert client.post('/api/groups', headers=auth, json={'name': 'X1', 'permissions': ['root']}).status_code == 422
    client.post('/api/accounts', headers=auth, json={'username': 'audit', 'password': 'audit-password', 'group_id': gid})
    token = client.post('/api/auth/login', json={'username': 'audit', 'password': 'audit-password'}).json()['access_token']
    audit = {'Authorization': f'Bearer {token}'}
    assert client.get('/api/networks', headers=audit).status_code == 200
    assert client.post('/api/networks', headers=audit, json={'name': 'n'}).status_code == 403
    # Granting a permission takes effect on the next request.
    assert client.put(f'/api/groups/{gid}', headers=auth, json={'name': 'Auditors', 'permissions':
                                                               ['topology.view', 'network.edit']}).status_code == 200
    assert client.post('/api/networks', headers=audit, json={'name': 'n'}).status_code == 201
    assert client.delete(f'/api/groups/{gid}', headers=auth).status_code == 422  # still has a member
    builtin = next(g for g in client.get('/api/groups', headers=auth).json() if g['name'] == 'Administrators')
    assert builtin['builtin'] and client.delete(f"/api/groups/{builtin['id']}", headers=auth).status_code == 422
    assert client.put(f"/api/groups/{builtin['id']}", headers=auth,
                      json={'name': 'Administrators', 'permissions': ['topology.view']}).status_code == 422


def test_session_revocation_preserves_returned_session(client, auth):
    earlier = client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'}).json()
    result = client.post('/api/auth/revoke-other-sessions', headers=auth)
    assert result.status_code == 200
    assert client.get('/api/auth/me', headers=auth).status_code == 401
    assert client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + earlier['access_token']}).status_code == 401
    assert client.get('/api/auth/me', headers={'Authorization': 'Bearer ' + result.json()['access_token']}).status_code == 200


def test_reset_admin_command_restores_the_default_login(client, auth):
    import netguard
    from sqlalchemy import select

    from backend.core.security import hash_password
    from backend.database.session import SessionLocal
    from backend.models import User

    with SessionLocal() as db:  # forgotten password and a disabled admin
        admin = db.scalar(select(User).where(User.username == "admin"))
        admin.password_hash, admin.is_active = hash_password("forgotten-1"), False
        db.commit()
    assert client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'}).status_code == 401
    assert netguard.reset_admin() == 0
    assert client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin'}).status_code == 200
