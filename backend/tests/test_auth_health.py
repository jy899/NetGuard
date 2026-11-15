from backend.core.security import create_access_token, hash_password, verify_password


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "application": "NetGuard"}


def test_password_is_hashed():
    stored = hash_password("admin")
    assert "admin" not in stored
    assert verify_password("admin", stored)
    assert not verify_password("wrong", stored)


def test_login_success_and_me(client, auth):
    me = client.get("/api/auth/me", headers=auth)
    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert me.json()["role"] == "Administrators"


def test_login_failure(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "nope"})
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_protected_routes_require_token(client):
    assert client.get("/api/networks").status_code == 401
    assert client.get("/api/networks", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_expired_token_rejected(client):
    token = create_access_token(1, "test-secret-key", expire_minutes=-1)
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_pages_served(client):
    for path in ["/login", "/learning", "/dashboard", "/networks", "/topology", "/changes", "/settings"]:
        response = client.get(path)
        assert response.status_code == 200, path
        assert "text/html" in response.headers["content-type"]
    assert client.get("/static/js/pages/topology.js").headers["content-type"].startswith("application/javascript")


def test_token_rejected_after_logout(client, auth):
    assert client.post("/api/auth/logout", headers=auth).status_code == 200
    assert client.get("/api/auth/me", headers=auth).status_code == 401
    fresh = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {fresh.json()['access_token']}"}).status_code == 200


def test_old_token_rejected_after_password_change(client, auth):
    other = client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).json()
    other_headers = {"Authorization": f"Bearer {other['access_token']}"}
    changed = client.put("/api/auth/password", headers=auth,
                         json={"current_password": "admin", "new_password": "new-password-1"})
    assert changed.status_code == 200
    assert client.get("/api/auth/me", headers=auth).status_code == 401  # this token is from before the change
    assert client.get("/api/auth/me", headers=other_headers).status_code == 401  # and so is any other session
    new_headers = {"Authorization": f"Bearer {changed.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=new_headers).status_code == 200  # the session continues
    assert client.post("/api/auth/login", json={"username": "admin", "password": "admin"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "new-password-1"}).status_code == 200


def test_token_without_version_claim_rejected(client):
    import base64
    import hashlib
    import hmac
    import json
    import time

    body = base64.urlsafe_b64encode(json.dumps({"sub": 1, "exp": int(time.time()) + 600}).encode()).rstrip(b"=").decode()
    sig = hmac.new(b"test-secret-key", body.encode(), hashlib.sha256).digest()
    token = f"{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_login_throttled_after_five_failures(client):
    bad = {"username": "admin", "password": "wrong"}
    for _ in range(5):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    blocked = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert blocked.status_code == 429
    assert blocked.json()["error"] == "too_many_attempts"
    assert "Too many failed login attempts" in blocked.json()["detail"]
    assert int(blocked.headers["Retry-After"]) > 0
    # Another username from the same client is not affected.
    assert client.post("/api/auth/login", json={"username": "someone", "password": "x"}).status_code == 401


def test_successful_login_resets_failure_count(client):
    bad = {"username": "admin", "password": "wrong"}
    good = {"username": "admin", "password": "admin"}
    for _ in range(4):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    assert client.post("/api/auth/login", json=good).status_code == 200
    for _ in range(4):
        assert client.post("/api/auth/login", json=bad).status_code == 401
    assert client.post("/api/auth/login", json=good).status_code == 200


def test_login_throttle_window_and_lockout_expire():
    from backend.core.login_throttle import LoginThrottle

    now = [1000.0]
    throttle = LoginThrottle(clock=lambda: now[0])
    key = throttle.key("Admin ", "10.0.0.5")
    assert key == ("admin", "10.0.0.5")
    for _ in range(4):
        throttle.record_failure(key)
    now[0] += 301  # older failures fall out of the 5-minute window
    throttle.record_failure(key)
    assert throttle.locked_for(key) == 0
    for _ in range(4):
        throttle.record_failure(key)
    assert 0 < throttle.locked_for(key) <= 301
    now[0] += 299
    assert throttle.locked_for(key) > 0
    now[0] += 2
    assert throttle.locked_for(key) == 0  # lockout over after 5 minutes
    throttle.record_failure(key)
    throttle.reset()
    assert throttle.locked_for(key) == 0


def test_security_headers_on_pages_api_and_static(client):
    for path in ["/login", "/topology", "/api/health", "/static/js/api.js"]:
        headers = client.get(path).headers
        csp = headers["content-security-policy"]
        assert "default-src 'self'" in csp and "script-src 'self';" in csp and "frame-ancestors 'none'" in csp, path
        assert "unsafe-eval" not in csp
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert headers["x-frame-options"] == "DENY"
    assert "x-frame-options" in client.get("/api/networks").headers  # error responses too (401)


def test_pages_have_no_inline_scripts():
    """The CSP allows scripts only from 'self': pages must not contain inline <script> code or handlers."""
    import re
    from html.parser import HTMLParser
    from pathlib import Path

    class Resources(HTMLParser):
        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            for key in ('src', 'href'):
                if tag in ('script', 'link', 'img', 'iframe') and key in values:
                    assert not values[key].startswith(('http://', 'https://')), f'external resource: {values[key]}'

    pages = Path(__file__).resolve().parents[2] / "frontend" / "pages"
    for page in pages.glob("*.html"):
        html = page.read_text(encoding="utf-8")
        for tag in re.findall(r"<script\b[^>]*>", html):
            assert "src=" in tag, f"inline script in {page.name}"
        assert not re.search(r"\son[a-z]+\s*=", html), f"inline event handler in {page.name}"
        Resources().feed(html)


def test_existing_database_gets_token_version_column(client):
    from sqlalchemy import inspect, text

    from backend.database.init_db import upgrade_schema
    from backend.database.session import engine

    with engine.begin() as connection:  # simulate a database created before token revocation
        connection.execute(text("ALTER TABLE users DROP COLUMN token_version"))
    assert "token_version" not in {c["name"] for c in inspect(engine).get_columns("users")}
    assert upgrade_schema() == ["users.token_version"]
    login = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    client.post("/api/auth/logout", headers=headers)
    assert client.get("/api/auth/me", headers=headers).status_code == 401
