"""Shared test helpers for the approval workflow."""
from __future__ import annotations


def group_id(client, auth, name: str) -> int:
    return next(g["id"] for g in client.get("/api/groups", headers=auth).json() if g["name"] == name)


def manager_auth(client, auth) -> dict:
    """Headers of an IT Manager account (created on first use)."""
    client.post("/api/accounts", headers=auth, json={"username": "manager", "password": "Manager-Pass1",
                                                     "group_id": group_id(client, auth, "IT Managers")})
    token = client.post("/api/auth/login", json={"username": "manager", "password": "Manager-Pass1"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def approve(client, auth, change_id: int) -> dict:
    """Validate, submit and approve a change; returns the final change (status may stay analyzed when refused)."""
    client.post(f"/api/changes/{change_id}/analyze", headers=auth)
    if client.post(f"/api/changes/{change_id}/submit", headers=auth).status_code == 200:
        client.post(f"/api/changes/{change_id}/approve", headers=manager_auth(client, auth), json={"note": "ok"})
    return client.get(f"/api/changes/{change_id}", headers=auth).json()


def approve_and_apply(client, auth, change_id: int):
    approve(client, auth, change_id)
    return client.post(f"/api/changes/{change_id}/apply", headers=auth, json={"confirm": True})
