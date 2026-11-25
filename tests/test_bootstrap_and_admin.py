"""Tests for health probes, first-run bootstrap, admin login, and RBAC."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from tests.conftest import bootstrap_admin

from anonix_gateway.config import Settings


async def test_health_and_readiness(gateway_client: httpx.AsyncClient) -> None:
    h = await gateway_client.get("/healthz")
    assert h.status_code == 200
    assert h.json()["status"] == "ok"

    r = await gateway_client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


async def test_bootstrap_once_and_login(gateway_client: httpx.AsyncClient) -> None:
    s1 = await gateway_client.get("/api/setup/status")
    assert s1.status_code == 200
    assert s1.json()["bootstrapped"] is False

    headers = await bootstrap_admin(gateway_client)
    assert "Authorization" in headers

    s2 = await gateway_client.get("/api/setup/status")
    assert s2.json()["bootstrapped"] is True

    # Second bootstrap must fail with 409 Conflict
    dup = await gateway_client.post(
        "/api/setup/bootstrap",
        json={
            "org_name": "Evil",
            "admin_email": "evil@acme.org",
            "admin_password": "Password123!",
        },
    )
    assert dup.status_code == 409

    # Valid login succeeds
    ok = await gateway_client.post(
        "/api/admin/login",
        json={"email": "admin@acme.org", "password": "StrongPass123!"},
    )
    assert ok.status_code == 200
    assert ok.json()["role"] == "platform_admin"

    # Bad password fails closed
    bad = await gateway_client.post(
        "/api/admin/login",
        json={"email": "admin@acme.org", "password": "wrong-password"},
    )
    assert bad.status_code == 401


async def test_admin_rbac_enforcement(gateway_client: httpx.AsyncClient) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    # Create a policy_author and an auditor
    r_author = await gateway_client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"email": "author@acme.org", "password": "AuthorPass123!", "role": "policy_author"},
    )
    assert r_author.status_code == 201

    r_auditor = await gateway_client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"email": "auditor@acme.org", "password": "AuditorPass123!", "role": "auditor"},
    )
    assert r_auditor.status_code == 201

    author_tok = (
        await gateway_client.post(
            "/api/admin/login",
            json={"email": "author@acme.org", "password": "AuthorPass123!"},
        )
    ).json()["access_token"]
    auditor_tok = (
        await gateway_client.post(
            "/api/admin/login",
            json={"email": "auditor@acme.org", "password": "AuditorPass123!"},
        )
    ).json()["access_token"]

    # policy_author cannot create API keys (403)
    forbidden_key = await gateway_client.post(
        "/api/admin/api-keys",
        headers={"Authorization": f"Bearer {author_tok}"},
        json={"name": "k1", "groups": ["analysts"]},
    )
    assert forbidden_key.status_code == 403

    # auditor can read audit logs (200) but cannot create policies (403)
    audit_ok = await gateway_client.get(
        "/api/admin/audit",
        headers={"Authorization": f"Bearer {auditor_tok}"},
    )
    assert audit_ok.status_code == 200

    forbidden_policy = await gateway_client.post(
        "/api/admin/policies",
        headers={"Authorization": f"Bearer {auditor_tok}"},
        json={
            "name": "p1",
            "yaml_content": (
                "version: '1.0'\nrules:\n  - selector: '$.ssn'\n    technique: redact\n"
            ),
        },
    )
    assert forbidden_policy.status_code == 403


def test_production_requires_explicit_secrets(tmp_path: Path) -> None:
    s = Settings(env="production", data_dir=tmp_path, master_key=None, admin_jwt_secret=None)
    with pytest.raises(RuntimeError, match="ANONIX_MASTER_KEY"):
        s.resolve_secrets()


async def test_full_crud_updates_and_deletes(gateway_client: httpx.AsyncClient) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    # Policy + new version + activate v1 rollback
    p = (
        await gateway_client.post(
            "/api/admin/policies",
            headers=admin_headers,
            json={"name": "p-crud", "yaml_content": "version: '1.0'\nrules: []\n"},
        )
    ).json()
    v2 = await gateway_client.post(
        f"/api/admin/policies/{p['id']}/versions",
        headers=admin_headers,
        json={
            "yaml_content": (
                "version: '1.0'\nrules:\n  - selector: '$.ssn'\n    technique: redact\n"
            ),
            "activate": True,
        },
    )
    assert v2.status_code == 201
    act = await gateway_client.post(
        f"/api/admin/policies/{p['id']}/versions/1/activate", headers=admin_headers
    )
    assert act.status_code == 200

    # Auth provider PATCH + DELETE
    prov = (
        await gateway_client.post(
            "/api/admin/auth-providers",
            headers=admin_headers,
            json={
                "name": "okta",
                "provider_type": "oidc",
                "issuer_url": "https://idp.example.com",
            },
        )
    ).json()
    assert (
        await gateway_client.patch(
            f"/api/admin/auth-providers/{prov['id']}",
            headers=admin_headers,
            json={"is_enabled": False, "name": "okta-disabled"},
        )
    ).json()["is_enabled"] is False

    # Group mapping PATCH + DELETE (policy_id required)
    bad_gm = await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={"external_group": "g1", "policy_role": "r1"},
    )
    assert bad_gm.status_code == 422

    gm = (
        await gateway_client.post(
            "/api/admin/group-mappings",
            headers=admin_headers,
            json={"external_group": "g1", "policy_role": "r1", "policy_id": p["id"], "priority": 5},
        )
    ).json()
    gm_up = await gateway_client.patch(
        f"/api/admin/group-mappings/{gm['id']}",
        headers=admin_headers,
        json={"policy_role": "", "priority": 20},
    )
    assert gm_up.json()["policy_role"] is None
    assert gm_up.json()["priority"] == 20

    # API key PATCH + DELETE
    k = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={"name": "k1", "groups": ["g1"]},
        )
    ).json()
    assert (
        await gateway_client.patch(
            f"/api/admin/api-keys/{k['id']}",
            headers=admin_headers,
            json={"name": "k1-renamed", "groups": ["g2"]},
        )
    ).json()["name"] == "k1-renamed"
    assert (
        await gateway_client.delete(f"/api/admin/api-keys/{k['id']}", headers=admin_headers)
    ).status_code == 204

    # Upstream & Route PATCH + DELETE
    up = (
        await gateway_client.post(
            "/api/admin/upstreams",
            headers=admin_headers,
            json={"name": "up1", "base_url": "http://127.0.0.1:9080"},
        )
    ).json()
    assert (
        await gateway_client.patch(
            f"/api/admin/upstreams/{up['id']}",
            headers=admin_headers,
            json={"base_url": "http://127.0.0.1:9081"},
        )
    ).json()["base_url"] == "http://127.0.0.1:9081"

    rt = (
        await gateway_client.post(
            "/api/admin/routes",
            headers=admin_headers,
            json={
                "name": "rt1",
                "route_prefix": "/old",
                "upstream_id": up["id"],
                "policy_id": p["id"],
            },
        )
    ).json()
    assert (
        await gateway_client.patch(
            f"/api/admin/routes/{rt['id']}",
            headers=admin_headers,
            json={"route_prefix": "/new", "strip_prefix": False},
        )
    ).json()["route_prefix"] == "/new"

    # Admin user PATCH + DELETE
    u = (
        await gateway_client.post(
            "/api/admin/users",
            headers=admin_headers,
            json={"email": "u2@acme.org", "password": "Password123!", "role": "auditor"},
        )
    ).json()
    assert (
        await gateway_client.patch(
            f"/api/admin/users/{u['id']}",
            headers=admin_headers,
            json={"role": "policy_author", "is_active": False},
        )
    ).json()["role"] == "policy_author"
    assert (
        await gateway_client.delete(f"/api/admin/users/{u['id']}", headers=admin_headers)
    ).status_code == 204


async def test_invalid_inputs_and_duplicates_return_clean_4xx(
    gateway_client: httpx.AsyncClient,
) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    # Invalid CIDR in trusted_proxy -> 422
    bad_cidr = await gateway_client.post(
        "/api/admin/auth-providers",
        headers=admin_headers,
        json={
            "name": "bad-tp",
            "provider_type": "trusted_proxy",
            "trusted_cidrs": ["not-an-ip"],
            "proxy_secret": "secret",
        },
    )
    assert bad_cidr.status_code == 422

    # Duplicate upstream name -> 409 (never 500)
    assert (
        await gateway_client.post(
            "/api/admin/upstreams",
            headers=admin_headers,
            json={"name": "dup-up", "base_url": "http://127.0.0.1:9080"},
        )
    ).status_code == 201
    dup_up = await gateway_client.post(
        "/api/admin/upstreams",
        headers=admin_headers,
        json={"name": "dup-up", "base_url": "http://127.0.0.1:9081"},
    )
    assert dup_up.status_code == 409

    # Route referencing nonexistent upstream/policy -> 422 (never 500)
    bad_route = await gateway_client.post(
        "/api/admin/routes",
        headers=admin_headers,
        json={
            "name": "bad-rt",
            "route_prefix": "/bad",
            "upstream_id": "nonexistent",
            "policy_id": "nonexistent",
        },
    )
    assert bad_route.status_code == 422

    # Duplicate admin email -> 409 (never 500)
    dup_user = await gateway_client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"email": "admin@acme.org", "password": "Password123!", "role": "auditor"},
    )
    assert dup_user.status_code == 409
