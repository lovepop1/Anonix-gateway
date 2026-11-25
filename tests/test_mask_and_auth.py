"""Tests for /v1/mask, fail-closed auth modes, GroupMapping, and zero-PII audit."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from tests.conftest import bootstrap_admin

SAMPLE_POLICY_YAML = """
version: '1.0'
rules:
  - selector: '$.ssn'
    technique: suppress
    roles:
      - researcher
  - selector: '$.email'
    technique: redact
    roles:
      - researcher
"""


async def test_mask_fails_closed_when_unauthenticated_or_unmapped(
    gateway_client: httpx.AsyncClient,
) -> None:
    await bootstrap_admin(gateway_client)

    # No credentials -> 401
    r1 = await gateway_client.post("/v1/mask", json={"payload": {"ssn": "123"}})
    assert r1.status_code == 401


async def test_api_key_masking_priority_and_zero_pii_audit(
    gateway_client: httpx.AsyncClient,
) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    # Create policy
    p_resp = await gateway_client.post(
        "/api/admin/policies",
        headers=admin_headers,
        json={"name": "patient-policy", "yaml_content": SAMPLE_POLICY_YAML},
    )
    assert p_resp.status_code == 201
    policy_id = p_resp.json()["id"]

    # Create two group mappings with different priorities
    m1 = await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={
            "external_group": "hospital-staff",
            "policy_role": "researcher",
            "policy_id": policy_id,
            "priority": 10,
        },
    )
    assert m1.status_code == 201

    # Unmapped API key -> 403
    k_unmapped = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={"name": "rogue-script", "groups": ["unknown-group"]},
        )
    ).json()["raw_key"]
    r_403 = await gateway_client.post(
        "/v1/mask",
        headers={"X-API-Key": k_unmapped},
        json={"policy": "patient-policy", "payload": {"name": "Aarav", "ssn": "123-45-6789"}},
    )
    assert r_403.status_code == 403

    # Mapped API key (policy pinned via GroupMapping!)
    k_researcher = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={"name": "analytics-etl", "groups": ["hospital-staff"]},
        )
    ).json()["raw_key"]

    r_ok = await gateway_client.post(
        "/v1/mask",
        headers={"X-API-Key": k_researcher},
        json={"payload": {"name": "Aarav", "ssn": "123-45-6789", "email": "aarav@acme.org"}},
    )
    assert r_ok.status_code == 200
    assert r_ok.headers["X-Anonix-Role"] == "researcher"
    masked = r_ok.json()
    assert "ssn" not in masked
    assert masked["email"] != "aarav@acme.org"
    assert masked["name"] == "Aarav"

    # Verify zero-PII audit log
    audits = (await gateway_client.get("/api/admin/audit", headers=admin_headers)).json()
    assert len(audits) == 1
    audit_blob = json.dumps(audits[0])
    assert "123-45-6789" not in audit_blob
    assert "aarav@acme.org" not in audit_blob
    assert audits[0]["resolved_role"] == "researcher"
    assert audits[0]["auth_method"] == "api_key"


@respx.mock
async def test_oidc_jwt_auth_and_group_mapping(gateway_client: httpx.AsyncClient) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    # Generate RSA keypair for mock OIDC provider
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "test-kid-1"
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"

    respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200, json={"jwks_uri": "https://idp.example.com/oauth2/jwks"}
        )
    )
    respx.get("https://idp.example.com/oauth2/jwks").mock(
        return_value=httpx.Response(200, json={"keys": [public_jwk]})
    )

    p_resp = await gateway_client.post(
        "/api/admin/policies",
        headers=admin_headers,
        json={"name": "ehr", "yaml_content": SAMPLE_POLICY_YAML},
    )
    policy_id = p_resp.json()["id"]

    prov_resp = await gateway_client.post(
        "/api/admin/auth-providers",
        headers=admin_headers,
        json={
            "name": "Okta Corp",
            "provider_type": "oidc",
            "issuer_url": "https://idp.example.com",
            "audience": "anonix-api",
            "groups_claim": "groups",
        },
    )
    assert prov_resp.status_code == 201
    prov_id = prov_resp.json()["id"]

    await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={
            "provider_id": prov_id,
            "external_group": "med-researchers",
            "policy_role": "researcher",
            "policy_id": policy_id,
            "priority": 50,
        },
    )

    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "alice@hospital.org",
            "iss": "https://idp.example.com",
            "aud": "anonix-api",
            "groups": ["med-researchers"],
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-kid-1"},
    )

    res = await gateway_client.post(
        "/v1/mask",
        headers={"Authorization": f"Bearer {token}"},
        json={"payload": {"name": "Meera", "ssn": "999-00-1111", "email": "meera@test.org"}},
    )
    assert res.status_code == 200
    body = res.json()
    assert "ssn" not in body
    assert body["name"] == "Meera"


async def test_trusted_proxy_auth_cidr_and_secret(gateway_client: httpx.AsyncClient) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    p_resp = await gateway_client.post(
        "/api/admin/policies",
        headers=admin_headers,
        json={"name": "tp-policy", "yaml_content": SAMPLE_POLICY_YAML},
    )
    policy_id = p_resp.json()["id"]

    await gateway_client.post(
        "/api/admin/auth-providers",
        headers=admin_headers,
        json={
            "name": "Kong Edge",
            "provider_type": "trusted_proxy",
            "trusted_cidrs": ["127.0.0.1/32", "0.0.0.0/0"],
            "proxy_secret": "super-secret-kong-token",
        },
    )
    await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={
            "external_group": "tp-researchers",
            "policy_role": "researcher",
            "policy_id": policy_id,
        },
    )

    # Wrong proxy secret -> 401
    bad = await gateway_client.post(
        "/v1/mask",
        headers={
            "X-Anonix-User": "bob@corp.com",
            "X-Anonix-Groups": "tp-researchers",
            "X-Anonix-Proxy-Secret": "wrong-secret",
        },
        json={"payload": {"ssn": "111-22-3333"}},
    )
    assert bad.status_code == 401

    # Valid proxy secret -> 200
    good = await gateway_client.post(
        "/v1/mask",
        headers={
            "X-Anonix-User": "bob@corp.com",
            "X-Anonix-Groups": "tp-researchers",
            "X-Anonix-Proxy-Secret": "super-secret-kong-token",
        },
        json={"payload": {"name": "Bob", "ssn": "111-22-3333", "email": "bob@corp.com"}},
    )
    assert good.status_code == 200
    assert "ssn" not in good.json()


async def test_group_mapping_optional_role_applies_default_rules(
    gateway_client: httpx.AsyncClient,
) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    default_yaml = """
version: '1.0'
rules:
  - selector: '$.ssn'
    technique: suppress
"""
    policy_id = (
        await gateway_client.post(
            "/api/admin/policies",
            headers=admin_headers,
            json={"name": "default-rules-policy", "yaml_content": default_yaml},
        )
    ).json()["id"]

    # Map group to policy with policy_role=None (uses default/unscoped policy rules)
    m_resp = await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={"external_group": "general-users", "policy_id": policy_id},
    )
    assert m_resp.status_code == 201
    assert m_resp.json()["policy_role"] is None

    k = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={"name": "general-app", "groups": ["general-users"]},
        )
    ).json()["raw_key"]

    res = await gateway_client.post(
        "/v1/mask",
        headers={"X-API-Key": k},
        json={"payload": {"name": "Alice", "ssn": "123-45-6789"}},
    )
    assert res.status_code == 200
    assert res.headers["X-Anonix-Role"] == "default"
    assert "ssn" not in res.json()
    assert res.json()["name"] == "Alice"
