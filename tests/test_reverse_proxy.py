"""Tests for SSRF protection and fail-closed reverse-proxy masking."""

from __future__ import annotations

import httpx
import pytest
import respx
from tests.conftest import bootstrap_admin

from anonix_gateway.proxy.ssrf import validate_upstream_url

PROXY_POLICY_YAML = """
version: '1.0'
rules:
  - selector: '$.ssn'
    technique: suppress
    roles:
      - advisor
  - selector: '$.fee_balance'
    technique: redact
    roles:
      - advisor
"""


def test_ssrf_blocks_metadata_and_private_when_disallowed() -> None:
    with pytest.raises(ValueError, match="SSRF"):
        validate_upstream_url("http://169.254.169.254/latest/meta-data", allow_private=False)

    with pytest.raises(ValueError, match="SSRF"):
        validate_upstream_url("http://169.254.169.254/latest/meta-data", allow_private=True)

    with pytest.raises(ValueError, match="SSRF"):
        validate_upstream_url("http://10.0.0.5:8080", allow_private=False)

    assert (
        validate_upstream_url("http://10.0.0.5:8080/", allow_private=True) == "http://10.0.0.5:8080"
    )


@respx.mock
async def test_reverse_proxy_end_to_end_and_fail_closed(
    gateway_client: httpx.AsyncClient,
) -> None:
    admin_headers = await bootstrap_admin(gateway_client)

    policy_id = (
        await gateway_client.post(
            "/api/admin/policies",
            headers=admin_headers,
            json={"name": "student-policy", "yaml_content": PROXY_POLICY_YAML},
        )
    ).json()["id"]

    await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={"external_group": "advisors", "policy_role": "advisor", "policy_id": policy_id},
    )
    api_key = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={"name": "portal-app", "groups": ["advisors"]},
        )
    ).json()["raw_key"]

    upstream_id = (
        await gateway_client.post(
            "/api/admin/upstreams",
            headers=admin_headers,
            json={
                "name": "sis-internal",
                "base_url": "http://sis.internal:8080",
                "auth_type": "bearer",
                "credential": "internal-service-secret",
            },
        )
    ).json()["id"]

    route_resp = await gateway_client.post(
        "/api/admin/routes",
        headers=admin_headers,
        json={
            "name": "students-route",
            "route_prefix": "/students",
            "upstream_id": upstream_id,
            "policy_id": policy_id,
            "allowed_methods": ["GET"],
            "blocked_subpaths": ["/internal/*"],
            "on_unstructured": "fail_closed",
        },
    )
    assert route_resp.status_code == 201

    # Mock upstream student endpoint
    upstream_route = respx.get("http://sis.internal:8080/101").mock(
        return_value=httpx.Response(
            200,
            json={"name": "Aarav", "ssn": "123-45-6789", "fee_balance": "5000", "gpa": 3.9},
        )
    )

    resp = await gateway_client.get(
        "/proxy/students/101",
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 200
    assert upstream_route.called
    sent_headers = upstream_route.calls.last.request.headers
    assert sent_headers["authorization"] == "Bearer internal-service-secret"
    assert "x-api-key" not in sent_headers

    data = resp.json()
    assert "ssn" not in data
    assert data["fee_balance"] != "5000"
    assert data["gpa"] == 3.9

    # Blocked subpath -> 403
    blocked = await gateway_client.get(
        "/proxy/students/internal/debug",
        headers={"X-API-Key": api_key},
    )
    assert blocked.status_code == 403

    # Disallowed method -> 405
    method_405 = await gateway_client.delete(
        "/proxy/students/101",
        headers={"X-API-Key": api_key},
    )
    assert method_405.status_code == 405

    # Unstructured HTML response -> 502 fail-closed
    respx.get("http://sis.internal:8080/html-leak").mock(
        return_value=httpx.Response(
            200,
            text="<html>raw secret leak</html>",
            headers={"Content-Type": "text/html"},
        )
    )
    html_502 = await gateway_client.get(
        "/proxy/students/html-leak",
        headers={"X-API-Key": api_key},
    )
    assert html_502.status_code == 502
    assert "raw secret leak" not in html_502.text

    # Corrupt JSON response -> 502 fail-closed
    respx.get("http://sis.internal:8080/corrupt").mock(
        return_value=httpx.Response(
            200, content=b"{not-valid-json", headers={"Content-Type": "application/json"}
        )
    )
    corrupt_502 = await gateway_client.get(
        "/proxy/students/corrupt",
        headers={"X-API-Key": api_key},
    )
    assert corrupt_502.status_code == 502

    # Group mapped to a DIFFERENT policy cannot access /proxy/students -> 403
    billing_pol_id = (
        await gateway_client.post(
            "/api/admin/policies",
            headers=admin_headers,
            json={"name": "billing-policy", "yaml_content": PROXY_POLICY_YAML},
        )
    ).json()["id"]
    await gateway_client.post(
        "/api/admin/group-mappings",
        headers=admin_headers,
        json={
            "external_group": "billing-only",
            "policy_role": "advisor",
            "policy_id": billing_pol_id,
        },
    )
    k_billing = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={"name": "billing-app", "groups": ["billing-only"]},
        )
    ).json()["raw_key"]
    cross_403 = await gateway_client.get(
        "/proxy/students/101",
        headers={"X-API-Key": k_billing},
    )
    assert cross_403.status_code == 403

    # Restricted API key (allowed only billing-policy) cannot access /proxy/students -> 403
    k_restricted = (
        await gateway_client.post(
            "/api/admin/api-keys",
            headers=admin_headers,
            json={
                "name": "restricted-app",
                "groups": ["advisors"],
                "allowed_policy_ids": [billing_pol_id],
            },
        )
    ).json()["raw_key"]
    restricted_403 = await gateway_client.get(
        "/proxy/students/101",
        headers={"X-API-Key": k_restricted},
    )
    assert restricted_403.status_code == 403
