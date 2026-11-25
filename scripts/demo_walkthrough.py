"""Self-contained live end-to-end verification & demo walkthrough for Anonix Gateway."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

import httpx

DEMO_POLICY_YAML = """version: '1.0'
rules:
  - selector: '$.ssn'
    technique: suppress
    roles:
      - researcher
  - selector: '$.email'
    technique: redact
    roles:
      - researcher
  - selector: '$.fee_balance'
    technique: suppress
    roles:
      - advisor
"""


def main() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        env = os.environ.copy()
        env["ANONIX_DATA_DIR"] = tmp
        env["ANONIX_DATABASE_URL"] = f"sqlite+aiosqlite:///{tmp}/live.db"
        env["ANONIX_ALLOW_PRIVATE_UPSTREAMS"] = "true"

        up = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "18080"],
            cwd="demo_upstream",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        gw = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "anonix_gateway.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "18000",
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(40):
                try:
                    if (
                        httpx.get("http://127.0.0.1:18000/healthz").status_code == 200
                        and httpx.get("http://127.0.0.1:18080/healthz").status_code == 200
                    ):
                        break
                except Exception:
                    time.sleep(0.25)

            c = httpx.Client(base_url="http://127.0.0.1:18000", timeout=10)
            ui_html = c.get("/").text
            print("1. Web Console served:", "Anonix Gateway" in ui_html)

            raw = httpx.get("http://127.0.0.1:18080/students/101").json()
            print("2. Raw Upstream (/students/101):", json.dumps(raw))

            boot = c.post(
                "/api/setup/bootstrap",
                json={
                    "org_name": "Demo University",
                    "admin_email": "admin@uni.edu",
                    "admin_password": "Password123!",
                },
            )
            boot.raise_for_status()
            hdr = {"Authorization": f"Bearer {boot.json()['access_token']}"}
            print("3. Bootstrapped admin:", boot.json()["email"])

            pol = c.post(
                "/api/admin/policies",
                headers=hdr,
                json={"name": "student-policy", "yaml_content": DEMO_POLICY_YAML},
            )
            pol.raise_for_status()
            pol_id = pol.json()["id"]

            c.post(
                "/api/admin/group-mappings",
                headers=hdr,
                json={
                    "external_group": "research-team",
                    "policy_role": "researcher",
                    "policy_id": pol_id,
                },
            ).raise_for_status()
            c.post(
                "/api/admin/group-mappings",
                headers=hdr,
                json={
                    "external_group": "advisors-team",
                    "policy_role": "advisor",
                    "policy_id": pol_id,
                },
            ).raise_for_status()

            k_res = c.post(
                "/api/admin/api-keys",
                headers=hdr,
                json={"name": "researcher-app", "groups": ["research-team"]},
            ).json()["raw_key"]
            k_adv = c.post(
                "/api/admin/api-keys",
                headers=hdr,
                json={"name": "advisor-app", "groups": ["advisors-team"]},
            ).json()["raw_key"]

            up_id = c.post(
                "/api/admin/upstreams",
                headers=hdr,
                json={"name": "sis", "base_url": "http://127.0.0.1:18080"},
            ).json()["id"]
            c.post(
                "/api/admin/routes",
                headers=hdr,
                json={
                    "name": "students",
                    "route_prefix": "/students",
                    "upstream_id": up_id,
                    "policy_id": pol_id,
                    "strip_prefix": False,
                },
            ).raise_for_status()

            unauth = c.get("/proxy/students/101")
            print("4. Unauthenticated /proxy/students/101:", unauth.status_code)

            res_proxy = c.get("/proxy/students/101", headers={"X-API-Key": k_res}).json()
            print("5. Researcher via /proxy/students/101:", json.dumps(res_proxy))

            adv_proxy = c.get("/proxy/students/101", headers={"X-API-Key": k_adv}).json()
            print("6. Advisor via /proxy/students/101:   ", json.dumps(adv_proxy))

            direct = c.post(
                "/v1/mask",
                headers={"X-API-Key": k_res},
                json={"policy": "student-policy", "payload": raw},
            ).json()
            print("7. Direct POST /v1/mask (researcher):", json.dumps(direct))

            audits = c.get("/api/admin/audit", headers=hdr).json()
            print(
                "8. Zero-PII Audit Log entries:",
                len(audits),
                "roles:",
                [a["resolved_role"] for a in audits],
            )
            audit_text = json.dumps(audits)
            assert "123-45-6789" not in audit_text
            assert "aarav.sharma@university.edu" not in audit_text
            print("9. Zero-PII check passed!")
        finally:
            gw.terminate()
            up.terminate()
            gw.wait(timeout=5)
            up.wait(timeout=5)


if __name__ == "__main__":
    main()
