# 5-Minute Live Demo Guide

This guide walks through demonstrating **Anonix Gateway** end-to-end—either via the automated script or interactively in a browser.

---

## 1. Automated End-to-End Proof (30 Seconds)

Runs both the mock upstream server and Anonix Gateway, bootstraps an admin, creates a policy, maps two roles (`researcher` and `advisor`), tests `/proxy/*` and `/v1/mask`, verifies `401` on unauthenticated calls, and asserts zero PII in the audit log:

```powershell
.\.venv\Scripts\python.exe scripts\demo_walkthrough.py
```

---

## 2. Interactive Browser & Terminal Demo

### Start Both Servers Locally
*(If port `8080` or `8000` is reserved on Windows by Hyper-V/WSL2, use `9080` and `9000`.)*

* **Terminal 1 (Mock Enterprise Backend):**
  ```powershell
  .\.venv\Scripts\python.exe -m uvicorn app:app --app-dir demo_upstream --port 9080
  ```
* **Terminal 2 (Anonix Gateway + Web Console):**
  ```powershell
  $env:ANONIX_ALLOW_PRIVATE_UPSTREAMS="true"
  .\.venv\Scripts\anonix-gateway.exe serve --port 9000
  ```

### Step-by-Step Walkthrough (`http://localhost:9000`)

1. **First-Run Setup:** Create your organization name and `platform_admin` account.
2. **Create Policy (`POLICIES` tab):**
   * Name: `student-policy`
   * YAML:
     ```yaml
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
       - selector: '$.fee_balance'
         technique: suppress
         roles:
           - advisor
     ```
   * Click **Test Masking** in the Live Playground to preview output immediately.
3. **Create Group Mappings (`MAPPINGS` tab):**
   * `research-team` $\rightarrow$ Policy `student-policy`, Role `researcher`
   * `advisors-team` $\rightarrow$ Policy `student-policy`, Role `advisor`
4. **Generate Two API Keys (`KEYS` tab):**
   * `researcher-app` with group `research-team`
   * `advisor-app` with group `advisors-team`
5. **Register Upstream & Route (`UPSTREAMS` & `ROUTES` tabs):**
   * Upstream: `sis-api`, Base URL `http://127.0.0.1:9080`, Outbound Auth `None`
   * Route: Prefix `/students`, Upstream `sis-api`, Policy `student-policy`, **uncheck** *Strip prefix* (because `demo_upstream` serves `/students/{id}`).
6. **Compare Raw vs. Role-Masked Responses:**
   * **Raw internal API:** `curl http://127.0.0.1:9080/students/101` *(returns `ssn`, `email`, `fee_balance`)*
   * **Unauthenticated gateway call:** `curl http://localhost:9000/proxy/students/101` *(`401 Unauthorized`)*
   * **Researcher:** `curl -H "X-API-Key: <RESEARCHER_KEY>" http://localhost:9000/proxy/students/101` *(`ssn` removed, `email` redacted)*
   * **Advisor:** `curl -H "X-API-Key: <ADVISOR_KEY>" http://localhost:9000/proxy/students/101` *(`fee_balance` removed, `ssn` & `email` visible)*
   * **Direct `/v1/mask`:** Send raw JSON directly to `POST http://localhost:9000/v1/mask`.
7. **Inspect `AUDIT` Tab:** Show request metadata (caller, auth method, role, status, latency) with **zero PII stored**.
