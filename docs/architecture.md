# Architecture & Security Model

Anonix Gateway separates **administration (Control Plane)** from **runtime masking traffic (Data Plane)** and enforces **fail-closed** behavior at every boundary.

---

## 1. Core Design Principles

1. **Zero-PII Persistence:** Anonix Gateway never writes raw or masked payload fields to disk, database tables, or logs. All masking occurs strictly in RAM via `anonix.MaskingEngine`.
2. **No Hardcoded Policies or Magic Roles:** Every masking rule comes from explicit `MaskingPolicy` YAML stored in the database. No built-in default policy or privileged role name exists.
3. **Fail-Closed Everywhere:**
   * Missing or invalid caller credentials $\rightarrow$ `401 Unauthorized`.
   * Unmapped groups or cross-policy access $\rightarrow$ `403 Forbidden`.
   * Masking failure or unstructured upstream response (`on_unstructured=fail_closed`) $\rightarrow$ raw payload dropped, returns `502 Bad Gateway`.
4. **No Hardcoded Secrets or Passwords:** Initial `platform_admin` accounts are created via first-run `/setup`, `anonix-gateway init`, or explicit bootstrap environment variables.

---

## 2. Three Security Planes

### Plane 1: Control Plane (`/api/setup/*`, `/api/admin/*`, Web Console)
* **Authentication:** Local `AdminUser` accounts hashed with Argon2id, issuing HS256 session JWTs signed with `ANONIX_ADMIN_JWT_SECRET`.
* **RBAC Roles:**
  * `platform_admin`: Full access (Admin Users, Auth Providers, Group Mappings, API Keys, Upstreams, Proxy Routes, Policies, Audit Logs). Self-lockout and last-admin deletion protections are enforced.
  * `policy_author`: Create/edit/version/activate/delete `MaskingPolicy`s, run the Live Playground, view `GroupMapping`s.
  * `auditor`: Read-only access to Policies and Zero-PII `AuditEvent` logs.

### Plane 2: Data Plane — Inbound (`/proxy/{prefix}/*` and `POST /v1/mask`)
1. **Caller Authentication:** Supports OIDC/JWT, API Keys, and Trusted-Proxy headers simultaneously (`authenticate_caller`).
2. **Group $\rightarrow$ Policy + Role Resolution:**
   * Every `GroupMapping` binds `(external_group) -> (policy_id, optional policy_role, priority)`.
   * **`policy_id` is required** on every `GroupMapping`; `policy_role` is optional (`None` applies the policy's unscoped/default rules).
   * **On `/proxy/*`:** Matches longest active `ProxyRoute` prefix, enforces `allowed_methods` (`405`) and `blocked_subpaths` (`403`), and verifies the caller has a `GroupMapping` matching `route.policy_id` (unless `allow_policy_override` is enabled). Enforces `ApiKey.allowed_policy_ids` if set.
   * **On `POST /v1/mask`:** If `"policy"` is provided (header or JSON envelope), verifies the caller's groups map to that policy (`403` otherwise); if omitted, selects the highest-priority `GroupMapping.policy_id`.

### Plane 3: Data Plane — Outbound (`/proxy/{prefix}/*` only)
* **SSRF Protection:** `validate_upstream_url` blocks link-local/metadata IPs (`169.254.169.254`, `metadata.google.internal`) unconditionally and blocks private/loopback networks unless `ANONIX_ALLOW_PRIVATE_UPSTREAMS=true` is explicitly configured for internal VPC upstreams.
* **Header Isolation:** Strips hop-by-hop headers and inbound caller credentials (`Authorization`, `X-API-Key`, `X-Anonix-*`) before forwarding to the upstream.
* **Encrypted Upstream Credentials:** Optional outbound `bearer`, `api_key_header`, or `basic` credentials are encrypted at rest with Fernet (`ANONIX_MASTER_KEY`) and decrypted in memory only when calling the upstream.

---

## 3. Database & Caching

* **Gateway Database (Zero Business PII):** Stores `Tenant`, `AdminUser`, `AuthProvider`, `MaskingPolicy`, `PolicyVersion`, `GroupMapping`, `ApiKey`, `Upstream`, `ProxyRoute`, and `AuditEvent`.
* **Tenancy:** Defaults to `ANONIX_TENANCY_MODE=single_org` (`default` tenant), while retaining `tenant_id` across all tables so `multi_tenant` (`X-Anonix-Tenant`) can be enabled without schema migration.
* **Rate Limiting:** Fixed-window per-minute quota backed by Redis (`ANONIX_REDIS_URL`) for multi-replica deployments, automatically falling back to an in-memory store when Redis is omitted.
