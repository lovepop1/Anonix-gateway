# API Reference

## Health & Readiness

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | None | Liveness probe (`{"status":"ok","version":"0.1.0"}`) |
| `GET` | `/readyz` | None | Readiness probe verifying database connectivity |

---

## First-Run Setup & Admin Login

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/setup/status` | None | Returns `{"bootstrapped": bool, "tenancy_mode": str}` |
| `POST` | `/api/setup/bootstrap` | None (one-time) | Creates initial org and `platform_admin` (`409` if already bootstrapped) |
| `POST` | `/api/admin/login` | None | Authenticates local admin and returns HS256 Bearer JWT |

---

## Data Plane: Direct Masking (`POST /v1/mask`)

Masks an in-memory `JSON`, `XML`, `YAML`, or `CSV` payload. Requires caller auth (`X-API-Key`, `Authorization: Bearer`, or Trusted-Proxy headers).

### JSON Envelope Example
```bash
curl -X POST http://localhost:8000/v1/mask \
  -H "X-API-Key: axk_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "pii-masking-policy",
    "format": "json",
    "payload": {
      "name": "Jane Doe",
      "email": "jane.doe@example.com",
      "ssn": "123-45-6789"
    }
  }'
```

### Raw Payload + Header Example (XML / CSV / YAML)
```bash
curl -X POST http://localhost:8000/v1/mask \
  -H "X-API-Key: axk_your_key_here" \
  -H "X-Anonix-Policy: pii-masking-policy" \
  -H "Content-Type: application/xml" \
  -d '<patient><name>Jane Doe</name><ssn>123-45-6789</ssn></patient>'
```

Response headers include `X-Anonix-Request-ID`, `X-Anonix-Role`, `X-Anonix-Policy`, and `X-Anonix-Policy-Version`.

---

## Data Plane: Reverse Proxy (`/proxy/{prefix}/*`)

Forwards requests matching the longest active `ProxyRoute` prefix to the configured `Upstream`, masks the upstream response in memory using `anonix`, and returns the masked response.

```bash
curl http://localhost:8000/proxy/students/101 \
  -H "X-API-Key: axk_your_key_here"
```

---

## Control Plane (`/api/admin/*`)

All `/api/admin/*` endpoints require `Authorization: Bearer <admin_jwt>`.

* **Policies:** `GET/POST /api/admin/policies`, `POST /api/admin/policies/{id}/versions`, `POST /api/admin/policies/{id}/versions/{ver}/activate`, `DELETE /api/admin/policies/{id}`, `POST /api/admin/policies/playground`
* **Auth Providers:** `GET/POST /api/admin/auth-providers`, `PATCH/DELETE /api/admin/auth-providers/{id}`
* **Group Mappings:** `GET/POST /api/admin/group-mappings`, `PATCH/DELETE /api/admin/group-mappings/{id}`
* **API Keys:** `GET/POST /api/admin/api-keys`, `PATCH/DELETE /api/admin/api-keys/{id}`, `POST /api/admin/api-keys/{id}/revoke`
* **Upstreams:** `GET/POST /api/admin/upstreams`, `PATCH/DELETE /api/admin/upstreams/{id}`
* **Proxy Routes:** `GET/POST /api/admin/routes`, `PATCH/DELETE /api/admin/routes/{id}`
* **Admin Users:** `GET/POST /api/admin/users`, `PATCH/DELETE /api/admin/users/{id}`
* **Audit Logs:** `GET /api/admin/audit?limit=50`
