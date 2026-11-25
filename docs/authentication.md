# Authentication & Authorization Guide

Anonix Gateway keeps **Control Plane auth** (admins managing Anonix) strictly separate from **Data Plane auth** (apps and users requesting masked data).

---

## 1. Inbound Caller Authentication (Data Plane)

Organizations can enable **any 1, 2, or all 3** modes simultaneously in the **AUTH** and **KEYS** tabs:

### Mode A: OIDC / JWT (Okta, Google, Microsoft Entra ID, Keycloak, Auth0)
1. In **AUTH → Add Auth Provider**, select **OIDC / JWT**.
2. Enter:
   * **Issuer URL** (e.g. `https://acme.okta.com/oauth2/default` or `https://accounts.google.com`)
   * **JWKS URL** *(optional; auto-discovered from `/.well-known/openid-configuration` if omitted)*
   * **Audience** *(optional; recommended in production to prevent cross-app token reuse)*
   * **Groups / Identity Claim** *(default: `groups`; use `roles`, `cognito:groups`, `email`, or `hd` as needed)*
   * **User ID Claim** *(default: `sub`; used for audit logs and rate limiting)*
3. Callers send `Authorization: Bearer <jwt>`.

### Mode B: API Keys (Services, Scripts, CI/ETL Pipelines)
1. In **KEYS → Create API Key**, specify:
   * **Key Name**
   * **Assigned Groups** (comma-separated, matched against `Group Mappings`)
   * **Allowed Policies** *(optional; restricts which policies this key can invoke)*
   * **Expiration Date** *(optional)*
2. Copy the generated `axk_...` key (shown once).
3. Callers send `X-API-Key: axk_...` (or `Authorization: Bearer axk_...`).

### Mode C: Trusted-Proxy Headers (Behind NGINX / Kong / AWS ALB)
Use this when your existing edge gateway already authenticates users and sits in front of Anonix:
1. In **AUTH → Add Auth Provider**, select **Trusted-Proxy Headers**.
2. Configure **Allowed Proxy Server IPs / CIDRs** (e.g. `10.0.0.0/8`) and a **Shared Secret**.
3. Configure your edge proxy to overwrite any client-supplied `X-Anonix-*` headers and set:
   ```nginx
   proxy_set_header X-Anonix-User         $authenticated_user;
   proxy_set_header X-Anonix-Groups       $authenticated_groups;
   proxy_set_header X-Anonix-Proxy-Secret "your-shared-secret";
   ```

---

## 2. Group Mapping & Role Resolution

* Every `GroupMapping` binds `(external_group) -> (policy_id, optional policy_role, priority)`.
* **Required Policy:** Every group mapping must reference a `MaskingPolicy`.
* **Optional Role:** If `policy_role` is specified, `anonix` applies rules for that role; if left blank, `anonix` applies the policy's unscoped/default rules.
* **Priority:** When a caller belongs to multiple mapped groups, the mapping with the highest `priority` integer wins.
* **Fail-Closed:** Callers with no matching `GroupMapping`—or mapped only to a different policy than the target route/request—receive `403 Forbidden`.
