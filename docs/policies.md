# Policy Authoring & `anonix` Reference

Anonix Gateway delegates all in-memory data masking to the open-source [`anonix`](https://pypi.org/project/anonix/) engine (`MaskingPolicy` + `MaskingEngine`). Every transformation is declarative: policies are authored in YAML, strictly validated when saved or activated, and compiled into an in-memory LRU cache inside the gateway.

There are **no built-in magic roles or hidden default rules**—only what you declare in your policy.

---

## 1. Anatomy of a `MaskingPolicy`

A policy is a YAML document validated against `anonix.policy.MaskingPolicy`:

```yaml
version: '1.0'
name: customer-pii-policy
description: Masks sensitive customer identifiers by caller role.

# Optional: 'json', 'xml', 'yaml', or 'csv' (enables load-time selector validation)
# format: json

# What happens to fields NOT matched by any rule:
#   preserve (default) | redact | nullify | suppress
unmatched_fields: preserve
unmatched_replacement: '[REDACTED]'

# What happens when a technique encounters an incompatible value (e.g. noise on a string):
#   raise (default, fail-closed) | preserve | redact | nullify
on_error: raise

# Top-level rules evaluated across the payload
rules:
  - id: mask-ssn
    description: Remove SSN completely for external partners
    selector: '$.ssn'
    technique: suppress
    roles:
      - partner
      - analyst

  - id: mask-email
    selector: '$.email'
    technique: mask_pattern
    params:
      pattern: '{first1}***@{domain}'
    roles:
      - partner
```

### Top-Level Fields

| Field | Default | Description |
| :--- | :--- | :--- |
| `version` | `'1.0'` | Policy schema version (`'1.0'` or `'3.0'`). |
| `name` | `null` | Human-readable policy name (informational). |
| `description` | `null` | Summary of purpose and compliance scope. |
| `format` | `null` | Optional `'json'`, `'xml'`, `'yaml'`, or `'csv'` for strict load-time selector validation. |
| `unmatched_fields` | `'preserve'` | Action on scalar leaf fields not matched by any rule: `preserve`, `redact`, `nullify`, `suppress`. |
| `unmatched_replacement` | `'[REDACTED]'` | Replacement string when `unmatched_fields: redact`. |
| `on_error` | `'raise'` | Error policy on type/value mismatch: `raise` (fail-closed `502`), `preserve`, `redact`, `nullify`. |
| `record_root` | `'$'` | Selector identifying individual records for `k_anonymity` (e.g. `'$.patients[*]'`). |
| `rules` | `[]` | List of `MaskingRule` objects. |
| `roles` | `{}` | Optional role definitions (`dict[str, RoleDefinition]`). |
| `profiles` | `{}` | Reusable named rule bundles referenced by `scopes`. |
| `scopes` | `[]` | Subtree-level governance rules (`ScopeRule`) with per-role strategies (`masked`, `passthrough`, `drop_subtree`, `deep_redact`, `synthesize`). |
| `k_anonymity` | `null` | Optional record-level k-anonymity verification/enforcement (`verify`, `enforce`, `suppress`). |

---

## 2. Selectors by Payload Format

| Format | Selector Syntax | Examples |
| :--- | :--- | :--- |
| **JSON / YAML** | JSONPath | `$.ssn`, `$.user.email`, `$.patients[*].dob`, `$..password` |
| **CSV** | JSONPath (row objects) | `$.email`, `$[*].ssn` |
| **XML** | XPath | `//patient/ssn`, `//user/email`, `//account/@number` |

> **Tip:** If a policy will be applied to both JSON and XML endpoints, omit the top-level `format` field or create format-specific policies.

---

## 3. Built-in `anonix` Masking Techniques

Every rule specifies a `technique` and optional `params` (parameters may be nested under `params:` or placed inline on the rule):

| Technique | Purpose | Key Parameters & Defaults |
| :--- | :--- | :--- |
| `redact` | Replace value with a static string | `replacement: '[REDACTED]'`, `preserve_null: false` |
| `suppress` | Remove the field/element completely from output | *(no required params)* |
| `nullify` | Set the field value to `null` / empty | *(no required params)* |
| `mask_pattern` | Template-based partial reveal | `pattern` (required) supporting `{first1}`..`{first4}`, `{last2}`, `{last4}`, `{digits_last4}`, `{domain}`; `preserve_null: true` |
| `pseudonymize` | Keyed HMAC-SHA256 or random hex token | `consistent: true`, `prefix: 'ANON_'`, `token_length: 16` (4–64), `salt: null`, `preserve_null: true` |
| `generalize` | Coarsen values via registered hierarchy | `hierarchy` (required, e.g. `'date'`, `'zipcode'`, `'age'`), `level: 1`, `preserve_null: true` |
| `noise` | Bounded multiplicative numeric perturbation | `percentage: 10.0` (0–100), `precision: 2` (0–10), `preserve_null: true` |
| `format_preserve` | Scramble digits/letters in-class, keep punctuation | `deterministic: false`, `preserve_prefix: 0`, `preserve_suffix: 0`, `preserve_null: true` |
| `synthesize` | Generate synthetic replacement values | `preserve_null: true` *(and type-appropriate synthesis options)* |
| `deep_redact` | Recursively redact all leaf scalars in a subtree | `replacement: '[REDACTED]'` |

### Technique Examples

```yaml
version: '1.0'
rules:
  # 1. Partial email reveal -> "a***@university.edu"
  - selector: '$.email'
    technique: mask_pattern
    params:
      pattern: '{first1}***@{domain}'

  # 2. Deterministic HMAC pseudonym -> "PAT_9f8a1b2c3d4e5f6a" (preserves joins across calls)
  - selector: '$.patient_id'
    technique: pseudonymize
    params:
      consistent: true
      prefix: 'PAT_'
      token_length: 16

  # 3. Format-preserving phone/SSN -> "555-829-6789" (keeps dashes & last 4)
  - selector: '$.ssn'
    technique: format_preserve
    params:
      deterministic: true
      preserve_suffix: 4

  # 4. Numeric noise on salary (±15%)
  - selector: '$.salary'
    technique: noise
    params:
      percentage: 15.0
      precision: 0
```

---

## 4. Role-Based Masking & Gateway Group Mappings

In `anonix`, a single policy can produce different outputs depending on the **role** passed at execution time:

1. **Unscoped rule** (no `roles:` list on the rule) $\rightarrow$ applies to **every** caller using that policy.
2. **Scoped rule** (`roles: [researcher, billing]`) $\rightarrow$ applies **only** when the caller resolves to one of those roles.
3. **Subtree `scopes`** $\rightarrow$ can apply `passthrough`, `drop_subtree`, `deep_redact`, `synthesize`, or `masked` per role on an entire nested object/array.

### How Anonix Gateway Resolves `(Policy + Role)`

1. Caller authenticates via **OIDC/JWT**, **API Key**, or **Trusted-Proxy Headers**, yielding one or more group strings (e.g. `["research-team"]`).
2. Gateway looks up **Group Mappings** (`MAPPINGS` tab in the Admin Console):
   ```text
   external_group ("research-team")  -->  policy_id ("student-policy")  +  policy_role ("researcher")  +  priority (10)
   ```
3. If the caller has multiple mapped groups, the **highest `priority` integer** wins.
4. If the caller has **no** matching `GroupMapping` (or maps only to a different policy than the target `/proxy/*` route or requested `X-Anonix-Policy`), the gateway **fails closed with `403 Forbidden`**.
5. Gateway runs `MaskingEngine(policy).mask(..., role=resolved_role)` strictly in RAM and returns the masked payload with response headers:
   * `X-Anonix-Policy`
   * `X-Anonix-Policy-Version`
   * `X-Anonix-Role`
   * `X-Anonix-Request-ID`

---

## 5. Policy Versioning, Activation & Live Playground

In the Web Admin Console (**POLICIES** tab) or via `/api/admin/policies`:
* Every policy maintains immutable numbered versions (`v1`, `v2`, `v3`, ...).
* **Live Playground (`POST /api/admin/policies/playground`):** Test draft YAML against sample `JSON`, `XML`, `YAML`, or `CSV` payloads and preview any role before saving or activating.
* **Activation & Rollback:** Only **one** version per policy is active at a time. Activating a new (or previous) version immediately invalidates the gateway's in-memory `MaskingEngine` cache for that policy with zero downtime.
