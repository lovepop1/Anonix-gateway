# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `anonix-gateway`, please do **not** open a public GitHub issue.
Instead, report it privately to the maintainers with:

- A clear description of the vulnerability and affected component
- Steps or a minimal proof-of-concept to reproduce the issue
- Potential impact (e.g., auth bypass, SSRF, PII leakage)

## Security Design Guarantees

- **Fail-closed defaults:** Missing or invalid authentication (`401`), unresolved authorization (`403`), or masking failures (`502`) never pass raw payloads through.
- **Zero-PII persistence:** `anonix-gateway` never stores raw or masked request/response payloads in its database or audit logs.
- **No hardcoded credentials:** All master encryption keys, admin JWT secrets, and initial admin accounts are generated or configured per deployment.
- **SSRF protection:** Upstream targets are validated against configurable private/metadata network policies before outbound forwarding.
