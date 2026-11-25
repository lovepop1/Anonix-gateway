import React, { useEffect, useState } from "react";

type Tab = "policies" | "auth" | "mappings" | "keys" | "upstreams" | "routes" | "users" | "audit";

const DEFAULT_YAML = `version: '1.0'
rules:
  - selector: '$.ssn'
    technique: suppress
    roles:
      - analyst
  - selector: '$.email'
    technique: redact
    roles:
      - analyst`;

const SAMPLE_PAYLOAD = `{
  "id": "usr_1042",
  "name": "Jane Doe",
  "email": "jane.doe@example.com",
  "ssn": "123-45-6789",
  "department": "Engineering"
}`;

export default function App() {
  const [bootstrapped, setBootstrapped] = useState<boolean | null>(null);
  const [token, setToken] = useState<string>(() => localStorage.getItem("anonix_admin_token") || "");
  const [adminEmail, setAdminEmail] = useState<string>(() => localStorage.getItem("anonix_admin_email") || "");
  const [tab, setTab] = useState<Tab>("policies");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  // Setup & Login form state
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Data collections
  const [policies, setPolicies] = useState<any[]>([]);
  const [providers, setProviders] = useState<any[]>([]);
  const [mappings, setMappings] = useState<any[]>([]);
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [upstreams, setUpstreams] = useState<any[]>([]);
  const [routes, setRoutes] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [audits, setAudits] = useState<any[]>([]);

  // Policies form + playground state
  const [editPolId, setEditPolId] = useState<string | null>(null);
  const [polName, setPolName] = useState("");
  const [polDesc, setPolDesc] = useState("");
  const [polYaml, setPolYaml] = useState(DEFAULT_YAML);
  const [playPayload, setPlayPayload] = useState(SAMPLE_PAYLOAD);
  const [playFormat, setPlayFormat] = useState("json");
  const [playRole, setPlayRole] = useState("analyst");
  const [playOut, setPlayOut] = useState("");

  // Auth providers form + edit state
  const [editProvId, setEditProvId] = useState<string | null>(null);
  const [provName, setProvName] = useState("");
  const [provType, setProvType] = useState("oidc");
  const [issuerUrl, setIssuerUrl] = useState("");
  const [jwksUrl, setJwksUrl] = useState("");
  const [audience, setAudience] = useState("");
  const [groupsClaim, setGroupsClaim] = useState("groups");
  const [subClaim, setSubClaim] = useState("sub");
  const [trustedCidrs, setTrustedCidrs] = useState("");
  const [proxySecret, setProxySecret] = useState("");

  // Group mappings form + edit state
  const [editMapId, setEditMapId] = useState<string | null>(null);
  const [mapProviderId, setMapProviderId] = useState("");
  const [mapGroup, setMapGroup] = useState("");
  const [mapRole, setMapRole] = useState("");
  const [mapPolicyId, setMapPolicyId] = useState("");
  const [mapPriority, setMapPriority] = useState(10);

  // API keys form + edit state
  const [editKeyId, setEditKeyId] = useState<string | null>(null);
  const [keyName, setKeyName] = useState("");
  const [keyGroups, setKeyGroups] = useState("");
  const [keyAllowedPolicyIds, setKeyAllowedPolicyIds] = useState<string[]>([]);
  const [keyExpiresAt, setKeyExpiresAt] = useState("");
  const [createdKeyRaw, setCreatedKeyRaw] = useState("");

  // Upstreams form + edit state
  const [editUpId, setEditUpId] = useState<string | null>(null);
  const [upName, setUpName] = useState("");
  const [upUrl, setUpUrl] = useState("");
  const [upAuthType, setUpAuthType] = useState("none");
  const [upHeaderName, setUpHeaderName] = useState("X-API-Key");
  const [upBasicUser, setUpBasicUser] = useState("");
  const [upCred, setUpCred] = useState("");
  const [upTimeout, setUpTimeout] = useState(15);

  // Proxy routes form + edit state
  const [editRtId, setEditRtId] = useState<string | null>(null);
  const [rtName, setRtName] = useState("");
  const [rtPrefix, setRtPrefix] = useState("");
  const [rtUpstreamId, setRtUpstreamId] = useState("");
  const [rtPolicyId, setRtPolicyId] = useState("");
  const [rtStripPrefix, setRtStripPrefix] = useState(true);
  const [rtMethods, setRtMethods] = useState("GET, POST");
  const [rtBlockedPaths, setRtBlockedPaths] = useState("");
  const [rtAllowPolicyOverride, setRtAllowPolicyOverride] = useState(false);
  const [rtOnUnstructured, setRtOnUnstructured] = useState("fail_closed");

  // Admin users form
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPass, setNewUserPass] = useState("");
  const [newUserRole, setNewUserRole] = useState("policy_author");

  async function runAction(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function api(path: string, opts: RequestInit = {}) {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...((opts.headers as Record<string, string>) || {}),
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(path, { ...opts, headers });
    if (res.status === 401 && token) {
      localStorage.removeItem("anonix_admin_token");
      localStorage.removeItem("anonix_admin_email");
      setToken("");
      setAdminEmail("");
      throw new Error("Session expired — please sign in again.");
    }
    if (res.status === 204) return null;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
    return data;
  }

  async function refreshAll() {
    if (!token) return;
    try {
      const [p, pr, m, k, u, r, us, a] = await Promise.all([
        api("/api/admin/policies").catch(() => []),
        api("/api/admin/auth-providers").catch(() => []),
        api("/api/admin/group-mappings").catch(() => []),
        api("/api/admin/api-keys").catch(() => []),
        api("/api/admin/upstreams").catch(() => []),
        api("/api/admin/routes").catch(() => []),
        api("/api/admin/users").catch(() => []),
        api("/api/admin/audit").catch(() => []),
      ]);
      setPolicies(p || []);
      setProviders(pr || []);
      setMappings(m || []);
      setApiKeys(k || []);
      setUpstreams(u || []);
      setRoutes(r || []);
      setUsers(us || []);
      setAudits(a || []);
    } catch (e: any) {
      setError(e.message);
    }
  }

  useEffect(() => {
    fetch("/api/setup/status")
      .then((r) => r.json())
      .then((d) => setBootstrapped(Boolean(d.bootstrapped)))
      .catch(() => setBootstrapped(true));
  }, []);

  useEffect(() => {
    if (token) refreshAll();
  }, [token]);

  async function handleSetup(e: React.FormEvent) {
    e.preventDefault();
    await runAction(async () => {
      const res = await api("/api/setup/bootstrap", {
        method: "POST",
        body: JSON.stringify({
          org_name: orgName.trim() || "Default Organization",
          admin_email: email,
          admin_password: password,
        }),
      });
      localStorage.setItem("anonix_admin_token", res.access_token);
      localStorage.setItem("anonix_admin_email", res.email);
      setToken(res.access_token);
      setAdminEmail(res.email);
      setBootstrapped(true);
    });
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    await runAction(async () => {
      const res = await api("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      localStorage.setItem("anonix_admin_token", res.access_token);
      localStorage.setItem("anonix_admin_email", res.email);
      setToken(res.access_token);
      setAdminEmail(res.email);
    });
  }

  function logout() {
    localStorage.removeItem("anonix_admin_token");
    localStorage.removeItem("anonix_admin_email");
    setToken("");
    setAdminEmail("");
  }

  if (bootstrapped === null) {
    return <div className="center-card">Loading Anonix Gateway...</div>;
  }

  if (!bootstrapped) {
    return (
      <div className="center-card">
        <h2>Anonix Gateway — First-Run Setup</h2>
        <p style={{ color: "var(--muted)", fontSize: 13 }}>
          Create your initial platform administrator account.
        </p>
        {error && <div className="alert alert-err">{error}</div>}
        <form onSubmit={handleSetup}>
          <label>Organization Name</label>
          <input value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme Corporation" required />
          <label>Admin Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" required />
          <label>Admin Password (min 8 characters)</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={8} required />
          <button className="btn" type="submit" disabled={busy}>Complete Setup</button>
        </form>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="center-card">
        <h2>Anonix Gateway — Admin Sign In</h2>
        {error && <div className="alert alert-err">{error}</div>}
        <form onSubmit={handleLogin}>
          <label>Admin Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" required />
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          <button className="btn" type="submit" disabled={busy}>Sign In</button>
        </form>
      </div>
    );
  }

  return (
    <div className="layout">
      <div className="topbar">
        <div>
          <h2 style={{ margin: 0 }}>Anonix Gateway</h2>
          <span style={{ fontSize: 12, color: "var(--muted)" }}>Control Plane · {adminEmail}</span>
        </div>
        <button className="btn btn-sm" onClick={logout}>Sign Out</button>
      </div>

      {error && <div className="alert alert-err">{error}</div>}
      {notice && <div className="alert alert-ok">{notice}</div>}

      <div className="tabs">
        {(["policies", "auth", "mappings", "keys", "upstreams", "routes", "users", "audit"] as Tab[]).map((t) => (
          <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      {tab === "policies" && (
        <div className="grid-2">
          <div className="card">
            <h3>{editPolId ? `Publish New Version for '${polName}'` : "Create Masking Policy"}</h3>
            <label>Policy Name</label>
            <input value={polName} onChange={(e) => setPolName(e.target.value)} placeholder="pii-masking-policy" disabled={Boolean(editPolId)} />
            {!editPolId && (
              <>
                <label>Description (Optional)</label>
                <input value={polDesc} onChange={(e) => setPolDesc(e.target.value)} placeholder="Masks PII fields for external consumers" />
              </>
            )}
            <label>Policy YAML</label>
            <textarea rows={11} value={polYaml} onChange={(e) => setPolYaml(e.target.value)} />
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                onClick={async () => {
                  setError(""); setNotice("");
                  try {
                    if (editPolId) {
                      const res = await api(`/api/admin/policies/${editPolId}/versions`, {
                        method: "POST",
                        body: JSON.stringify({ yaml_content: polYaml, activate: true }),
                      });
                      setNotice(`Published & activated v${res.version_number} for '${polName}'.`);
                      setEditPolId(null); setPolName(""); setPolDesc(""); setPolYaml(DEFAULT_YAML);
                    } else {
                      await api("/api/admin/policies", {
                        method: "POST",
                        body: JSON.stringify({ name: polName, description: polDesc, yaml_content: polYaml }),
                      });
                      setNotice(`Policy '${polName}' created.`);
                      setPolName(""); setPolDesc("");
                    }
                    refreshAll();
                  } catch (e: any) { setError(e.message); }
                }}
              >
                {editPolId ? "Publish New Version" : "Save Policy"}
              </button>
              {editPolId && (
                <button className="btn btn-danger" onClick={() => { setEditPolId(null); setPolName(""); setPolDesc(""); setPolYaml(DEFAULT_YAML); }}>
                  Cancel
                </button>
              )}
            </div>
          </div>

          <div className="card">
            <h3>Live Policy Playground</h3>
            <label>Payload Format</label>
            <select value={playFormat} onChange={(e) => setPlayFormat(e.target.value)}>
              <option value="json">JSON</option>
              <option value="xml">XML</option>
              <option value="yaml">YAML</option>
              <option value="csv">CSV</option>
            </select>
            <label>Caller Role (Optional — leave blank for unscoped/default rules)</label>
            <input value={playRole} onChange={(e) => setPlayRole(e.target.value)} placeholder="analyst" />
            <label>Sample Payload</label>
            <textarea rows={6} value={playPayload} onChange={(e) => setPlayPayload(e.target.value)} />
            <button
              className="btn"
              onClick={async () => {
                setError("");
                try {
                  const res = await api("/api/admin/policies/playground", {
                    method: "POST",
                    body: JSON.stringify({
                      yaml_content: polYaml,
                      payload: playPayload,
                      format: playFormat,
                      role: playRole.trim() || null,
                    }),
                  });
                  setPlayOut(res.output);
                } catch (e: any) { setError(e.message); }
              }}
            >
              Test Masking
            </button>
            {playOut && <pre>{playOut}</pre>}
          </div>

          <div className="card" style={{ gridColumn: "1 / -1" }}>
            <h3>Saved Policies ({policies.length})</h3>
            <table>
              <thead><tr><th>Name</th><th>Description</th><th>Active</th><th>Versions</th><th>Actions</th></tr></thead>
              <tbody>
                {policies.map((p) => {
                  const activeVer = p.versions?.find((v: any) => v.status === "active");
                  return (
                    <tr key={p.id}>
                      <td>{p.name}</td>
                      <td>{p.description || "-"}</td>
                      <td>v{activeVer?.version_number ?? "-"}</td>
                      <td>
                        {p.versions?.map((v: any) => (
                          <button
                            key={v.id}
                            className="btn btn-sm"
                            style={{ marginRight: 4, opacity: v.status === "active" ? 1 : 0.6 }}
                            onClick={async () => {
                              await api(`/api/admin/policies/${p.id}/versions/${v.version_number}/activate`, { method: "POST" });
                              refreshAll();
                            }}
                          >
                            v{v.version_number}{v.status === "active" ? " *" : ""}
                          </button>
                        ))}
                      </td>
                      <td style={{ display: "flex", gap: 6 }}>
                        <button
                          className="btn btn-sm"
                          onClick={() => {
                            setEditPolId(p.id);
                            setPolName(p.name);
                            setPolYaml(activeVer?.yaml_content || DEFAULT_YAML);
                          }}
                        >
                          Edit / New Version
                        </button>
                        <button className="btn btn-sm btn-danger" onClick={async () => { await api(`/api/admin/policies/${p.id}`, { method: "DELETE" }); refreshAll(); }}>Delete</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "auth" && (
        <div className="grid-2">
          <div className="card">
            <h3>{editProvId ? "Edit Auth Provider" : "Add Auth Provider"}</h3>
            <label>Provider Name</label>
            <input value={provName} onChange={(e) => setProvName(e.target.value)} placeholder="Corporate Identity Provider" />
            <label>Provider Type</label>
            <select value={provType} onChange={(e) => setProvType(e.target.value)} disabled={Boolean(editProvId)}>
              <option value="oidc">OIDC / JWT (Okta, Google, Entra ID, Keycloak)</option>
              <option value="trusted_proxy">Trusted-Proxy Headers (NGINX / Kong / ALB)</option>
            </select>
            {provType === "oidc" ? (
              <>
                <label>Issuer URL</label>
                <input value={issuerUrl} onChange={(e) => setIssuerUrl(e.target.value)} placeholder="https://idp.example.com" />
                <label>JWKS URL (Optional — auto-discovered from Issuer if blank)</label>
                <input value={jwksUrl} onChange={(e) => setJwksUrl(e.target.value)} placeholder="https://idp.example.com/.well-known/jwks.json" />
                <label>Audience (Optional — Client ID or API Audience)</label>
                <input value={audience} onChange={(e) => setAudience(e.target.value)} placeholder="optional" />
                <label>Groups / Identity Claim (e.g. groups, roles, email, hd)</label>
                <input value={groupsClaim} onChange={(e) => setGroupsClaim(e.target.value)} />
                <label>User ID Claim (default: sub)</label>
                <input value={subClaim} onChange={(e) => setSubClaim(e.target.value)} />
              </>
            ) : (
              <>
                <div className="alert" style={{ background: "var(--surface-2)", border: "1px solid var(--border)", marginTop: 10 }}>
                  Your edge proxy (NGINX / Kong / ALB) must overwrite any client-supplied <code>X-Anonix-*</code> headers and set:<br />
                  <code>X-Anonix-User</code>, <code>X-Anonix-Groups</code> (comma-separated), and <code>X-Anonix-Proxy-Secret</code>.
                </div>
                <label>Allowed Proxy Server IPs / CIDRs (comma-separated)</label>
                <input value={trustedCidrs} onChange={(e) => setTrustedCidrs(e.target.value)} placeholder="10.0.0.0/8, 192.168.1.0/24" />
                <label>Shared Secret (for X-Anonix-Proxy-Secret) {editProvId ? "(leave blank to keep existing)" : ""}</label>
                <input type="password" value={proxySecret} onChange={(e) => setProxySecret(e.target.value)} />
              </>
            )}
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                onClick={async () => {
                  setError(""); setNotice("");
                  try {
                    if (editProvId) {
                      await api(`/api/admin/auth-providers/${editProvId}`, {
                        method: "PATCH",
                        body: JSON.stringify({
                          name: provName,
                          issuer_url: provType === "oidc" ? issuerUrl : undefined,
                          jwks_url: provType === "oidc" ? (jwksUrl.trim() || null) : undefined,
                          audience: provType === "oidc" ? (audience.trim() || null) : undefined,
                          groups_claim: groupsClaim,
                          sub_claim: subClaim,
                          trusted_cidrs: trustedCidrs.split(",").map((s) => s.trim()).filter(Boolean),
                          proxy_secret: proxySecret || undefined,
                        }),
                      });
                      setNotice("Auth provider updated.");
                      setEditProvId(null);
                    } else {
                      await api("/api/admin/auth-providers", {
                        method: "POST",
                        body: JSON.stringify({
                          name: provName,
                          provider_type: provType,
                          issuer_url: provType === "oidc" ? issuerUrl : null,
                          jwks_url: provType === "oidc" ? (jwksUrl.trim() || null) : null,
                          audience: provType === "oidc" ? (audience.trim() || null) : null,
                          groups_claim: groupsClaim,
                          sub_claim: subClaim,
                          trusted_cidrs: trustedCidrs.split(",").map((s) => s.trim()).filter(Boolean),
                          proxy_secret: provType === "trusted_proxy" ? proxySecret : null,
                        }),
                      });
                      setNotice("Auth provider added.");
                    }
                    setProvName(""); setProxySecret(""); setAudience(""); setJwksUrl("");
                    refreshAll();
                  } catch (e: any) { setError(e.message); }
                }}
              >
                {editProvId ? "Save Changes" : "Add Provider"}
              </button>
              {editProvId && <button className="btn btn-danger" onClick={() => { setEditProvId(null); setProvName(""); setAudience(""); setJwksUrl(""); }}>Cancel</button>}
            </div>
          </div>
          <div className="card">
            <h3>Configured Providers</h3>
            <table>
              <thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                {providers.map((p) => (
                  <tr key={p.id}>
                    <td>{p.name}</td><td>{p.provider_type}</td>
                    <td>{p.is_enabled ? "enabled" : "disabled"}</td>
                    <td style={{ display: "flex", gap: 6 }}>
                      <button
                        className="btn btn-sm"
                        onClick={async () => {
                          await api(`/api/admin/auth-providers/${p.id}`, {
                            method: "PATCH",
                            body: JSON.stringify({ is_enabled: !p.is_enabled }),
                          });
                          refreshAll();
                        }}
                      >
                        {p.is_enabled ? "Disable" : "Enable"}
                      </button>
                      <button
                        className="btn btn-sm"
                        onClick={() => {
                          setEditProvId(p.id); setProvName(p.name); setProvType(p.provider_type);
                          setIssuerUrl(p.issuer_url || ""); setJwksUrl(p.jwks_url || "");
                          setAudience(p.audience || ""); setGroupsClaim(p.groups_claim || "groups");
                          setSubClaim(p.sub_claim || "sub"); setTrustedCidrs((p.trusted_cidrs || []).join(", "));
                        }}
                      >
                        Edit
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={async () => { await api(`/api/admin/auth-providers/${p.id}`, { method: "DELETE" }); refreshAll(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "mappings" && (
        <div className="grid-2">
          <div className="card">
            <h3>{editMapId ? "Edit Group Mapping" : "Create Group Mapping"}</h3>
            {!editMapId && (
              <>
                <label>Auth Provider Scope (Optional)</label>
                <select value={mapProviderId} onChange={(e) => setMapProviderId(e.target.value)}>
                  <option value="">Any Provider / API Key</option>
                  {providers.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.provider_type})</option>)}
                </select>
              </>
            )}
            <label>External Group / Claim Value</label>
            <input value={mapGroup} onChange={(e) => setMapGroup(e.target.value)} placeholder="data-analysts" />
            <label>Policy Role (Optional — leave blank for policy default rules)</label>
            <input value={mapRole} onChange={(e) => setMapRole(e.target.value)} placeholder="analyst" />
            <label>Policy (Required)</label>
            <select value={mapPolicyId} onChange={(e) => setMapPolicyId(e.target.value)}>
              <option value="">Select policy...</option>
              {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <label>Priority (higher number wins when caller has multiple groups)</label>
            <input type="number" value={mapPriority} onChange={(e) => setMapPriority(Number(e.target.value))} />
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                disabled={busy}
                onClick={() =>
                  runAction(async () => {
                    if (!mapGroup.trim() || !mapPolicyId) {
                      throw new Error("External group and policy are required.");
                    }
                    if (editMapId) {
                      await api(`/api/admin/group-mappings/${editMapId}`, {
                        method: "PATCH",
                        body: JSON.stringify({
                          external_group: mapGroup,
                          policy_role: mapRole.trim(),
                          policy_id: mapPolicyId,
                          priority: mapPriority,
                        }),
                      });
                      setNotice("Mapping updated.");
                      setEditMapId(null);
                    } else {
                      await api("/api/admin/group-mappings", {
                        method: "POST",
                        body: JSON.stringify({
                          provider_id: mapProviderId || null,
                          external_group: mapGroup,
                          policy_role: mapRole.trim() || null,
                          policy_id: mapPolicyId,
                          priority: mapPriority,
                        }),
                      });
                      setNotice("Mapping created.");
                    }
                    setMapGroup(""); setMapRole(""); setMapPolicyId(""); setMapProviderId("");
                    refreshAll();
                  })
                }
              >
                {editMapId ? "Save Changes" : "Add Mapping"}
              </button>
              {editMapId && <button className="btn btn-danger" onClick={() => { setEditMapId(null); setMapGroup(""); setMapRole(""); setMapPolicyId(""); }}>Cancel</button>}
            </div>
          </div>
          <div className="card">
            <h3>Group Mappings</h3>
            <table>
              <thead><tr><th>Group</th><th>Role</th><th>Priority</th><th>Actions</th></tr></thead>
              <tbody>
                {mappings.map((m) => (
                  <tr key={m.id}>
                    <td>{m.external_group}</td><td>{m.policy_role || "(default)"}</td><td>{m.priority}</td>
                    <td style={{ display: "flex", gap: 6 }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => {
                          setEditMapId(m.id); setMapGroup(m.external_group);
                          setMapRole(m.policy_role || ""); setMapPolicyId(m.policy_id || "");
                          setMapPriority(m.priority);
                        }}
                      >
                        Edit
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={async () => { await api(`/api/admin/group-mappings/${m.id}`, { method: "DELETE" }); refreshAll(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "keys" && (
        <div className="grid-2">
          <div className="card">
            <h3>{editKeyId ? "Edit API Key" : "Create API Key"}</h3>
            <label>Key Name</label>
            <input value={keyName} onChange={(e) => setKeyName(e.target.value)} placeholder="etl-pipeline-service" />
            <label>Assigned Groups (comma-separated, matched against Group Mappings)</label>
            <input value={keyGroups} onChange={(e) => setKeyGroups(e.target.value)} placeholder="data-analysts" />
            {!editKeyId && (
              <>
                {policies.length > 0 && (
                  <>
                    <label>Allowed Policies (optional — leave all unchecked to allow any policy)</label>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 10, marginTop: 4 }}>
                      {policies.map((p) => (
                        <label key={p.id} style={{ display: "flex", alignItems: "center", gap: 4, margin: 0 }}>
                          <input
                            type="checkbox"
                            style={{ width: "auto" }}
                            checked={keyAllowedPolicyIds.includes(p.id)}
                            onChange={(e) => {
                              setKeyAllowedPolicyIds((prev) =>
                                e.target.checked ? [...prev, p.id] : prev.filter((id) => id !== p.id)
                              );
                            }}
                          />
                          {p.name}
                        </label>
                      ))}
                    </div>
                  </>
                )}
                <label>Expiration Date (Optional)</label>
                <input type="datetime-local" value={keyExpiresAt} onChange={(e) => setKeyExpiresAt(e.target.value)} />
              </>
            )}
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                onClick={async () => {
                  setError(""); setCreatedKeyRaw(""); setNotice("");
                  try {
                    const groupsArr = keyGroups.split(",").map((s) => s.trim()).filter(Boolean);
                    if (editKeyId) {
                      await api(`/api/admin/api-keys/${editKeyId}`, {
                        method: "PATCH",
                        body: JSON.stringify({ name: keyName, groups: groupsArr }),
                      });
                      setNotice("API key updated.");
                      setEditKeyId(null);
                    } else {
                      const res = await api("/api/admin/api-keys", {
                        method: "POST",
                        body: JSON.stringify({
                          name: keyName,
                          groups: groupsArr,
                          allowed_policy_ids: keyAllowedPolicyIds.length ? keyAllowedPolicyIds : null,
                          expires_at: keyExpiresAt ? new Date(keyExpiresAt).toISOString() : null,
                        }),
                      });
                      setCreatedKeyRaw(res.raw_key);
                    }
                    setKeyName(""); setKeyGroups(""); setKeyAllowedPolicyIds([]); setKeyExpiresAt("");
                    refreshAll();
                  } catch (e: any) { setError(e.message); }
                }}
              >
                {editKeyId ? "Save Changes" : "Generate Key"}
              </button>
              {editKeyId && <button className="btn btn-danger" onClick={() => { setEditKeyId(null); setKeyName(""); setKeyGroups(""); }}>Cancel</button>}
            </div>
            {createdKeyRaw && (
              <div className="alert alert-ok" style={{ marginTop: 12 }}>
                Copy now (shown once): <code>{createdKeyRaw}</code>
              </div>
            )}
          </div>
          <div className="card">
            <h3>API Keys</h3>
            <table>
              <thead><tr><th>Name</th><th>Prefix</th><th>Groups</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                {apiKeys.map((k) => (
                  <tr key={k.id}>
                    <td>{k.name}</td><td>{k.key_prefix}…</td><td>{k.groups?.join(", ")}</td>
                    <td>{k.is_active ? "active" : "revoked"}</td>
                    <td style={{ display: "flex", gap: 6 }}>
                      <button className="btn btn-sm" onClick={() => { setEditKeyId(k.id); setKeyName(k.name); setKeyGroups((k.groups || []).join(", ")); }}>Edit</button>
                      {k.is_active && <button className="btn btn-sm" onClick={async () => { await api(`/api/admin/api-keys/${k.id}/revoke`, { method: "POST" }); refreshAll(); }}>Revoke</button>}
                      <button className="btn btn-sm btn-danger" onClick={async () => { await api(`/api/admin/api-keys/${k.id}`, { method: "DELETE" }); refreshAll(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "upstreams" && (
        <div className="grid-2">
          <div className="card">
            <h3>{editUpId ? "Edit Upstream API" : "Register Upstream API"}</h3>
            <label>Upstream Name</label>
            <input value={upName} onChange={(e) => setUpName(e.target.value)} placeholder="internal-records-api" />
            <label>Base URL</label>
            <input value={upUrl} onChange={(e) => setUpUrl(e.target.value)} placeholder="https://internal-api.example.com" />
            <label>Request Timeout (seconds)</label>
            <input type="number" min={0.5} max={120} step={0.5} value={upTimeout} onChange={(e) => setUpTimeout(Number(e.target.value))} />
            <label>Outbound Auth (how Anonix authenticates to this upstream)</label>
            <select value={upAuthType} onChange={(e) => setUpAuthType(e.target.value)}>
              <option value="none">None</option>
              <option value="bearer">Bearer Token</option>
              <option value="api_key_header">API Key Header</option>
              <option value="basic">Basic Auth</option>
            </select>
            {upAuthType === "bearer" && (
              <>
                <label>Bearer Token {editUpId ? "(leave blank to keep existing)" : ""}</label>
                <input type="password" value={upCred} onChange={(e) => setUpCred(e.target.value)} placeholder="eyJ..." />
              </>
            )}
            {upAuthType === "api_key_header" && (
              <>
                <label>Header Name</label>
                <input value={upHeaderName} onChange={(e) => setUpHeaderName(e.target.value)} placeholder="X-API-Key" />
                <label>API Key Value {editUpId ? "(leave blank to keep existing)" : ""}</label>
                <input type="password" value={upCred} onChange={(e) => setUpCred(e.target.value)} />
              </>
            )}
            {upAuthType === "basic" && (
              <>
                <label>Username {editUpId ? "(leave blank to keep existing)" : ""}</label>
                <input value={upBasicUser} onChange={(e) => setUpBasicUser(e.target.value)} placeholder="service_user" />
                <label>Password {editUpId ? "(leave blank to keep existing)" : ""}</label>
                <input type="password" value={upCred} onChange={(e) => setUpCred(e.target.value)} />
              </>
            )}
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                onClick={async () => {
                  setError(""); setNotice("");
                  try {
                    const finalCred =
                      upAuthType === "basic" && (upBasicUser || upCred)
                        ? `${upBasicUser}:${upCred}`
                        : upCred;
                    const headerName = upAuthType === "api_key_header" ? upHeaderName.trim() || "X-API-Key" : null;
                    if (editUpId) {
                      await api(`/api/admin/upstreams/${editUpId}`, {
                        method: "PATCH",
                        body: JSON.stringify({
                          name: upName,
                          base_url: upUrl,
                          auth_type: upAuthType,
                          auth_header_name: headerName,
                          credential: finalCred || undefined,
                          timeout_seconds: upTimeout,
                        }),
                      });
                      setNotice("Upstream updated.");
                      setEditUpId(null);
                    } else {
                      await api("/api/admin/upstreams", {
                        method: "POST",
                        body: JSON.stringify({
                          name: upName,
                          base_url: upUrl,
                          auth_type: upAuthType,
                          auth_header_name: headerName,
                          credential: finalCred || null,
                          timeout_seconds: upTimeout,
                        }),
                      });
                      setNotice("Upstream registered.");
                    }
                    setUpName(""); setUpUrl(""); setUpCred(""); setUpBasicUser(""); setUpTimeout(15);
                    refreshAll();
                  } catch (e: any) { setError(e.message); }
                }}
              >
                {editUpId ? "Save Changes" : "Save Upstream"}
              </button>
              {editUpId && <button className="btn btn-danger" onClick={() => { setEditUpId(null); setUpName(""); setUpUrl(""); setUpBasicUser(""); setUpCred(""); }}>Cancel</button>}
            </div>
          </div>
          <div className="card">
            <h3>Registered Upstreams</h3>
            <table>
              <thead><tr><th>Name</th><th>Base URL</th><th>Auth</th><th>Timeout</th><th>Actions</th></tr></thead>
              <tbody>
                {upstreams.map((u) => (
                  <tr key={u.id}>
                    <td>{u.name}</td><td>{u.base_url}</td><td>{u.auth_type}</td><td>{u.timeout_seconds}s</td>
                    <td style={{ display: "flex", gap: 6 }}>
                      <button className="btn btn-sm" onClick={() => { setEditUpId(u.id); setUpName(u.name); setUpUrl(u.base_url); setUpAuthType(u.auth_type); setUpHeaderName(u.auth_header_name || "X-API-Key"); setUpTimeout(u.timeout_seconds || 15); setUpBasicUser(""); setUpCred(""); }}>Edit</button>
                      <button className="btn btn-sm btn-danger" onClick={async () => { await api(`/api/admin/upstreams/${u.id}`, { method: "DELETE" }); refreshAll(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "routes" && (
        <div className="grid-2">
          <div className="card">
            <h3>{editRtId ? "Edit Proxy Route" : "Create Proxy Route"}</h3>
            <label>Route Name</label>
            <input value={rtName} onChange={(e) => setRtName(e.target.value)} placeholder="records-route" />
            <label>Public Prefix (served under /proxy/...)</label>
            <input value={rtPrefix} onChange={(e) => setRtPrefix(e.target.value)} placeholder="/records" />
            <label>Upstream</label>
            <select value={rtUpstreamId} onChange={(e) => setRtUpstreamId(e.target.value)}>
              <option value="">Select upstream...</option>
              {upstreams.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.base_url})</option>)}
            </select>
            <label>Masking Policy</label>
            <select value={rtPolicyId} onChange={(e) => setRtPolicyId(e.target.value)}>
              <option value="">Select policy...</option>
              {policies.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <label>Allowed HTTP Methods (comma-separated)</label>
            <input value={rtMethods} onChange={(e) => setRtMethods(e.target.value)} placeholder="GET, POST" />
            <label>Blocked Subpath Patterns (optional, comma-separated, e.g. /internal/*, /debug/*)</label>
            <input value={rtBlockedPaths} onChange={(e) => setRtBlockedPaths(e.target.value)} placeholder="/internal/*" />
            <label>Unstructured / Non-Structured Upstream Response Handling</label>
            <select value={rtOnUnstructured} onChange={(e) => setRtOnUnstructured(e.target.value)}>
              <option value="fail_closed">Fail Closed (return 502 — recommended)</option>
              <option value="passthrough">Passthrough (forward unmasked)</option>
            </select>
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={rtStripPrefix} onChange={(e) => setRtStripPrefix(e.target.checked)} />
              Strip prefix before forwarding to upstream
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 8 }}>
              <input type="checkbox" style={{ width: "auto" }} checked={rtAllowPolicyOverride} onChange={(e) => setRtAllowPolicyOverride(e.target.checked)} />
              Allow Group Mapping policy override on this route
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                disabled={busy}
                onClick={() =>
                  runAction(async () => {
                    if (!rtName.trim() || !rtPrefix.trim() || !rtUpstreamId || !rtPolicyId) {
                      throw new Error("Route name, prefix, upstream, and masking policy are all required.");
                    }
                    const payload = {
                      name: rtName,
                      route_prefix: rtPrefix,
                      upstream_id: rtUpstreamId,
                      policy_id: rtPolicyId,
                      strip_prefix: rtStripPrefix,
                      allowed_methods: rtMethods.split(",").map((m) => m.trim().toUpperCase()).filter(Boolean),
                      blocked_subpaths: rtBlockedPaths.split(",").map((p) => p.trim()).filter(Boolean),
                      allow_policy_override: rtAllowPolicyOverride,
                      on_unstructured: rtOnUnstructured,
                    };
                    if (editRtId) {
                      await api(`/api/admin/routes/${editRtId}`, { method: "PATCH", body: JSON.stringify(payload) });
                      setNotice("Proxy route updated.");
                      setEditRtId(null);
                    } else {
                      await api("/api/admin/routes", { method: "POST", body: JSON.stringify(payload) });
                      setNotice("Proxy route created.");
                    }
                    setRtName(""); setRtPrefix(""); setRtBlockedPaths("");
                    refreshAll();
                  })
                }
              >
                {editRtId ? "Save Changes" : "Create Route"}
              </button>
              {editRtId && <button className="btn btn-danger" onClick={() => { setEditRtId(null); setRtName(""); setRtPrefix(""); }}>Cancel</button>}
            </div>
          </div>
          <div className="card">
            <h3>Active Proxy Routes</h3>
            <table>
              <thead><tr><th>Name</th><th>Prefix</th><th>Methods</th><th>Strip</th><th>Actions</th></tr></thead>
              <tbody>
                {routes.map((r) => (
                  <tr key={r.id}>
                    <td>{r.name}</td><td>/proxy{r.route_prefix}</td><td>{r.allowed_methods?.join(", ")}</td><td>{r.strip_prefix ? "yes" : "no"}</td>
                    <td style={{ display: "flex", gap: 6 }}>
                      <button
                        className="btn btn-sm"
                        onClick={() => {
                          setEditRtId(r.id); setRtName(r.name); setRtPrefix(r.route_prefix);
                          setRtUpstreamId(r.upstream_id); setRtPolicyId(r.policy_id);
                          setRtStripPrefix(Boolean(r.strip_prefix));
                          setRtMethods((r.allowed_methods || ["GET", "POST"]).join(", "));
                          setRtBlockedPaths((r.blocked_subpaths || []).join(", "));
                          setRtAllowPolicyOverride(Boolean(r.allow_policy_override));
                          setRtOnUnstructured(r.on_unstructured || "fail_closed");
                        }}
                      >
                        Edit
                      </button>
                      <button className="btn btn-sm btn-danger" onClick={async () => { await api(`/api/admin/routes/${r.id}`, { method: "DELETE" }); refreshAll(); }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "users" && (
        <div className="grid-2">
          <div className="card">
            <h3>Create Admin User</h3>
            <label>Email</label>
            <input type="email" value={newUserEmail} onChange={(e) => setNewUserEmail(e.target.value)} placeholder="user@example.com" />
            <label>Password (min 8 characters)</label>
            <input type="password" value={newUserPass} onChange={(e) => setNewUserPass(e.target.value)} />
            <label>Role</label>
            <select value={newUserRole} onChange={(e) => setNewUserRole(e.target.value)}>
              <option value="platform_admin">platform_admin</option>
              <option value="policy_author">policy_author</option>
              <option value="auditor">auditor</option>
            </select>
            <button
              className="btn"
              onClick={async () => {
                setError(""); setNotice("");
                try {
                  await api("/api/admin/users", {
                    method: "POST",
                    body: JSON.stringify({ email: newUserEmail, password: newUserPass, role: newUserRole }),
                  });
                  setNotice(`Admin user '${newUserEmail}' created.`);
                  setNewUserEmail(""); setNewUserPass("");
                  refreshAll();
                } catch (e: any) { setError(e.message); }
              }}
            >
              Add Admin User
            </button>
          </div>
          <div className="card">
            <h3>Admin Users</h3>
            <table>
              <thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = u.email === adminEmail;
                  return (
                    <tr key={u.id}>
                      <td>{u.email} {isSelf ? "(you)" : ""}</td>
                      <td>
                        <select
                          value={u.role}
                          disabled={isSelf}
                          onChange={async (e) => {
                            setError("");
                            try {
                              await api(`/api/admin/users/${u.id}`, {
                                method: "PATCH",
                                body: JSON.stringify({ role: e.target.value }),
                              });
                              refreshAll();
                            } catch (err: any) { setError(err.message); }
                          }}
                        >
                          <option value="platform_admin">platform_admin</option>
                          <option value="policy_author">policy_author</option>
                          <option value="auditor">auditor</option>
                        </select>
                      </td>
                      <td>{u.is_active ? "active" : "disabled"}</td>
                      <td style={{ display: "flex", gap: 6 }}>
                        {!isSelf && (
                          <>
                            <button
                              className="btn btn-sm"
                              onClick={async () => {
                                setError("");
                                try {
                                  await api(`/api/admin/users/${u.id}`, {
                                    method: "PATCH",
                                    body: JSON.stringify({ is_active: !u.is_active }),
                                  });
                                  refreshAll();
                                } catch (err: any) { setError(err.message); }
                              }}
                            >
                              {u.is_active ? "Disable" : "Enable"}
                            </button>
                            <button
                              className="btn btn-sm btn-danger"
                              onClick={async () => {
                                setError("");
                                try {
                                  await api(`/api/admin/users/${u.id}`, { method: "DELETE" });
                                  refreshAll();
                                } catch (err: any) { setError(err.message); }
                              }}
                            >
                              Delete
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "audit" && (
        <div className="card">
          <h3>Zero-PII Audit Log</h3>
          <table>
            <thead><tr><th>Time</th><th>Caller</th><th>Auth</th><th>Role</th><th>Format</th><th>Status</th><th>Latency</th></tr></thead>
            <tbody>
              {audits.map((a) => (
                <tr key={a.id}>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td>{a.caller_id}</td>
                  <td>{a.auth_method}</td>
                  <td>{a.resolved_role || "-"}</td>
                  <td>{a.format_name || "-"}</td>
                  <td>{a.status_code}</td>
                  <td>{a.duration_ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
