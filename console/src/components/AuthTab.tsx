import { useState } from "react";
import type { AuthProvider, TabContextProps } from "../types";

interface AuthTabProps extends TabContextProps {
  providers: AuthProvider[];
}

export function AuthTab({ providers, busy, api, runAction, refreshAll, setNotice }: AuthTabProps) {
  const [editProvId, setEditProvId] = useState<string | null>(null);
  const [provName, setProvName] = useState("");
  const [provType, setProvType] = useState<"oidc" | "trusted_proxy">("oidc");
  const [issuerUrl, setIssuerUrl] = useState("");
  const [jwksUrl, setJwksUrl] = useState("");
  const [audience, setAudience] = useState("");
  const [groupsClaim, setGroupsClaim] = useState("groups");
  const [subClaim, setSubClaim] = useState("sub");
  const [trustedCidrs, setTrustedCidrs] = useState("");
  const [proxySecret, setProxySecret] = useState("");

  const resetForm = () => {
    setEditProvId(null);
    setProvName("");
    setProxySecret("");
    setAudience("");
    setJwksUrl("");
    setIssuerUrl("");
    setTrustedCidrs("");
  };

  return (
    <div className="grid-2">
      <div className="card">
        <h3>{editProvId ? "Edit Auth Provider" : "Add Auth Provider"}</h3>
        <label>Provider Name</label>
        <input
          value={provName}
          onChange={(e) => setProvName(e.target.value)}
          placeholder="Corporate Identity Provider"
        />
        <label>Provider Type</label>
        <select
          value={provType}
          onChange={(e) => setProvType(e.target.value as "oidc" | "trusted_proxy")}
          disabled={Boolean(editProvId)}
        >
          <option value="oidc">OIDC / JWT (Okta, Google, Entra ID, Keycloak)</option>
          <option value="trusted_proxy">Trusted-Proxy Headers (NGINX / Kong / ALB)</option>
        </select>

        {provType === "oidc" ? (
          <>
            <label>Issuer URL</label>
            <input
              value={issuerUrl}
              onChange={(e) => setIssuerUrl(e.target.value)}
              placeholder="https://idp.example.com"
            />
            <label>JWKS URL (Optional — auto-discovered from Issuer if blank)</label>
            <input
              value={jwksUrl}
              onChange={(e) => setJwksUrl(e.target.value)}
              placeholder="https://idp.example.com/.well-known/jwks.json"
            />
            <label>Audience (Optional — Client ID or API Audience)</label>
            <input value={audience} onChange={(e) => setAudience(e.target.value)} placeholder="optional" />
            <label>Groups / Identity Claim (e.g. groups, roles, email, hd)</label>
            <input value={groupsClaim} onChange={(e) => setGroupsClaim(e.target.value)} />
            <label>User ID Claim (default: sub)</label>
            <input value={subClaim} onChange={(e) => setSubClaim(e.target.value)} />
          </>
        ) : (
          <>
            <div className="alert info-box">
              Your edge proxy (NGINX / Kong / ALB) must overwrite any client-supplied{" "}
              <code>X-Anonix-*</code> headers and set: <code>X-Anonix-User</code>,{" "}
              <code>X-Anonix-Groups</code> (comma-separated), and <code>X-Anonix-Proxy-Secret</code>.
            </div>
            <label>Allowed Proxy Server IPs / CIDRs (comma-separated)</label>
            <input
              value={trustedCidrs}
              onChange={(e) => setTrustedCidrs(e.target.value)}
              placeholder="10.0.0.0/8, 192.168.1.0/24"
            />
            <label>
              Shared Secret (for X-Anonix-Proxy-Secret) {editProvId ? "(leave blank to keep existing)" : ""}
            </label>
            <input type="password" value={proxySecret} onChange={(e) => setProxySecret(e.target.value)} />
          </>
        )}

        <div className="btn-row">
          <button
            className="btn"
            disabled={busy}
            onClick={() =>
              runAction(async () => {
                const cidrs = trustedCidrs.split(",").map((s) => s.trim()).filter(Boolean);
                if (editProvId) {
                  await api(`/api/admin/auth-providers/${editProvId}`, {
                    method: "PATCH",
                    body: JSON.stringify({
                      name: provName,
                      issuer_url: provType === "oidc" ? issuerUrl : undefined,
                      jwks_url: provType === "oidc" ? jwksUrl.trim() || null : undefined,
                      audience: provType === "oidc" ? audience.trim() || null : undefined,
                      groups_claim: groupsClaim,
                      sub_claim: subClaim,
                      trusted_cidrs: cidrs,
                      proxy_secret: proxySecret || undefined,
                    }),
                  });
                  setNotice("Auth provider updated.");
                } else {
                  await api("/api/admin/auth-providers", {
                    method: "POST",
                    body: JSON.stringify({
                      name: provName,
                      provider_type: provType,
                      issuer_url: provType === "oidc" ? issuerUrl : null,
                      jwks_url: provType === "oidc" ? jwksUrl.trim() || null : null,
                      audience: provType === "oidc" ? audience.trim() || null : null,
                      groups_claim: groupsClaim,
                      sub_claim: subClaim,
                      trusted_cidrs: cidrs,
                      proxy_secret: provType === "trusted_proxy" ? proxySecret : null,
                    }),
                  });
                  setNotice("Auth provider added.");
                }
                resetForm();
                await refreshAll();
              })
            }
          >
            {editProvId ? "Save Changes" : "Add Provider"}
          </button>
          {editProvId && (
            <button className="btn btn-danger" onClick={resetForm}>
              Cancel
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Configured Providers ({providers.length})</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th className="nowrap">Type</th>
                <th className="nowrap">Status</th>
                <th className="actions-col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {providers.length === 0 ? (
                <tr>
                  <td colSpan={4} className="empty-row">No auth providers configured yet.</td>
                </tr>
              ) : (
                providers.map((p) => (
                  <tr key={p.id}>
                    <td>{p.name}</td>
                    <td className="nowrap">{p.provider_type}</td>
                    <td className="nowrap">{p.is_enabled ? "enabled" : "disabled"}</td>
                    <td className="actions-col">
                      <div className="action-buttons">
                        <button
                          className="btn btn-sm"
                          onClick={() =>
                            runAction(async () => {
                              await api(`/api/admin/auth-providers/${p.id}`, {
                                method: "PATCH",
                                body: JSON.stringify({ is_enabled: !p.is_enabled }),
                              });
                              await refreshAll();
                            })
                          }
                        >
                          {p.is_enabled ? "Disable" : "Enable"}
                        </button>
                        <button
                          className="btn btn-sm"
                          onClick={() => {
                            setEditProvId(p.id);
                            setProvName(p.name);
                            setProvType(p.provider_type);
                            setIssuerUrl(p.issuer_url || "");
                            setJwksUrl(p.jwks_url || "");
                            setAudience(p.audience || "");
                            setGroupsClaim(p.groups_claim || "groups");
                            setSubClaim(p.sub_claim || "sub");
                            setTrustedCidrs((p.trusted_cidrs || []).join(", "));
                          }}
                        >
                          Edit
                        </button>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() =>
                            runAction(async () => {
                              await api(`/api/admin/auth-providers/${p.id}`, { method: "DELETE" });
                              await refreshAll();
                            })
                          }
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
