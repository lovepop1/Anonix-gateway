import { useState } from "react";
import type { Policy, ProxyRoute, TabContextProps, Upstream } from "../types";

interface RoutesTabProps extends TabContextProps {
  routes: ProxyRoute[];
  upstreams: Upstream[];
  policies: Policy[];
}

export function RoutesTab({
  routes,
  upstreams,
  policies,
  busy,
  api,
  runAction,
  refreshAll,
  setNotice,
}: RoutesTabProps) {
  const [editRtId, setEditRtId] = useState<string | null>(null);
  const [rtName, setRtName] = useState("");
  const [rtPrefix, setRtPrefix] = useState("");
  const [rtUpstreamId, setRtUpstreamId] = useState("");
  const [rtPolicyId, setRtPolicyId] = useState("");
  const [rtStripPrefix, setRtStripPrefix] = useState(true);
  const [rtMethods, setRtMethods] = useState("GET, POST");
  const [rtBlockedPaths, setRtBlockedPaths] = useState("");
  const [rtAllowPolicyOverride, setRtAllowPolicyOverride] = useState(false);
  const [rtOnUnstructured, setRtOnUnstructured] = useState<"fail_closed" | "passthrough">("fail_closed");

  const resetForm = () => {
    setEditRtId(null);
    setRtName("");
    setRtPrefix("");
    setRtUpstreamId("");
    setRtPolicyId("");
    setRtBlockedPaths("");
    setRtStripPrefix(true);
    setRtAllowPolicyOverride(false);
    setRtOnUnstructured("fail_closed");
  };

  return (
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
          {upstreams.map((u) => (
            <option key={u.id} value={u.id}>{u.name} ({u.base_url})</option>
          ))}
        </select>
        <label>Masking Policy</label>
        <select value={rtPolicyId} onChange={(e) => setRtPolicyId(e.target.value)}>
          <option value="">Select policy...</option>
          {policies.map((p) => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
        <label>Allowed HTTP Methods (comma-separated)</label>
        <input value={rtMethods} onChange={(e) => setRtMethods(e.target.value)} placeholder="GET, POST" />
        <label>Blocked Subpath Patterns (optional, comma-separated, e.g. /internal/*)</label>
        <input value={rtBlockedPaths} onChange={(e) => setRtBlockedPaths(e.target.value)} placeholder="/internal/*" />
        <label>Unstructured / Non-Structured Upstream Response Handling</label>
        <select
          value={rtOnUnstructured}
          onChange={(e) => setRtOnUnstructured(e.target.value as "fail_closed" | "passthrough")}
        >
          <option value="fail_closed">Fail Closed (return 502 — recommended)</option>
          <option value="passthrough">Passthrough (forward unmasked)</option>
        </select>

        <label className="inline-check spaced">
          <input type="checkbox" checked={rtStripPrefix} onChange={(e) => setRtStripPrefix(e.target.checked)} />
          Strip prefix before forwarding to upstream
        </label>
        <label className="inline-check spaced">
          <input
            type="checkbox"
            checked={rtAllowPolicyOverride}
            onChange={(e) => setRtAllowPolicyOverride(e.target.checked)}
          />
          Allow Group Mapping policy override on this route
        </label>

        <div className="btn-row">
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
                } else {
                  await api("/api/admin/routes", { method: "POST", body: JSON.stringify(payload) });
                  setNotice("Proxy route created.");
                }
                resetForm();
                await refreshAll();
              })
            }
          >
            {editRtId ? "Save Changes" : "Create Route"}
          </button>
          {editRtId && (
            <button className="btn btn-danger" onClick={resetForm}>
              Cancel
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Active Proxy Routes</h3>
        <table>
          <thead>
            <tr><th>Name</th><th>Prefix</th><th>Methods</th><th>Strip</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {routes.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>/proxy{r.route_prefix}</td>
                <td>{r.allowed_methods.join(", ")}</td>
                <td>{r.strip_prefix ? "yes" : "no"}</td>
                <td className="action-cell">
                  <button
                    className="btn btn-sm"
                    onClick={() => {
                      setEditRtId(r.id);
                      setRtName(r.name);
                      setRtPrefix(r.route_prefix);
                      setRtUpstreamId(r.upstream_id);
                      setRtPolicyId(r.policy_id);
                      setRtStripPrefix(Boolean(r.strip_prefix));
                      setRtMethods(r.allowed_methods.join(", "));
                      setRtBlockedPaths(r.blocked_subpaths.join(", "));
                      setRtAllowPolicyOverride(Boolean(r.allow_policy_override));
                      setRtOnUnstructured(r.on_unstructured);
                    }}
                  >
                    Edit
                  </button>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() =>
                      runAction(async () => {
                        await api(`/api/admin/routes/${r.id}`, { method: "DELETE" });
                        await refreshAll();
                      })
                    }
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
