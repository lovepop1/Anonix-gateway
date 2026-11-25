import { useState } from "react";
import type { TabContextProps, Upstream } from "../types";

interface UpstreamsTabProps extends TabContextProps {
  upstreams: Upstream[];
}

export function UpstreamsTab({ upstreams, busy, api, runAction, refreshAll, setNotice }: UpstreamsTabProps) {
  const [editUpId, setEditUpId] = useState<string | null>(null);
  const [upName, setUpName] = useState("");
  const [upUrl, setUpUrl] = useState("");
  const [upAuthType, setUpAuthType] = useState<Upstream["auth_type"]>("none");
  const [upHeaderName, setUpHeaderName] = useState("X-API-Key");
  const [upBasicUser, setUpBasicUser] = useState("");
  const [upCred, setUpCred] = useState("");
  const [upTimeout, setUpTimeout] = useState(15);

  const resetForm = () => {
    setEditUpId(null);
    setUpName("");
    setUpUrl("");
    setUpAuthType("none");
    setUpHeaderName("X-API-Key");
    setUpBasicUser("");
    setUpCred("");
    setUpTimeout(15);
  };

  return (
    <div className="grid-2">
      <div className="card">
        <h3>{editUpId ? "Edit Upstream API" : "Register Upstream API"}</h3>
        <label>Upstream Name</label>
        <input value={upName} onChange={(e) => setUpName(e.target.value)} placeholder="internal-records-api" />
        <label>Base URL</label>
        <input value={upUrl} onChange={(e) => setUpUrl(e.target.value)} placeholder="https://internal-api.example.com" />
        <label>Request Timeout (seconds)</label>
        <input
          type="number"
          min={0.5}
          max={120}
          step={0.5}
          value={upTimeout}
          onChange={(e) => setUpTimeout(Number(e.target.value))}
        />
        <label>Outbound Auth (how Anonix authenticates to this upstream)</label>
        <select
          value={upAuthType}
          onChange={(e) => setUpAuthType(e.target.value as Upstream["auth_type"])}
        >
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

        <div className="btn-row">
          <button
            className="btn"
            disabled={busy}
            onClick={() =>
              runAction(async () => {
                const finalCred =
                  upAuthType === "basic" && (upBasicUser || upCred) ? `${upBasicUser}:${upCred}` : upCred;
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
                resetForm();
                await refreshAll();
              })
            }
          >
            {editUpId ? "Save Changes" : "Save Upstream"}
          </button>
          {editUpId && (
            <button className="btn btn-danger" onClick={resetForm}>
              Cancel
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Registered Upstreams</h3>
        <table>
          <thead>
            <tr><th>Name</th><th>Base URL</th><th>Auth</th><th>Timeout</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {upstreams.map((u) => (
              <tr key={u.id}>
                <td>{u.name}</td>
                <td>{u.base_url}</td>
                <td>{u.auth_type}</td>
                <td>{u.timeout_seconds}s</td>
                <td className="action-cell">
                  <button
                    className="btn btn-sm"
                    onClick={() => {
                      setEditUpId(u.id);
                      setUpName(u.name);
                      setUpUrl(u.base_url);
                      setUpAuthType(u.auth_type);
                      setUpHeaderName(u.auth_header_name || "X-API-Key");
                      setUpTimeout(u.timeout_seconds || 15);
                      setUpBasicUser("");
                      setUpCred("");
                    }}
                  >
                    Edit
                  </button>
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() =>
                      runAction(async () => {
                        await api(`/api/admin/upstreams/${u.id}`, { method: "DELETE" });
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
