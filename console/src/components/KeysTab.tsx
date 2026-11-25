import { useState } from "react";
import type { ApiKey, Policy, TabContextProps } from "../types";

interface KeysTabProps extends TabContextProps {
  apiKeys: ApiKey[];
  policies: Policy[];
}

export function KeysTab({ apiKeys, policies, busy, api, runAction, refreshAll, setNotice }: KeysTabProps) {
  const [editKeyId, setEditKeyId] = useState<string | null>(null);
  const [keyName, setKeyName] = useState("");
  const [keyGroups, setKeyGroups] = useState("");
  const [keyAllowedPolicyIds, setKeyAllowedPolicyIds] = useState<string[]>([]);
  const [keyExpiresAt, setKeyExpiresAt] = useState("");
  const [createdKeyRaw, setCreatedKeyRaw] = useState("");

  return (
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
                <div className="checkbox-group">
                  {policies.map((p) => (
                    <label key={p.id} className="inline-check">
                      <input
                        type="checkbox"
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

        <div className="btn-row">
          <button
            className="btn"
            disabled={busy}
            onClick={() =>
              runAction(async () => {
                setCreatedKeyRaw("");
                const groupsArr = keyGroups.split(",").map((s) => s.trim()).filter(Boolean);
                if (!keyName.trim() || groupsArr.length === 0) {
                  throw new Error("Key name and at least one group are required.");
                }
                if (editKeyId) {
                  await api(`/api/admin/api-keys/${editKeyId}`, {
                    method: "PATCH",
                    body: JSON.stringify({ name: keyName, groups: groupsArr }),
                  });
                  setNotice("API key updated.");
                  setEditKeyId(null);
                } else {
                  const res = await api<{ raw_key: string }>("/api/admin/api-keys", {
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
                setKeyName("");
                setKeyGroups("");
                setKeyAllowedPolicyIds([]);
                setKeyExpiresAt("");
                await refreshAll();
              })
            }
          >
            {editKeyId ? "Save Changes" : "Generate Key"}
          </button>
          {editKeyId && (
            <button
              className="btn btn-danger"
              onClick={() => {
                setEditKeyId(null);
                setKeyName("");
                setKeyGroups("");
              }}
            >
              Cancel
            </button>
          )}
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
          <thead>
            <tr><th>Name</th><th>Prefix</th><th>Groups</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {apiKeys.map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td>{k.key_prefix}…</td>
                <td>{k.groups.join(", ")}</td>
                <td>{k.is_active ? "active" : "revoked"}</td>
                <td className="action-cell">
                  <button
                    className="btn btn-sm"
                    onClick={() => {
                      setEditKeyId(k.id);
                      setKeyName(k.name);
                      setKeyGroups(k.groups.join(", "));
                    }}
                  >
                    Edit
                  </button>
                  {k.is_active && (
                    <button
                      className="btn btn-sm"
                      onClick={() =>
                        runAction(async () => {
                          await api(`/api/admin/api-keys/${k.id}/revoke`, { method: "POST" });
                          await refreshAll();
                        })
                      }
                    >
                      Revoke
                    </button>
                  )}
                  <button
                    className="btn btn-sm btn-danger"
                    onClick={() =>
                      runAction(async () => {
                        await api(`/api/admin/api-keys/${k.id}`, { method: "DELETE" });
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
