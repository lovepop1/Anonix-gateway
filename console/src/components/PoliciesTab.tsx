import { useState } from "react";
import type { Policy, TabContextProps } from "../types";

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

interface PoliciesTabProps extends TabContextProps {
  policies: Policy[];
}

export function PoliciesTab({ policies, busy, api, runAction, refreshAll, setNotice }: PoliciesTabProps) {
  const [editPolId, setEditPolId] = useState<string | null>(null);
  const [polName, setPolName] = useState("");
  const [polDesc, setPolDesc] = useState("");
  const [polYaml, setPolYaml] = useState(DEFAULT_YAML);

  const [playPayload, setPlayPayload] = useState(SAMPLE_PAYLOAD);
  const [playFormat, setPlayFormat] = useState("json");
  const [playRole, setPlayRole] = useState("analyst");
  const [playOut, setPlayOut] = useState("");

  return (
    <div className="grid-2">
      <div className="card">
        <h3>{editPolId ? `Publish New Version for '${polName}'` : "Create Masking Policy"}</h3>
        <label>Policy Name</label>
        <input
          value={polName}
          onChange={(e) => setPolName(e.target.value)}
          placeholder="pii-masking-policy"
          disabled={Boolean(editPolId)}
        />
        {!editPolId && (
          <>
            <label>Description (Optional)</label>
            <input
              value={polDesc}
              onChange={(e) => setPolDesc(e.target.value)}
              placeholder="Masks PII fields for external consumers"
            />
          </>
        )}
        <label>Policy YAML</label>
        <textarea rows={11} value={polYaml} onChange={(e) => setPolYaml(e.target.value)} />
        <div className="btn-row">
          <button
            className="btn"
            disabled={busy}
            onClick={() =>
              runAction(async () => {
                if (!polName.trim() || !polYaml.trim()) {
                  throw new Error("Policy name and YAML content are required.");
                }
                if (editPolId) {
                  const res = await api<{ version_number: number }>(
                    `/api/admin/policies/${editPolId}/versions`,
                    { method: "POST", body: JSON.stringify({ yaml_content: polYaml, activate: true }) }
                  );
                  setNotice(`Published & activated v${res.version_number} for '${polName}'.`);
                  setEditPolId(null);
                  setPolName("");
                  setPolDesc("");
                  setPolYaml(DEFAULT_YAML);
                } else {
                  await api("/api/admin/policies", {
                    method: "POST",
                    body: JSON.stringify({ name: polName, description: polDesc, yaml_content: polYaml }),
                  });
                  setNotice(`Policy '${polName}' created.`);
                  setPolName("");
                  setPolDesc("");
                }
                await refreshAll();
              })
            }
          >
            {editPolId ? "Publish New Version" : "Save Policy"}
          </button>
          {editPolId && (
            <button
              className="btn btn-danger"
              onClick={() => {
                setEditPolId(null);
                setPolName("");
                setPolDesc("");
                setPolYaml(DEFAULT_YAML);
              }}
            >
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
          disabled={busy}
          onClick={() =>
            runAction(async () => {
              const res = await api<{ output: string }>("/api/admin/policies/playground", {
                method: "POST",
                body: JSON.stringify({
                  yaml_content: polYaml,
                  payload: playPayload,
                  format: playFormat,
                  role: playRole.trim() || null,
                }),
              });
              setPlayOut(res.output);
            })
          }
        >
          Test Masking
        </button>
        {playOut && <pre>{playOut}</pre>}
      </div>

      <div className="card full-span">
        <h3>Saved Policies ({policies.length})</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th className="nowrap">Active</th>
                <th>Versions</th>
                <th className="actions-col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty-row">No policies created yet.</td>
                </tr>
              ) : (
                policies.map((p) => {
                  const activeVer = p.versions.find((v) => v.status === "active");
                  return (
                    <tr key={p.id}>
                      <td>{p.name}</td>
                      <td>{p.description || "-"}</td>
                      <td className="nowrap">v{activeVer?.version_number ?? "-"}</td>
                      <td>
                        <div className="version-list">
                          {p.versions.map((v) => (
                            <button
                              key={v.id}
                              className="btn btn-sm"
                              style={{ opacity: v.status === "active" ? 1 : 0.6 }}
                              onClick={() =>
                                runAction(async () => {
                                  await api(`/api/admin/policies/${p.id}/versions/${v.version_number}/activate`, {
                                    method: "POST",
                                  });
                                  setNotice(`Activated v${v.version_number} for '${p.name}'.`);
                                  await refreshAll();
                                })
                              }
                            >
                              v{v.version_number}{v.status === "active" ? " *" : ""}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td className="actions-col">
                        <div className="action-buttons">
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
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() =>
                              runAction(async () => {
                                await api(`/api/admin/policies/${p.id}`, { method: "DELETE" });
                                setNotice(`Deleted policy '${p.name}'.`);
                                await refreshAll();
                              })
                            }
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
