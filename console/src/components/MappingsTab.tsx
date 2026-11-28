import { useState } from "react";
import type { AuthProvider, GroupMapping, Policy, TabContextProps } from "../types";

interface MappingsTabProps extends TabContextProps {
  mappings: GroupMapping[];
  policies: Policy[];
  providers: AuthProvider[];
}

export function MappingsTab({
  mappings,
  policies,
  providers,
  busy,
  api,
  runAction,
  refreshAll,
  setNotice,
}: MappingsTabProps) {
  const [editMapId, setEditMapId] = useState<string | null>(null);
  const [mapProviderId, setMapProviderId] = useState("");
  const [mapGroup, setMapGroup] = useState("");
  const [mapRole, setMapRole] = useState("");
  const [mapPolicyId, setMapPolicyId] = useState("");
  const [mapPriority, setMapPriority] = useState(10);

  const resetForm = () => {
    setEditMapId(null);
    setMapProviderId("");
    setMapGroup("");
    setMapRole("");
    setMapPolicyId("");
  };

  return (
    <div className="grid-2">
      <div className="card">
        <h3>{editMapId ? "Edit Group Mapping" : "Create Group Mapping"}</h3>
        {!editMapId && (
          <>
            <label>Auth Provider Scope (Optional)</label>
            <select value={mapProviderId} onChange={(e) => setMapProviderId(e.target.value)}>
              <option value="">Any Provider / API Key</option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>{p.name} ({p.provider_type})</option>
              ))}
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
          {policies.map((p) => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
        <label>Priority (higher number wins when caller has multiple groups)</label>
        <input type="number" value={mapPriority} onChange={(e) => setMapPriority(Number(e.target.value))} />
        <div className="btn-row">
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
                resetForm();
                await refreshAll();
              })
            }
          >
            {editMapId ? "Save Changes" : "Add Mapping"}
          </button>
          {editMapId && (
            <button className="btn btn-danger" onClick={resetForm}>
              Cancel
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Group Mappings ({mappings.length})</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Group</th>
                <th>Policy</th>
                <th>Role</th>
                <th className="nowrap">Priority</th>
                <th className="actions-col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {mappings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty-row">No group mappings configured yet.</td>
                </tr>
              ) : (
                mappings.map((m) => {
                  const policyName = policies.find((p) => p.id === m.policy_id)?.name || m.policy_id;
                  return (
                    <tr key={m.id}>
                      <td>{m.external_group}</td>
                      <td>{policyName}</td>
                      <td>{m.policy_role || "(default)"}</td>
                      <td className="nowrap">{m.priority}</td>
                      <td className="actions-col">
                        <div className="action-buttons">
                          <button
                            className="btn btn-sm"
                            onClick={() => {
                              setEditMapId(m.id);
                              setMapGroup(m.external_group);
                              setMapRole(m.policy_role || "");
                              setMapPolicyId(m.policy_id);
                              setMapPriority(m.priority);
                            }}
                          >
                            Edit
                          </button>
                          <button
                            className="btn btn-sm btn-danger"
                            onClick={() =>
                              runAction(async () => {
                                await api(`/api/admin/group-mappings/${m.id}`, { method: "DELETE" });
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
