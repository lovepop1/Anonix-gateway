import type { AuditEvent } from "../types";

interface AuditTabProps {
  audits: AuditEvent[];
}

export function AuditTab({ audits }: AuditTabProps) {
  return (
    <div className="card">
      <h3>Zero-PII Audit Log ({audits.length})</h3>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th className="nowrap">Time</th>
              <th>Caller</th>
              <th className="nowrap">Auth</th>
              <th className="nowrap">Role</th>
              <th className="nowrap">Format</th>
              <th className="nowrap">Status</th>
              <th className="nowrap">Latency</th>
            </tr>
          </thead>
          <tbody>
            {audits.length === 0 ? (
              <tr>
                <td colSpan={7} className="empty-row">No audit events recorded yet.</td>
              </tr>
            ) : (
              audits.map((a) => (
                <tr key={a.id}>
                  <td className="nowrap">{new Date(a.created_at).toLocaleString()}</td>
                  <td>{a.caller_id}</td>
                  <td className="nowrap">{a.auth_method}</td>
                  <td className="nowrap">{a.resolved_role || "-"}</td>
                  <td className="nowrap">{a.format_name || "-"}</td>
                  <td className="nowrap">{a.status_code}</td>
                  <td className="nowrap">{a.duration_ms} ms</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
