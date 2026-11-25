import type { AuditEvent } from "../types";

interface AuditTabProps {
  audits: AuditEvent[];
}

export function AuditTab({ audits }: AuditTabProps) {
  return (
    <div className="card">
      <h3>Zero-PII Audit Log</h3>
      <table>
        <thead>
          <tr><th>Time</th><th>Caller</th><th>Auth</th><th>Role</th><th>Format</th><th>Status</th><th>Latency</th></tr>
        </thead>
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
  );
}
