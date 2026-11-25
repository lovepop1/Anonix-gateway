import { useState } from "react";
import type { AdminUser, TabContextProps } from "../types";

interface UsersTabProps extends TabContextProps {
  users: AdminUser[];
  adminEmail: string;
}

export function UsersTab({ users, adminEmail, busy, api, runAction, refreshAll, setNotice }: UsersTabProps) {
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPass, setNewUserPass] = useState("");
  const [newUserRole, setNewUserRole] = useState<AdminUser["role"]>("policy_author");

  return (
    <div className="grid-2">
      <div className="card">
        <h3>Create Admin User</h3>
        <label>Email</label>
        <input
          type="email"
          value={newUserEmail}
          onChange={(e) => setNewUserEmail(e.target.value)}
          placeholder="user@example.com"
        />
        <label>Password (min 8 characters)</label>
        <input type="password" value={newUserPass} onChange={(e) => setNewUserPass(e.target.value)} />
        <label>Role</label>
        <select
          value={newUserRole}
          onChange={(e) => setNewUserRole(e.target.value as AdminUser["role"])}
        >
          <option value="platform_admin">platform_admin</option>
          <option value="policy_author">policy_author</option>
          <option value="auditor">auditor</option>
        </select>
        <button
          className="btn"
          disabled={busy}
          onClick={() =>
            runAction(async () => {
              await api("/api/admin/users", {
                method: "POST",
                body: JSON.stringify({ email: newUserEmail, password: newUserPass, role: newUserRole }),
              });
              setNotice(`Admin user '${newUserEmail}' created.`);
              setNewUserEmail("");
              setNewUserPass("");
              await refreshAll();
            })
          }
        >
          Add Admin User
        </button>
      </div>

      <div className="card">
        <h3>Admin Users</h3>
        <table>
          <thead>
            <tr><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr>
          </thead>
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
                      onChange={(e) =>
                        runAction(async () => {
                          await api(`/api/admin/users/${u.id}`, {
                            method: "PATCH",
                            body: JSON.stringify({ role: e.target.value }),
                          });
                          await refreshAll();
                        })
                      }
                    >
                      <option value="platform_admin">platform_admin</option>
                      <option value="policy_author">policy_author</option>
                      <option value="auditor">auditor</option>
                    </select>
                  </td>
                  <td>{u.is_active ? "active" : "disabled"}</td>
                  <td className="action-cell">
                    {!isSelf && (
                      <>
                        <button
                          className="btn btn-sm"
                          onClick={() =>
                            runAction(async () => {
                              await api(`/api/admin/users/${u.id}`, {
                                method: "PATCH",
                                body: JSON.stringify({ is_active: !u.is_active }),
                              });
                              await refreshAll();
                            })
                          }
                        >
                          {u.is_active ? "Disable" : "Enable"}
                        </button>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() =>
                            runAction(async () => {
                              await api(`/api/admin/users/${u.id}`, { method: "DELETE" });
                              await refreshAll();
                            })
                          }
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
  );
}
