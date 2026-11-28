import React, { useCallback, useEffect, useState } from "react";
import { requestJson } from "./api/client";
import { AuditTab } from "./components/AuditTab";
import { AuthTab } from "./components/AuthTab";
import { KeysTab } from "./components/KeysTab";
import { MappingsTab } from "./components/MappingsTab";
import { PoliciesTab } from "./components/PoliciesTab";
import { RoutesTab } from "./components/RoutesTab";
import { UpstreamsTab } from "./components/UpstreamsTab";
import { UsersTab } from "./components/UsersTab";
import type {
  AdminUser,
  ApiKey,
  AuditEvent,
  AuthProvider,
  GroupMapping,
  Policy,
  ProxyRoute,
  TabId,
  Upstream,
} from "./types";

const TABS: TabId[] = ["policies", "auth", "mappings", "keys", "upstreams", "routes", "users", "audit"];

export default function App() {
  const [bootstrapped, setBootstrapped] = useState<boolean | null>(null);
  const [token, setToken] = useState<string>(() => localStorage.getItem("anonix_admin_token") || "");
  const [adminEmail, setAdminEmail] = useState<string>(() => localStorage.getItem("anonix_admin_email") || "");
  const [tab, setTab] = useState<TabId>("policies");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [providers, setProviders] = useState<AuthProvider[]>([]);
  const [mappings, setMappings] = useState<GroupMapping[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [upstreams, setUpstreams] = useState<Upstream[]>([]);
  const [routes, setRoutes] = useState<ProxyRoute[]>([]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audits, setAudits] = useState<AuditEvent[]>([]);

  const logout = useCallback(() => {
    localStorage.removeItem("anonix_admin_token");
    localStorage.removeItem("anonix_admin_email");
    setToken("");
    setAdminEmail("");
  }, []);

  const api = useCallback(
    <T,>(path: string, opts: RequestInit = {}) => requestJson<T>(path, token, logout, opts),
    [token, logout]
  );

  const runAction = useCallback(
    async (fn: () => Promise<void>) => {
      if (busy) return;
      setBusy(true);
      setError("");
      setNotice("");
      try {
        await fn();
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Operation failed.");
      } finally {
        setBusy(false);
      }
    },
    [busy]
  );

  const refreshAll = useCallback(async () => {
    if (!token) return;
    const [p, pr, m, k, u, r, us, a] = await Promise.all([
      api<Policy[]>("/api/admin/policies").catch(() => []),
      api<AuthProvider[]>("/api/admin/auth-providers").catch(() => []),
      api<GroupMapping[]>("/api/admin/group-mappings").catch(() => []),
      api<ApiKey[]>("/api/admin/api-keys").catch(() => []),
      api<Upstream[]>("/api/admin/upstreams").catch(() => []),
      api<ProxyRoute[]>("/api/admin/routes").catch(() => []),
      api<AdminUser[]>("/api/admin/users").catch(() => []),
      api<AuditEvent[]>("/api/admin/audit").catch(() => []),
    ]);
    setPolicies(p);
    setProviders(pr);
    setMappings(m);
    setApiKeys(k);
    setUpstreams(u);
    setRoutes(r);
    setUsers(us);
    setAudits(a);
  }, [token, api]);

  useEffect(() => {
    fetch("/api/setup/status")
      .then((r) => r.json())
      .then((d) => setBootstrapped(Boolean(d.bootstrapped)))
      .catch(() => setBootstrapped(true));
  }, []);

  useEffect(() => {
    if (token) {
      void refreshAll();
    }
  }, [token, refreshAll]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 4500);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (!error) return;
    const timer = window.setTimeout(() => setError(""), 8000);
    return () => window.clearTimeout(timer);
  }, [error]);

  async function handleSetup(e: React.FormEvent) {
    e.preventDefault();
    await runAction(async () => {
      const res = await api<{ access_token: string; email: string }>("/api/setup/bootstrap", {
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
      const res = await api<{ access_token: string; email: string }>("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      localStorage.setItem("anonix_admin_token", res.access_token);
      localStorage.setItem("anonix_admin_email", res.email);
      setToken(res.access_token);
      setAdminEmail(res.email);
    });
  }

  if (bootstrapped === null) {
    return <div className="center-card">Loading Anonix Gateway...</div>;
  }

  if (!bootstrapped) {
    return (
      <div className="center-card">
        <h2>Anonix Gateway — First-Run Setup</h2>
        <p className="muted-copy">Create your initial platform administrator account.</p>
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

  const shared = { busy, api, runAction, refreshAll, setNotice };

  return (
    <div className="layout">
      <div className="topbar">
        <div>
          <h2 className="brand-title">Anonix Gateway</h2>
          <span className="muted-copy">Control Plane · {adminEmail}</span>
        </div>
        <button className="btn btn-sm" onClick={logout}>Sign Out</button>
      </div>

      {error && (
        <div className="alert alert-err" role="alert">
          <span className="alert-body">{error}</span>
          <button type="button" className="alert-close" aria-label="Dismiss error" onClick={() => setError("")}>
            ×
          </button>
        </div>
      )}
      {notice && (
        <div className="alert alert-ok" role="status">
          <span className="alert-body">{notice}</span>
          <button type="button" className="alert-close" aria-label="Dismiss notice" onClick={() => setNotice("")}>
            ×
          </button>
        </div>
      )}

      <div className="tabs">
        {TABS.map((t) => (
          <button
            key={t}
            className={`tab ${tab === t ? "active" : ""}`}
            onClick={() => {
              setTab(t);
              setError("");
              setNotice("");
            }}
          >
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      {tab === "policies" && <PoliciesTab policies={policies} {...shared} />}
      {tab === "auth" && <AuthTab providers={providers} {...shared} />}
      {tab === "mappings" && <MappingsTab mappings={mappings} policies={policies} providers={providers} {...shared} />}
      {tab === "keys" && <KeysTab apiKeys={apiKeys} policies={policies} {...shared} />}
      {tab === "upstreams" && <UpstreamsTab upstreams={upstreams} {...shared} />}
      {tab === "routes" && <RoutesTab routes={routes} upstreams={upstreams} policies={policies} {...shared} />}
      {tab === "users" && <UsersTab users={users} adminEmail={adminEmail} {...shared} />}
      {tab === "audit" && <AuditTab audits={audits} />}
    </div>
  );
}
