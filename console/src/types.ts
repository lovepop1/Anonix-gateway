export type TabId =
  | "policies"
  | "auth"
  | "mappings"
  | "keys"
  | "upstreams"
  | "routes"
  | "users"
  | "audit";

export interface PolicyVersion {
  id: string;
  version_number: number;
  status: string;
  yaml_content: string;
  created_by: string;
  created_at: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  created_at: string;
  versions: PolicyVersion[];
}

export interface AuthProvider {
  id: string;
  name: string;
  provider_type: "oidc" | "trusted_proxy";
  is_enabled: boolean;
  issuer_url: string | null;
  audience: string | null;
  jwks_url: string | null;
  groups_claim: string;
  sub_claim: string;
  trusted_cidrs: string[];
  has_proxy_secret: boolean;
  created_at: string;
}

export interface GroupMapping {
  id: string;
  provider_id: string | null;
  external_group: string;
  policy_role: string | null;
  policy_id: string;
  priority: number;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  groups: string[];
  allowed_policy_ids: string[] | null;
  is_active: boolean;
  expires_at: string | null;
  last_used_at: string | null;
}

export interface Upstream {
  id: string;
  name: string;
  base_url: string;
  auth_type: "none" | "bearer" | "api_key_header" | "basic";
  auth_header_name: string | null;
  has_credential: boolean;
  timeout_seconds: number;
  is_active: boolean;
}

export interface ProxyRoute {
  id: string;
  name: string;
  route_prefix: string;
  upstream_id: string;
  policy_id: string;
  strip_prefix: boolean;
  allowed_methods: string[];
  blocked_subpaths: string[];
  allow_policy_override: boolean;
  on_unstructured: "fail_closed" | "passthrough";
  is_active: boolean;
}

export interface AdminUser {
  id: string;
  email: string;
  role: "platform_admin" | "policy_author" | "auditor";
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AuditEvent {
  id: string;
  request_id: string;
  caller_id: string;
  auth_method: string;
  route_id: string | null;
  policy_id: string | null;
  policy_version: number | null;
  resolved_role: string | null;
  format_name: string | null;
  status_code: number;
  duration_ms: number;
  created_at: string;
}

export interface TabContextProps {
  busy: boolean;
  api: <T>(path: string, opts?: RequestInit) => Promise<T>;
  runAction: (fn: () => Promise<void>) => Promise<void>;
  refreshAll: () => Promise<void>;
  setNotice: (msg: string) => void;
}
