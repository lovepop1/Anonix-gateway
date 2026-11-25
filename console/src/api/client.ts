export async function requestJson<T>(
  path: string,
  token: string,
  onUnauthorized: () => void,
  opts: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((opts.headers as Record<string, string>) || {}),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401 && token) {
    onUnauthorized();
    throw new Error("Session expired — please sign in again.");
  }
  if (res.status === 204) {
    return null as T;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `Request failed (${res.status})`);
  }
  return data as T;
}
