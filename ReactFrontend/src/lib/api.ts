/**
 * API client for the Django backend.
 *
 * Replaces supabase.ts — handles:
 *   - Base URL configuration
 *   - JWT token storage (localStorage)
 *   - Auto-attach Authorization header
 *   - Token refresh on 401
 *   - Typed request helpers (get, post, patch, delete, upload)
 */

const API_BASE = "http://127.0.0.1:8000/api/v1";

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

export function getAccessToken(): string | null {
  return localStorage.getItem("access_token");
}

export function getRefreshToken(): string | null {
  return localStorage.getItem("refresh_token");
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem("access_token", access);
  localStorage.setItem("refresh_token", refresh);
}

export function clearTokens() {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
}

// ---------------------------------------------------------------------------
// Core fetch wrapper
// ---------------------------------------------------------------------------

async function apiFetch(
  endpoint: string,
  options: RequestInit = {}
): Promise<Response> {
  const url = `${API_BASE}${endpoint}`;

  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string> || {}),
  };

  // Auto-attach JWT token (skip for FormData — browser sets Content-Type)
  const token = getAccessToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Set Content-Type for JSON requests (not for FormData uploads)
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(url, { ...options, headers });

  // Auto-refresh on 401
  if (response.status === 401 && getRefreshToken()) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      // Retry the original request with new token
      headers["Authorization"] = `Bearer ${getAccessToken()}`;
      return fetch(url, { ...options, headers });
    } else {
      // Refresh failed — clear tokens and redirect to login
      clearTokens();
      window.location.href = "/login";
    }
  }

  return response;
}

async function refreshAccessToken(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  try {
    const response = await fetch(`${API_BASE}/auth/token/refresh/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh: refreshToken }),
    });

    if (response.ok) {
      const data = await response.json();
      setTokens(data.access, refreshToken);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Typed request helpers
// ---------------------------------------------------------------------------

export async function api<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<{ data: T | null; error: string | null; status: number }> {
  try {
    const response = await apiFetch(endpoint, options);
    const status = response.status;

    if (response.ok) {
      // Handle empty responses (204 No Content)
      const text = await response.text();
      const data = text ? JSON.parse(text) : null;
      return { data: data as T, error: null, status };
    }

    // Parse error response
    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.detail ||
      errorData.error ||
      errorData.message ||
      Object.values(errorData).flat().join(", ") ||
      `Request failed (${status})`;
    return { data: null, error: errorMessage, status };
  } catch (err: any) {
    return { data: null, error: err.message || "Network error", status: 0 };
  }
}

export async function apiGet<T = any>(endpoint: string) {
  return api<T>(endpoint, { method: "GET" });
}

export async function apiPost<T = any>(endpoint: string, body?: any) {
  return api<T>(endpoint, {
    method: "POST",
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function apiPatch<T = any>(endpoint: string, body?: any) {
  return api<T>(endpoint, {
    method: "PATCH",
    body: body ? JSON.stringify(body) : undefined,
  });
}

export async function apiDelete<T = any>(endpoint: string) {
  return api<T>(endpoint, { method: "DELETE" });
}

export async function apiUpload<T = any>(endpoint: string, formData: FormData) {
  return api<T>(endpoint, {
    method: "POST",
    body: formData,
    // Don't set Content-Type — browser sets it with boundary for FormData
  });
}
