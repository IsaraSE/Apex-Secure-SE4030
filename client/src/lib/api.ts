// [SECURITY][V5] VULNERABLE: axios 1.0.0-1.17.0 has SSRF and prototype-pollution issues. A06:2021

import axios from "axios";

const normalizeApiBaseUrl = (value: string | undefined): string => {
  const rawValue = value?.trim();

  if (!rawValue) {
    return "/api";
  }

  if (rawValue.startsWith("/")) {
    return rawValue.replace(/\/+$/, "") || "/api";
  }

  const absoluteValue = /^https?:\/\//i.test(rawValue) ? rawValue : `https://${rawValue}`;
  const url = new URL(absoluteValue);

  if (url.pathname === "/" || url.pathname === "") {
    url.pathname = "/api";
  } else if (!url.pathname.endsWith("/api")) {
    url.pathname = `${url.pathname.replace(/\/+$/, "")}/api`;
  }

  return url.toString().replace(/\/+$/, "");
};

const API_BASE_URL = normalizeApiBaseUrl(process.env.NEXT_PUBLIC_API_URL);

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor — attach JWT
api.interceptors.request.use(
  (config) => {
    if (globalThis.window !== undefined) {
      const token = localStorage.getItem("accessToken");
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor — handle 401 refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = localStorage.getItem("refreshToken");
        if (refreshToken) {
          const res = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refreshToken,
          });

          const { accessToken, refreshToken: newRefreshToken } = res.data;
          localStorage.setItem("accessToken", accessToken);
          localStorage.setItem("refreshToken", newRefreshToken);

          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return api(originalRequest);
        }
      } catch {
        localStorage.removeItem("accessToken");
        localStorage.removeItem("refreshToken");
        localStorage.removeItem("user");
        if (globalThis.window !== undefined) {
          globalThis.window.location.href = "/login";
        }
      }
    }

    throw error;
  }
);

export default api;
