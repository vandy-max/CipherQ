import { useState, useCallback, useEffect } from "react";
import { stopMonitoring } from "../services/api";

function randomId() {
  if (window.crypto?.randomUUID) return window.crypto.randomUUID();
  return `id-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function computeDeviceFingerprint() {
  const signals = [
    navigator.userAgent || "",
    navigator.platform || "",
    navigator.language || "",
    String(navigator.hardwareConcurrency || ""),
    String(screen.width) + "x" + String(screen.height),
    String(screen.colorDepth || ""),
    String(Intl.DateTimeFormat().resolvedOptions().timeZone || ""),
  ].join("::");

  if (window.crypto?.subtle?.digest) {
    try {
      const bytes = new TextEncoder().encode(signals);
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      const hex = Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      return `fp-${hex.slice(0, 32)}`;
    } catch {
      // fall through
    }
  }
  let hash = 0;
  for (let i = 0; i < signals.length; i++) hash = (hash * 31 + signals.charCodeAt(i)) | 0;
  return `fp-${Math.abs(hash).toString(16)}`;
}

// Device trust is ACCOUNT-SCOPED. The same physical browser can be used
// to test Admin and User accounts without one account inheriting the other's
// revoked-device state. The backend still owns the final trust decision.
async function getOrCreateDeviceIdForUser(userId) {
  const key = `ibqc_device_id_${userId}`;
  let id = localStorage.getItem(key);
  if (id) return id;

  const base = await computeDeviceFingerprint();
  id = `${base}-u${userId}`;
  localStorage.setItem(key, id);
  return id;
}

export function useAuth() {
  const [token, setToken] = useState(() => localStorage.getItem("ibqc_token"));
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("ibqc_user") || "null");
    } catch {
      return null;
    }
  });
  const [deviceId, setDeviceId] = useState(() => {
    const savedUser = (() => {
      try { return JSON.parse(localStorage.getItem("ibqc_user") || "null"); } catch { return null; }
    })();
    return savedUser?.userId ? localStorage.getItem(`ibqc_device_id_${savedUser.userId}`) : null;
  });
  const [sessionId, setSessionId] = useState(() => localStorage.getItem("ibqc_session_id"));

  useEffect(() => {
    if (!user?.userId || deviceId) return;
    let cancelled = false;
    getOrCreateDeviceIdForUser(user.userId).then((id) => {
      if (!cancelled) setDeviceId(id);
    });
    return () => { cancelled = true; };
  }, [user?.userId, deviceId]);

  const saveAuth = useCallback(async (authResult) => {
    const u = {
      userId: authResult.user_id,
      username: authResult.username,
      role: authResult.role,
    };
    const newSessionId = randomId();
    const userDeviceId = await getOrCreateDeviceIdForUser(u.userId);

    localStorage.setItem("ibqc_token", authResult.token);
    localStorage.setItem("ibqc_user", JSON.stringify(u));
    localStorage.setItem("ibqc_session_id", newSessionId);
    // Remove the legacy browser-global device key so old test state cannot
    // leak into this account-scoped device identity.
    localStorage.removeItem("ibqc_device_id");

    setToken(authResult.token);
    setUser(u);
    setDeviceId(userDeviceId);
    setSessionId(newSessionId);
  }, []);

  const logout = useCallback(async () => {
    // Stop the authoritative backend monitoring session BEFORE clearing
    // the bearer token. This prevents a logout/login on the same browser
    // from leaving the previous account's monitoring session alive.
    const monitoringSessionId = sessionStorage.getItem("ibqc_monitoring_session_id");
    if (monitoringSessionId) {
      try {
        await stopMonitoring(monitoringSessionId);
      } catch {
        // Best effort; frontend state is still cleared below.
      }
    }
    sessionStorage.removeItem("ibqc_monitoring_session_id");
    localStorage.removeItem("ibqc_token");
    localStorage.removeItem("ibqc_user");
    localStorage.removeItem("ibqc_session_id");
    sessionStorage.removeItem("ibqc_security_access_consent");
    sessionStorage.removeItem("ibqc_face_verified_this_login");
    sessionStorage.removeItem("ibqc_pending_monitoring_face_confidence");
    setToken(null);
    setUser(null);
    setDeviceId(null);
    setSessionId(null);
  }, []);

  return { token, user, deviceId, sessionId, saveAuth, logout, isAuthenticated: !!token };
}
