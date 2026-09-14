const BASE = "/api";

class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
    this.status = status;
    this.detail = detail;
  }
}

function getToken() {
  return localStorage.getItem("ibqc_token");
}

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 204) return null;

  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    throw new ApiError(res.status, data?.detail ?? data ?? res.statusText);
  }
  return data;
}

// ---------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------
// `role` is optional and, when sent, may only be "USER_LEVEL_1" or
// "USER_LEVEL_2" — the backend rejects/ignores anything else (including
// "ADMIN"). Admin accounts are never created through this endpoint.
export const register = (username, email, password, role) =>
  request("/auth/register", {
    method: "POST",
    body: { username, email, password, ...(role ? { role } : {}) },
    auth: false,
  });

export const login = (username, password) =>
  request("/auth/login", { method: "POST", body: { username, password }, auth: false });

// ---------------------------------------------------------------------
// Face auth (identity only)
// ---------------------------------------------------------------------
export const enrollFace = (descriptor) =>
  request("/face/enroll", { method: "POST", body: { descriptor } });

export const verifyFace = (descriptor) =>
  request("/face/verify", { method: "POST", body: { descriptor } });

export const faceStatus = () => request("/face/status");

// ---------------------------------------------------------------------
// Quantum (BB84)
// ---------------------------------------------------------------------
export const generateQuantumKey = (nQubits, eavesdropProb) =>
  request("/quantum/generate-key", {
    method: "POST",
    body: { n_qubits: nQubits, eavesdrop_prob: eavesdropProb },
  });

export const quantumBackendInfo = () => request("/quantum/info", { auth: false });

// ---------------------------------------------------------------------
// Intent
// ---------------------------------------------------------------------
export const createIntent = (cid, reason) =>
  request("/intent", { method: "POST", body: { cid, reason } });

export const validateIntent = (cid, intentId) =>
  request("/intent/validate", { method: "POST", body: { cid, intent_id: intentId ?? null } });

export const transitionIntent = (intentId, targetState, reason) =>
  request(`/intent/${intentId}/transition`, {
    method: "POST",
    body: { target_state: targetState, reason },
  });

export const listIntents = (lifecycleState) =>
  request(lifecycleState ? `/intent?lifecycle_state=${lifecycleState}` : "/intent");

// Fix pass section F: resolve an approved intent's authoritative
// detail (owner, resource, operation, purpose, lifecycle, and —
// crucially — validity window) from its hash. Nothing about the
// validity window shown afterward is client-supplied.
export const resolveIntentByHash = (intentHash) =>
  request(`/intent/by-hash/${encodeURIComponent(intentHash)}`);

// ---------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------
export const encrypt = (intentId, cid, plaintextBase64, quantumKeyHex, faceDescriptor) =>
  request("/encrypt", {
    method: "POST",
    body: {
      intent_id: intentId,
      cid,
      plaintext_base64: plaintextBase64,
      quantum_key_hex: quantumKeyHex,
      face_descriptor: faceDescriptor ?? null,
    },
  });

export const decrypt = (recordId, cid, quantumKeyHex, faceDescriptor) =>
  request("/decrypt", {
    method: "POST",
    body: {
      record_id: recordId,
      cid,
      quantum_key_hex: quantumKeyHex,
      face_descriptor: faceDescriptor ?? null,
    },
  });

// ---------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------
export const listAuditLogs = () => request("/audit/logs");
export const verifyAuditChain = () => request("/audit/verify");

// ---------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------
export const listPolicies = () => request("/policies");
export const createPolicy = (name, ruleType, config, active) =>
  request("/policies", { method: "POST", body: { name, rule_type: ruleType, config, active } });
export const updatePolicy = (id, name, ruleType, config, active) =>
  request(`/policies/${id}`, { method: "PUT", body: { name, rule_type: ruleType, config, active } });
export const deletePolicy = (id) => request(`/policies/${id}`, { method: "DELETE" });

// ---------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------
export const assessRisk = (factors) =>
  request("/risk/assess", { method: "POST", body: factors });

// ---------------------------------------------------------------------
// Authorization (devices / sessions — continuous authorization)
// ---------------------------------------------------------------------
export const getDeviceStatus = (deviceId) => request(`/authorization/devices/${deviceId}`);
export const getDeviceTrust = (deviceId) => request(`/authorization/devices/${deviceId}/trust`);
export const revokeDevice = (deviceId) =>
  request(`/authorization/devices/${deviceId}/revoke`, { method: "POST" });
export const unrevokeDevice = (deviceId) =>
  request(`/authorization/devices/${deviceId}/unrevoke`, { method: "POST" });
export const getSessionStatus = (sessionId) => request(`/authorization/sessions/${sessionId}`);
export const revokeSession = (sessionId) =>
  request(`/authorization/sessions/${sessionId}/revoke`, { method: "POST" });
export const refreshSession = (sessionId, deviceId, ttlMinutes = 60) =>
  request(`/authorization/sessions/${sessionId}/refresh`, {
    method: "POST",
    body: { device_id: deviceId, ttl_minutes: ttlMinutes },
  });

// ---------------------------------------------------------------------
// Trusted location / geofence
// ---------------------------------------------------------------------
export const getTrustedLocation = () => request("/location/trust");
export const enrollTrustedLocation = (latitude, longitude, accuracyM) =>
  request("/location/trust", {
    method: "POST",
    body: { latitude, longitude, accuracy_m: accuracyM },
  });
export const clearTrustedLocation = () => request("/location/trust", { method: "DELETE" });
export const checkLocation = (latitude, longitude, accuracyM, radiusM) =>
  request("/location/check", {
    method: "POST",
    body: { latitude, longitude, accuracy_m: accuracyM, radius_m: radiusM },
  });

// The ONLY way to restore a revoked session — requires a live face
// descriptor. Normal `refreshSession` above will now correctly fail
// (403) against a revoked session rather than silently un-revoking
// it (fix pass section A); this is the explicit re-authentication
// path the UI must fall back to.
export const reauthenticateSession = (
  sessionId,
  deviceId,
  faceDescriptor,
  ttlMinutes = 60,
  reauthRequestId = null
) =>
  request(`/authorization/sessions/${sessionId}/reauthenticate`, {
    method: "POST",
    body: {
      device_id: deviceId,
      face_descriptor: faceDescriptor,
      ttl_minutes: ttlMinutes,
      ...(reauthRequestId != null ? { reauth_request_id: reauthRequestId } : {}),
    },
  });

// ---------------------------------------------------------------------
// Continuous monitoring
// ---------------------------------------------------------------------
export const startMonitoring = (deviceId, sessionId, faceConfidence, intentId) =>
  request("/monitoring/start", {
    method: "POST",
    body: {
      device_id: deviceId,
      session_id: sessionId,
      face_confidence: faceConfidence,
      intent_id: intentId ?? null,
    },
  });

export const monitoringHeartbeat = (
  monitoringSessionId,
  { facePresent, faceMatchConfidence = null, liveness = true, cameraAvailable = true, expressionHint = null }
) =>
  request("/monitoring/heartbeat", {
    method: "POST",
    body: {
      monitoring_session_id: monitoringSessionId,
      face_present: facePresent,
      face_match_confidence: faceMatchConfidence,
      liveness,
      camera_available: cameraAvailable,
      expression_hint: expressionHint,
    },
  });

export const getMonitoringStatus = (monitoringSessionId) =>
  request(`/monitoring/${monitoringSessionId}`);

export const getMonitoringForSession = (sessionId) =>
  request(`/monitoring/by-session/${encodeURIComponent(sessionId)}`);

export const listMonitoringEvents = (monitoringSessionId) =>
  request(`/monitoring/${monitoringSessionId}/events`);

export const stopMonitoring = (monitoringSessionId) =>
  request(`/monitoring/${monitoringSessionId}/stop`, { method: "POST" });

// ---------------------------------------------------------------------
// Admin: users & roles
// ---------------------------------------------------------------------
export const listUsers = () => request("/users");
export const updateUserRole = (userId, role) =>
  request(`/users/${userId}/role`, { method: "PUT", body: { role } });

export const getUserRiskOverview = () => request("/security/risk-overview");

// ---------------------------------------------------------------------
// Qira — CipherQ Security Copilot
// ---------------------------------------------------------------------
export const getSecurityContext = (monitoringSessionId, locationPermissionState) =>
  request(
    `/security/context?monitoring_session_id=${encodeURIComponent(monitoringSessionId)}` +
      (locationPermissionState
        ? `&location_permission_state=${encodeURIComponent(locationPermissionState)}`
        : "")
  );

export const assessSecurity = (monitoringSessionId, locationPermissionState) =>
  request("/security/assess", {
    method: "POST",
    body: {
      monitoring_session_id: monitoringSessionId,
      location_permission_state: locationPermissionState ?? undefined,
    },
  });

export const askQira = (monitoringSessionId, question) =>
  request("/security/ask", {
    method: "POST",
    body: { monitoring_session_id: monitoringSessionId, question },
  });

// Admin-only: security incidents queue (Qira Part 13/14).
export const listSecurityIncidents = (resolved) =>
  request(`/security/incidents${resolved === undefined ? "" : `?resolved=${resolved}`}`);

export const resolveSecurityIncident = (incidentId, note) =>
  request(`/security/incidents/${incidentId}/resolve`, {
    method: "POST",
    body: { note },
  });

// ---------------------------------------------------------------------
// Reauthorization requests — the in-app path for a user whose DEVICE
// (not just session) was revoked by continuous monitoring. Normal
// `reauthenticateSession` above deliberately refuses to fix that case
// on its own (see authorization/reauth_requests.py); this is the
// escalation path to an admin instead.
// ---------------------------------------------------------------------
export const createReauthRequest = (deviceId, sessionId, message) =>
  request("/reauth-requests", {
    method: "POST",
    body: { device_id: deviceId, session_id: sessionId, message },
  });

// The user's own request history, newest first — used to poll for
// the admin's decision without needing a dedicated push channel.
export const listMyReauthRequests = () => request("/reauth-requests/mine");

// Admin-only: the full queue, optionally filtered to one status.
export const listReauthRequests = (statusFilter) =>
  request(`/reauth-requests${statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : ""}`);

export const approveReauthRequest = (requestId, note) =>
  request(`/reauth-requests/${requestId}/approve`, { method: "POST", body: { note: note || null } });

export const rejectReauthRequest = (requestId, note) =>
  request(`/reauth-requests/${requestId}/reject`, { method: "POST", body: { note: note || null } });

export { ApiError };
