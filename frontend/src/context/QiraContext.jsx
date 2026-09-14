import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { useMonitoringContext } from "./MonitoringContext";
import { assessSecurity, askQira } from "../services/api";

const QiraContext = createContext(null);

// Part 17 — Qira is refreshed on MEANINGFUL monitoring transitions, never
// on a fixed timer and never on every camera-driven heartbeat tick. This
// is the exact set of `snapshot` fields whose CHANGE is worth a fresh
// assessment; the polling interval itself is irrelevant here — only
// transitions between these values trigger a call.
function significantKey(snapshot) {
  if (!snapshot) return null;
  return [snapshot.status, snapshot.security_state, snapshot.identity_state, snapshot.face_present, snapshot.liveness, snapshot.current_risk, Math.floor(Number(snapshot.risk_score || 0) / 5), snapshot.warnings?.length || 0].join("|");
}

/**
 * ONE authoritative Qira assessment per monitoring session, shared by
 * every consumer (topbar badge, dashboard Continuous Monitoring card,
 * floating Qira widget) — Part 4 of the brief: "They must never
 * contradict each other." Each consumer reading its own independent
 * `/api/security/assess` call could race and show different answers
 * for a few seconds; this provider makes sure there is exactly one
 * in-flight assessment and one shared result at any time.
 *
 * Must be nested INSIDE <MonitoringProvider> — it reads
 * monitoringSessionId/snapshot from it.
 */
export function QiraProvider({ children }) {
  const { monitoringSessionId, snapshot } = useMonitoringContext();

  const [decision, setDecision] = useState(null); // last QiraDecision
  const [assessing, setAssessing] = useState(false);
  const [error, setError] = useState("");

  const lastKeyRef = useRef(null);
  const latestKeyRef = useRef(null);
  const pendingKeyRef = useRef(null);
  const lastAssessedKeyRef = useRef(null);
  const inFlightRef = useRef(false);
  const inFlightSessionRef = useRef(null);
  const assessmentGenerationRef = useRef(0);

  const refresh = useCallback(async (requestedKey = latestKeyRef.current) => {
    if (!monitoringSessionId || !requestedKey) return;

    // Never lose a newer monitoring state just because an older Qira
    // assessment is still running. Keep only the newest pending key; when
    // the current request finishes, that key is assessed next.
    if (inFlightRef.current && inFlightSessionRef.current === monitoringSessionId) {
      pendingKeyRef.current = requestedKey;
      return;
    }

    if (requestedKey === lastAssessedKeyRef.current) return;

    const generation = assessmentGenerationRef.current;
    const requestedSession = monitoringSessionId;
    inFlightRef.current = true;
    inFlightSessionRef.current = requestedSession;
    setAssessing(true);
    setError("");

    try {
      const result = await assessSecurity(requestedSession);
      // A response is accepted only if it belongs to the current monitoring
      // session generation. The key is recorded only after the response is
      // accepted, so a newer pending state can never be hidden by an older
      // assessment response.
      const isCurrentAssessment =
        generation === assessmentGenerationRef.current &&
        requestedSession === monitoringSessionId;
      const isLatestRequestedState = requestedKey === latestKeyRef.current;

      if (isCurrentAssessment && isLatestRequestedState) {
        setDecision(result);
        lastAssessedKeyRef.current = requestedKey;
      }
    } catch (err) {
      if (
        generation === assessmentGenerationRef.current &&
        requestedSession === monitoringSessionId &&
        requestedKey === latestKeyRef.current
      ) {
        setError(err.message || "Qira assessment failed");
      }
    } finally {
      if (inFlightSessionRef.current === requestedSession) {
        inFlightRef.current = false;
        inFlightSessionRef.current = null;
      }

      if (generation === assessmentGenerationRef.current && requestedSession === monitoringSessionId) {
        setAssessing(false);
        // Always prefer the latest state observed by the monitoring
        // context. The pending ref is only a compatibility queue for
        // changes observed while the request was in flight. This closes
        // the WARNING -> SECURE race where an older response could be
        // accepted after the monitoring snapshot had already recovered.
        const pendingKey = latestKeyRef.current || pendingKeyRef.current;
        pendingKeyRef.current = null;
        if (pendingKey && pendingKey !== lastAssessedKeyRef.current) {
          // Start the newest queued assessment after the current promise has
          // fully released the in-flight guard. This is intentionally one
          // follow-up request, not a polling loop.
          queueMicrotask(() => refresh(pendingKey));
        }
      }
    }
  }, [monitoringSessionId]);

  // Reset shared state when the monitoring session itself changes
  // (e.g. after reauthentication starts a fresh session) so a stale
  // decision from the PREVIOUS session never lingers on screen.
  useEffect(() => {
    assessmentGenerationRef.current += 1;
    lastKeyRef.current = null;
    latestKeyRef.current = null;
    pendingKeyRef.current = null;
    lastAssessedKeyRef.current = null;
    setDecision(null);
    setError("");
    setAssessing(false);
  }, [monitoringSessionId]);

  useEffect(() => {
    if (!monitoringSessionId || !snapshot) return;
    const key = significantKey(snapshot);
    latestKeyRef.current = key;
    if (key === lastKeyRef.current) return;
    lastKeyRef.current = key;
    refresh(key);
  }, [monitoringSessionId, snapshot, refresh]);

  const ask = useCallback(
    async (question) => {
      if (!monitoringSessionId) throw new Error("No active monitoring session");
      return askQira(monitoringSessionId, question);
    },
    [monitoringSessionId]
  );

  return (
    <QiraContext.Provider value={{ decision, assessing, error, refresh, ask }}>{children}</QiraContext.Provider>
  );
}

export function useQiraContext() {
  const ctx = useContext(QiraContext);
  if (!ctx) {
    throw new Error("useQiraContext must be used within a QiraProvider");
  }
  return ctx;
}