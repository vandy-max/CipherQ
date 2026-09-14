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
  const inFlightRef = useRef(false);
  const inFlightSessionRef = useRef(null);
  const assessmentGenerationRef = useRef(0);

  const refresh = useCallback(async () => {
    if (!monitoringSessionId) return;
    const generation = assessmentGenerationRef.current;
    const requestedSession = monitoringSessionId;
    // Do not duplicate an assessment for the same session, but do allow a
    // fresh session to start its own assessment while an old-session
    // request is still finishing.
    if (inFlightRef.current && inFlightSessionRef.current === requestedSession) return;
    inFlightRef.current = true;
    inFlightSessionRef.current = requestedSession;
    setAssessing(true);
    setError("");
    try {
      const result = await assessSecurity(requestedSession);
      // A slow assessment from an older monitoring session must never
      // overwrite the decision for the new session after reauthentication.
      if (generation === assessmentGenerationRef.current) {
        setDecision(result);
      }
    } catch (err) {
      if (generation === assessmentGenerationRef.current) {
        setError(err.message || "Qira assessment failed");
      }
    } finally {
      if (generation === assessmentGenerationRef.current) setAssessing(false);
      if (inFlightSessionRef.current === requestedSession) {
        inFlightRef.current = false;
        inFlightSessionRef.current = null;
      }
    }
  }, [monitoringSessionId]);

  useEffect(() => {
    if (!monitoringSessionId || !snapshot) return;
    const key = significantKey(snapshot);
    if (key === lastKeyRef.current) return;
    lastKeyRef.current = key;
    refresh();
  }, [monitoringSessionId, snapshot, refresh]);

  // Reset shared state when the monitoring session itself changes
  // (e.g. after reauthentication starts a fresh session) so a stale
  // decision from the PREVIOUS session never lingers on screen.
  useEffect(() => {
    assessmentGenerationRef.current += 1;
    lastKeyRef.current = null;
    setDecision(null);
    setError("");
    setAssessing(false);
  }, [monitoringSessionId]);

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
