import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import Webcam from "react-webcam";
import {
  startMonitoring as apiStartMonitoring,
  monitoringHeartbeat,
  stopMonitoring as apiStopMonitoring,
  getMonitoringStatus,
  getMonitoringForSession,
  getDeviceStatus,
  getSessionStatus,
  refreshSession,
  reauthenticateSession,
  verifyFace,
} from "../services/api";
import { detectFaceLite, extractDescriptor, assessQuality, loadModels } from "../services/faceIdentity";

const MonitoringContext = createContext(null);

// See LoginPage: after LOGIN -> FACE VERIFIED, the confidence from
// that verification is stashed here so the freshly-mounted (post
// navigate) MonitoringProvider can immediately start the continuous
// monitoring session — "MONITORING SESSION STARTED".
const PENDING_CONFIDENCE_KEY = "ibqc_pending_monitoring_face_confidence";

// PART 4 — configurable monitoring interval, not hard-coded around
// one arbitrary value. Frames are sampled/processed at this interval
// rather than on every webcam frame, to avoid burning CPU/GPU and to
// avoid generating an unbounded number of /face/verify + audit
// entries. Override via VITE_MONITORING_INTERVAL_MS at build time.
const MONITORING_INTERVAL_MS = Number(import.meta.env?.VITE_MONITORING_INTERVAL_MS) || 5000;

// A heartbeat request must fail this many times in a row before the
// UI stops trusting the last-known ACTIVE status and shows
// "connection lost" instead (PART 11) — one blip on a flaky network
// shouldn't flip the whole badge.
const CONNECTION_LOST_AFTER_FAILURES = 2;

// Heartbeat ("I'm still alive") and state refresh ("what is my
// CURRENT authoritative security state") are different things (fix
// pass: continuous-monitoring-lifecycle). Heartbeat runs every
// MONITORING_INTERVAL_MS above; this is the separate, slower cadence
// for re-pulling device/session/monitoring status from their own
// authoritative endpoints — the same ones AdminDashboard's
// Devices & Sessions panel and the monitoring GET-status endpoint
// already expose. Override via VITE_MONITORING_REFRESH_MS.
const STATE_REFRESH_INTERVAL_MS = Number(import.meta.env?.VITE_MONITORING_REFRESH_MS) || 20000;

const CAMERA_CONSTRAINTS = { width: 320, height: 240, facingMode: "user" };

// PART: continuous-monitoring-lifecycle (reauthentication race fix).
// Opening the webcam stream and loading the face-api models both take
// real, non-zero time, and both are torn down and re-requested from
// scratch every time a monitoring session (re)starts — including right
// after `reauthenticate()`, the exact moment a user who was just
// revoked-then-restored is most likely to see it. The heartbeat loop
// below starts on its own fixed cadence as soon as `monitoringSessionId`
// is set, independent of whether the camera/models have actually finished
// initializing yet. Without a grace window, a camera/model that simply
// hasn't warmed up in time gets reported as `cameraAvailable: false` —
// an outright failed tick — and enough of those in a row is exactly what
// the backend's `reauth_required_after` / `invalidate_after` thresholds
// exist to act on, re-revoking a session that was never actually
// unattended. During this window (from the moment a monitoring session
// starts until the camera reports ready, capped at this many ms), a
// not-yet-ready camera is treated as "still warming up" and the tick is
// skipped entirely — no heartbeat is sent, so no failure is recorded —
// rather than reported as a failed identity check. A camera that is
// genuinely unavailable (denied permission, no device, etc.) is still
// caught: once the grace window elapses, ticks resume normally and an
// actually-missing camera starts counting toward the real thresholds.
const CAMERA_WARMUP_GRACE_MS = Number(import.meta.env?.VITE_MONITORING_CAMERA_GRACE_MS) || 8000;

// Both `/sessions/{id}/refresh` and `/sessions/{id}/reauthenticate`
// 403 with this exact substring when the DEVICE itself (not just the
// session) is revoked — a stronger boundary that no amount of face
// re-verification can clear from the client side (see
// authorization/reauth_requests.py). Detecting it lets the UI offer
// "request admin approval" instead of retrying a face check that will
// only 403 again.
function isDeviceRevokedError(err) {
  const text = typeof err?.detail === "string" ? err.detail : err?.message || "";
  return text.toLowerCase().includes("administrator must restore the device");
}

/**
 * Wraps the authenticated app. Owns the monitoring_session_id, the
 * live MonitoringSnapshot, and the actual continuous-monitoring
 * camera loop:
 *
 *   camera permission -> camera stream -> periodic frame sample ->
 *   face detection -> identity comparison (server-side /face/verify
 *   against the caller's own enrolled descriptor) -> liveness/quality
 *   check -> heartbeat (derived telemetry only, never raw video) ->
 *   backend risk/authorization decision -> updated MonitoringSnapshot
 *
 * Every tick captures a FRESH frame and re-runs detection + identity
 * comparison — nothing here reuses the confidence obtained at login
 * beyond the very first heartbeat sent immediately at `startSession`
 * (before the camera loop has had time to run once), which mirrors
 * exactly what a real "face verified at login, then watched
 * continuously from that instant" flow means.
 *
 * `simulateFaceFailure()` remains as an explicit, clearly-labelled
 * demo/test override (see MonitoringBadge's "(demo)" button) that
 * forces the *next* tick's outcome — it never replaces the real
 * camera-driven loop, it just perturbs one tick of it on purpose.
 */
export function MonitoringProvider({ user, deviceId, sessionId, children }) {
  const [monitoringSessionId, setMonitoringSessionId] = useState(null);
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState("");
  // Set specifically when the bootstrap/refresh path discovers the
  // session is REVOKED (fix pass section A) — distinct from a
  // generic `error`, so the UI can render an explicit "REAUTH
  // REQUIRED" state with a re-authentication action, rather than a
  // dead-end error string. Cleared the instant reauthenticate()
  // succeeds (or a fresh session is otherwise established).
  const [reauthRequired, setReauthRequired] = useState(false);
  // Set specifically when a face-verification-based reauthentication
  // was refused because the DEVICE itself (not just the session) is
  // revoked — the backend's `/sessions/{id}/reauthenticate` 403s with
  // a distinct message in that case (see authorization/reauth_requests.py
  // docstring for why: a revoked device is a stronger boundary a face
  // check alone can't clear). When this is true, the UI must offer
  // "request admin approval" instead of the normal face-reauth panel,
  // since retrying the same face verification will only 403 again.
  const [deviceRevoked, setDeviceRevoked] = useState(false);
  // Camera lifecycle: 'idle' | 'requesting' | 'ready' | 'unavailable'
  const [cameraState, setCameraState] = useState("idle");
  // Returning authenticated users may have a valid app session but no
  // monitoring session after a browser/page restart. In that case we
  // temporarily open the same hidden camera surface used by monitoring
  // to perform one fresh face verification before starting monitoring.
  const [returningUserVerification, setReturningUserVerification] = useState(false);
  // PART 11 — network/backend reachability, independent of `status`.
  const [connectionState, setConnectionState] = useState("connected"); // 'connected' | 'lost'
  // Fix pass (continuous-monitoring-lifecycle): the SAME authoritative
  // device/session state every consumer (CurrentDeviceCard,
  // CookieSessionIntegrityCard, MonitoringBadge) must read — never
  // independently re-fetched by each card (that was the root cause of
  // the reported desync, see refreshMonitoringState below). `null`
  // means "not fetched yet", not "revoked".
  const [deviceStatus, setDeviceStatus] = useState(null);
  const [sessionStatus, setSessionStatus] = useState(null);
  const [lastRefreshedAt, setLastRefreshedAt] = useState(null);

  const webcamRef = useRef(null);
  const returningVerificationInFlightRef = useRef(false);
  const pendingFailuresRef = useRef(0);
  const intervalRef = useRef(null);
  const stateRefreshIntervalRef = useRef(null);
  const refreshInFlightRef = useRef(false);
  const wasConnectionLostRef = useRef(false);
  const consecutiveHeartbeatFailuresRef = useRef(0);
  const tickInFlightRef = useRef(false);
  // Invalidates any in-flight work from a previous monitoring session.
  // A late heartbeat from a revoked session must never overwrite the fresh
  // session created by reauthentication.
  const monitoringGenerationRef = useRef(0);
  const cameraStateRef = useRef("idle");
  const monitoringStartInFlightRef = useRef(false);
  const lastStartedSessionKeyRef = useRef("");
  // See CAMERA_WARMUP_GRACE_MS above. `null` means "no active grace
  // window" (either never started, or the camera already reported
  // ready and the window was cleared early).
  const cameraGraceDeadlineRef = useRef(null);
  // Backend snapshots carry a monotonic revision. A slower read-only GET
  // must never overwrite a newer heartbeat response.
  const snapshotRevisionRef = useRef(-1);
  const snapshotSessionRef = useRef(null);

  useEffect(() => {
    cameraStateRef.current = cameraState;
    // The camera warmed up before the grace window elapsed — no need to
    // keep tolerating not-ready ticks any longer than that.
    if (cameraState === "ready") cameraGraceDeadlineRef.current = null;
  }, [cameraState]);

  const applySnapshot = useCallback((nextSnapshot) => {
    if (!nextSnapshot) return false;
    const nextSession = nextSnapshot.monitoring_session_id || null;
    const nextRevision = Number(nextSnapshot.snapshot_revision ?? 0);

    // A new monitoring session starts a fresh revision stream.
    if (snapshotSessionRef.current !== nextSession) {
      snapshotSessionRef.current = nextSession;
      snapshotRevisionRef.current = -1;
    }

    if (nextRevision < snapshotRevisionRef.current) {
      console.debug("[Monitoring] ignored stale snapshot", {
        session: nextSession,
        revision: nextRevision,
        currentRevision: snapshotRevisionRef.current,
      });
      return false;
    }

    snapshotRevisionRef.current = nextRevision;
    setSnapshot(nextSnapshot);
    return true;
  }, []);

  const stopLoop = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = null;
  }, []);

  const stopStateRefreshLoop = useCallback(() => {
    if (stateRefreshIntervalRef.current) clearInterval(stateRefreshIntervalRef.current);
    stateRefreshIntervalRef.current = null;
  }, []);

  // ------------------------------------------------------------------
  // THE single centralized "what is my current authoritative security
  // state" refresh (fix pass: continuous-monitoring-lifecycle, Part
  // 22/23). Re-pulls device status, session status, and — if a
  // monitoring session is running — a read-only monitoring status
  // refresh (GET /api/monitoring/{id}, distinct from the heartbeat
  // POST) from their own already-authoritative endpoints, and updates
  // ONE shared place in context. Every card that used to run its own
  // independent poll now reads deviceStatus/sessionStatus/snapshot
  // from here instead — see CurrentDeviceCard/CookieSessionIntegrityCard.
  //
  // A 404 on device/session is treated as "not established yet", NOT
  // "revoked" — revocation sets a `revoked: true` flag on an existing
  // record, it never deletes it (see authorization/devices.py,
  // authorization/sessions.py). Conflating "no record found" with
  // "revoked" was the concrete bug that could show a spurious
  // INVALIDATED/REVOKED card immediately after login, before the
  // session record had been created server-side.
  const refreshMonitoringState = useCallback(async (monitoringIdOverride = null) => {
    if (refreshInFlightRef.current) return;
    const monitoringId = monitoringIdOverride || monitoringSessionId;
    if (!deviceId && !sessionId && !monitoringId) return;
    refreshInFlightRef.current = true;
    const generation = monitoringGenerationRef.current;
    try {
      const [deviceResult, sessionResult, monitoringResult] = await Promise.allSettled([
        deviceId ? getDeviceStatus(deviceId) : Promise.resolve(null),
        sessionId ? getSessionStatus(sessionId) : Promise.resolve(null),
        monitoringId ? getMonitoringStatus(monitoringId) : Promise.resolve(null),
      ]);

      if (generation !== monitoringGenerationRef.current) return;

      if (deviceResult.status === "fulfilled") {
        if (deviceResult.value) setDeviceStatus(deviceResult.value);
      } else if (deviceResult.reason?.status !== 404) {
        // A real error (network/5xx) — leave the last-known value in
        // place rather than blanking a working card on one bad call.
        console.warn("[Monitoring] device status refresh failed", deviceResult.reason?.message);
      }

      if (sessionResult.status === "fulfilled") {
        if (sessionResult.value) setSessionStatus(sessionResult.value);
      } else if (sessionResult.reason?.status !== 404) {
        console.warn("[Monitoring] session status refresh failed", sessionResult.reason?.message);
      }

      if (monitoringResult.status === "fulfilled" && monitoringResult.value) {
        applySnapshot(monitoringResult.value);
      }

      setLastRefreshedAt(new Date().toISOString());
      console.log("[Monitoring] backend state refreshed", {
        device: deviceResult.status,
        session: sessionResult.status,
        monitoring: monitoringResult.status,
      });
    } finally {
      refreshInFlightRef.current = false;
    }
  }, [applySnapshot, deviceId, sessionId, monitoringSessionId]);

  // ------------------------------------------------------------------
  // One monitoring tick: sample a frame, run identity + liveness
  // checks against it, then heartbeat the derived result.
  // ------------------------------------------------------------------
  const tick = useCallback(async (currentMonitoringSessionId) => {
    if (tickInFlightRef.current) return; // never overlap ticks
    const generation = monitoringGenerationRef.current;
    tickInFlightRef.current = true;

    const forcingFailure = pendingFailuresRef.current > 0;
    if (forcingFailure) pendingFailuresRef.current -= 1;

    let facePresent = false;
    let faceMatchConfidence = null;
    let liveness = false;
    let cameraAvailable = cameraStateRef.current === "ready";

    // See CAMERA_WARMUP_GRACE_MS: a camera that simply hasn't finished
    // opening yet must not be sent as a failed identity check — that is
    // what let a just-restored session get silently re-revoked while the
    // hidden capture element was still (re)initializing. Skip the tick
    // outright (no heartbeat sent, nothing recorded) rather than reporting
    // a false failure; the demo "simulate failure" override always takes
    // priority and is never swallowed by this grace window.
    if (
      !forcingFailure &&
      !cameraAvailable &&
      cameraGraceDeadlineRef.current !== null &&
      Date.now() < cameraGraceDeadlineRef.current
    ) {
      tickInFlightRef.current = false;
      return;
    }

    try {
      if (forcingFailure) {
        // Demo override for this one tick only — see docstring above.
        facePresent = false;
        liveness = false;
      } else if (cameraAvailable) {
        const video = webcamRef.current?.video;
        if (video && video.readyState === 4) {
          const detection = await detectFaceLite(video);
          const quality = assessQuality(detection, video);
          facePresent = !!detection;
          liveness = facePresent && quality.ok;

          if (facePresent) {
            // Only pay for the expensive 128-d descriptor + a real
            // server-side identity comparison when a face was
            // actually found this tick — never send a cached
            // descriptor or a cached confidence value.
            const descriptor = await extractDescriptor(video);
            if (descriptor) {
              const result = await verifyFace(descriptor);
              faceMatchConfidence = result.confidence;
            } else {
              // Detected a face box but couldn't extract a usable
              // descriptor this frame (motion blur, partial
              // occlusion) — treat as present-but-unconfirmed rather
              // than fabricating a confidence value.
              faceMatchConfidence = null;
              liveness = false;
            }
          }
        } else {
          cameraAvailable = false;
        }
      }

      // The session may have been stopped/revoked/replaced while the
      // camera or face verification was still running. Do not send a late
      // heartbeat for an obsolete monitoring generation.
      if (generation !== monitoringGenerationRef.current) return;

      const result = await monitoringHeartbeat(currentMonitoringSessionId, {
        facePresent,
        faceMatchConfidence,
        liveness,
        cameraAvailable,
      });
      if (generation !== monitoringGenerationRef.current) return;
      console.log("[MONITORING] heartbeat completed", { monitoringSessionId: currentMonitoringSessionId });
      applySnapshot(result);
      setError("");
      const wasLost = wasConnectionLostRef.current;
      setConnectionState("connected");
      wasConnectionLostRef.current = false;
      consecutiveHeartbeatFailuresRef.current = 0;
      if (wasLost && generation === monitoringGenerationRef.current) {
        // PART 13/14 — network/backend just came back after a
        // temporary outage: re-pull the full authoritative state
        // (device/session/monitoring), don't just trust that this one
        // heartbeat response alone reflects everything that could
        // have changed while disconnected.
        console.log("[Monitoring] reconnecting -> backend reachable again, refreshing state");
        refreshMonitoringState();
      }
    } catch (err) {
      // A superseded session is expected to fail/finish asynchronously.
      // Never let that old request change connection health for the new
      // monitoring generation.
      if (generation !== monitoringGenerationRef.current) return;

      // Network hiccup, backend down, or session gone. PART 11: do
      // NOT keep silently showing the last-known ACTIVE status
      // forever — after enough consecutive misses, surface
      // "connection lost" so the UI stops implying a guarantee the
      // backend hasn't actually made recently.
      consecutiveHeartbeatFailuresRef.current += 1;
      if (consecutiveHeartbeatFailuresRef.current >= CONNECTION_LOST_AFTER_FAILURES) {
        setConnectionState("lost");
        wasConnectionLostRef.current = true;
      }
      console.error("[MONITORING] heartbeat failed", err);
      console.log("[Monitoring] heartbeat failed");
      setError(err.message || "monitoring heartbeat failed");
    } finally {
      tickInFlightRef.current = false;
    }
  }, [applySnapshot, refreshMonitoringState]);

  const startSession = useCallback(
    async (faceConfidence, intentId) => {
      if (!user || !deviceId || !sessionId) {
        throw new Error("Monitoring requires a valid authenticated session.");
      }

      const sessionKey = `${user.userId}:${deviceId}:${sessionId}`;
      if (monitoringSessionId && lastStartedSessionKeyRef.current === sessionKey) {
        return snapshot;
      }

      monitoringGenerationRef.current += 1;
      pendingFailuresRef.current = 0;
      consecutiveHeartbeatFailuresRef.current = 0;
      setConnectionState("connected");
      // Fresh monitoring lifecycle starting -> give the (re)opening camera
      // stream / face-api models a grace window before a not-yet-ready
      // camera counts as a failed identity check (see CAMERA_WARMUP_GRACE_MS).
      cameraGraceDeadlineRef.current = Date.now() + CAMERA_WARMUP_GRACE_MS;

      console.log("[MONITORING] auth ready", { userId: user.userId, deviceId, sessionId });
      console.log("[MONITORING] face verified", { confidence: faceConfidence });
      console.log("[MONITORING] starting monitoring...", { deviceId, sessionId, faceConfidence, intentId });

      try {
        const sessionRefreshResult = await refreshSession(sessionId, deviceId, 60);
        console.log("[MONITORING] session ready", sessionRefreshResult);
        if (sessionRefreshResult?.revoked) {
          // Defense in depth only — the backend refresh endpoint no
          // longer returns a revoked session as success at all (see
          // fix pass section A), so this branch should be
          // unreachable in practice. Kept so a future backend
          // regression fails safe here too, rather than silently
          // starting monitoring on a revoked session.
          setReauthRequired(true);
          throw new Error("Monitoring start is blocked by existing ownership/session authorization.");
        }
        setReauthRequired(false);
        setDeviceRevoked(false);

        if (monitoringStartInFlightRef.current) {
          return snapshot;
        }
        monitoringStartInFlightRef.current = true;

        console.log("[MONITORING] sending start request", {
          userId: user.userId,
          deviceId,
          sessionId,
          faceConfidence,
          intentId,
        });

        // The very first snapshot is seeded from the face verification
        // that just happened at login (payload requires a confidence –
        // this endpoint only STARTS watching, it doesn't re-verify).
        // Every subsequent tick re-verifies for real via the camera
        // loop below.
        const result = await apiStartMonitoring(deviceId, sessionId, faceConfidence, intentId);
        console.log("[MONITORING] start response", result);
        console.log("[Monitoring] started");
        applySnapshot(result);
        setMonitoringSessionId(result.monitoring_session_id);
        sessionStorage.setItem("ibqc_monitoring_session_id", result.monitoring_session_id);
        lastStartedSessionKeyRef.current = sessionKey;
        console.log("[MONITORING] monitoring session", result.monitoring_session_id);
        // Fix pass (continuous-monitoring-lifecycle, Part 4/29): don't
        // make CurrentDeviceCard/CookieSessionIntegrityCard wait for
        // their own next independent poll tick to learn the current
        // device/session state — pull it once, immediately, right as
        // monitoring starts, into the SAME shared context they now
        // read from.
        refreshMonitoringState();
        return result;
      } catch (err) {
        console.error("[MONITORING] start failed", {
          status: err?.status,
          detail: err?.detail,
          userId: user?.userId,
          deviceId,
          sessionId,
          faceConfidence,
          intentId,
        });
        // A 403 from the refresh call above means the session is
        // revoked — normal refresh MUST NOT resurrect it (fix pass
        // section A), so surface this as an explicit REAUTH REQUIRED
        // state instead of a generic failure. Monitoring is
        // deliberately left un-started; only reauthenticate() below
        // is allowed to clear this.
        if (err?.status === 403) {
          setReauthRequired(true);
          setDeviceRevoked(isDeviceRevokedError(err));
          console.log("[Monitoring] reauthentication required", { deviceRevoked: isDeviceRevokedError(err) });
        }
        setError(err?.message || err?.detail || "failed to start monitoring");
        throw err;
      } finally {
        monitoringStartInFlightRef.current = false;
      }
    },
    [applySnapshot, deviceId, monitoringSessionId, sessionId, snapshot, user, refreshMonitoringState]
  );

  const stopSession = useCallback(async () => {
    monitoringGenerationRef.current += 1;
    stopLoop();
    stopStateRefreshLoop();
    console.log("[MONITORING] stopping monitoring", { monitoringSessionId });
    if (monitoringSessionId) {
      try {
        await apiStopMonitoring(monitoringSessionId);
      } catch {
        /* best-effort */
      }
    }
    setMonitoringSessionId(null);
    sessionStorage.removeItem("ibqc_monitoring_session_id");
    snapshotRevisionRef.current = -1;
    snapshotSessionRef.current = null;
    setSnapshot(null);
    setCameraState("idle");
    setDeviceStatus(null);
    setSessionStatus(null);
    setLastRefreshedAt(null);
    lastStartedSessionKeyRef.current = "";
    console.log("[MONITORING] stopped");
    console.log("[Monitoring] stopped");
  }, [monitoringSessionId, stopLoop, stopStateRefreshLoop]);

  const simulateFaceFailure = useCallback((count = 1) => {
    pendingFailuresRef.current += count;
  }, []);

  // Re-establish trust: a live face verification + fresh authorized
  // session in one atomic backend call (bumps `version`, which is
  // exactly what invalidates any stale cryptographic session bound
  // to the old one), then starts a brand-new monitoring session in
  // place of the revoked one. This is the ONLY path in the app that
  // can restore a revoked session — see authorization/sessions.py's
  // `reauthorize` and the dedicated `/reauthenticate` endpoint.
  const reauthenticate = useCallback(
    async (descriptor, faceConfidence = null, reauthRequestId = null) => {
      monitoringGenerationRef.current += 1;
      // A brand-new monitoring session is about to start below — the
      // hidden <Webcam> element unmounts/remounts and face-api's models
      // may need to reload. Give that a grace window (see
      // CAMERA_WARMUP_GRACE_MS) so initialization latency right after
      // being restored is never itself misread as a failed identity
      // check and escalated straight back into REAUTH_REQUIRED/REVOKED.
      cameraGraceDeadlineRef.current = Date.now() + CAMERA_WARMUP_GRACE_MS;
      let session;
      try {
        session = await reauthenticateSession(
          sessionId,
          deviceId,
          descriptor,
          60,
          reauthRequestId
        );
      } catch (err) {
        // Surface the device-revoked case distinctly so the caller
        // (MonitoringBadge) can switch to "request admin approval"
        // instead of just showing a generic reauth error and inviting
        // another doomed retry of the same face check.
        if (err?.status === 403) setDeviceRevoked(isDeviceRevokedError(err));
        throw err;
      }
      console.log("[Monitoring] reauthentication successful", {
        sessionId: session.session_id,
        revoked: session.revoked,
        version: session.version,
      });
      if (session.revoked) {
        throw new Error("Reauthentication returned an invalid session; monitoring remains blocked.");
      }
      pendingFailuresRef.current = 0;
      consecutiveHeartbeatFailuresRef.current = 0;
      wasConnectionLostRef.current = false;
      setConnectionState("connected");
      // Keep the UI blocked until the NEW backend monitoring state is
      // fetched and confirmed below.
      setDeviceRevoked(false);
      // Tear down the old monitoring loop/state before creating the
      // replacement session. Otherwise a heartbeat from the revoked
      // session can race the fresh session and put the UI straight back
      // into REVOKED/REAUTH_REQUIRED.
      stopLoop();
      stopStateRefreshLoop();
      // Do not manually clear tickInFlightRef here: an old async tick may
      // still be finishing. Generation guards invalidate its response;
      // allowing the in-flight flag to clear naturally prevents overlap
      // with the new session's camera verification.
      monitoringStartInFlightRef.current = false;
      lastStartedSessionKeyRef.current = "";
      snapshotRevisionRef.current = -1;
      snapshotSessionRef.current = null;
      setSnapshot(null);
      setMonitoringSessionId(null);
      setCameraState("idle");
      setDeviceStatus(null);
      setSessionStatus(null);
      setLastRefreshedAt(null);
      // The face verification above already ran server-side as part
      // of `reauthenticateSession`. Use the REAL confidence returned by
      // the live FaceAuthPanel when available; the monitoring heartbeat
      // immediately follows and independently re-checks the camera.
      const seedConfidence = Number.isFinite(Number(faceConfidence))
        ? Number(faceConfidence)
        : 1.0;
      const result = await apiStartMonitoring(deviceId, sessionId, seedConfidence);
      console.log("[Monitoring] new session activated", { monitoringSessionId: result.monitoring_session_id });
      applySnapshot(result);
      setMonitoringSessionId(result.monitoring_session_id);
      sessionStorage.setItem("ibqc_monitoring_session_id", result.monitoring_session_id);
      // Mark this authorization session as already started so a remount
      // or bootstrap cannot create a duplicate monitoring session during
      // the same successful recovery cycle.
      lastStartedSessionKeyRef.current = `${user.userId}:${deviceId}:${sessionId}`;
      // Fix pass (continuous-monitoring-lifecycle, Part 16/17/19):
      // this is the critical fix for the reported bug — do NOT leave
      // CurrentDeviceCard/CookieSessionIntegrityCard showing the OLD
      // revoked session's state until their own independent poll
      // timer happens to fire. Force an immediate authoritative
      // refresh of device/session/monitoring state right now, in the
      // same tick reauthentication completes. `session` above already
      // reflects revoked:false, but device status and any other
      // context these cards show may also have changed.
      await refreshMonitoringState(result.monitoring_session_id);
      const refreshedSession = await getSessionStatus(sessionId);
      const refreshedDevice = await getDeviceStatus(deviceId);
      const refreshedMonitoring = await getMonitoringStatus(result.monitoring_session_id);
      if (
        refreshedSession?.revoked ||
        refreshedDevice?.revoked ||
        refreshedMonitoring?.status === "revoked" ||
        refreshedMonitoring?.current_authorization_state !== "valid"
      ) {
        setReauthRequired(true);
        throw new Error("Reauthentication completed, but the authoritative security state is still blocked.");
      }
      setSessionStatus(refreshedSession);
      setDeviceStatus(refreshedDevice);
      applySnapshot(refreshedMonitoring);
      setReauthRequired(false);
      return { session, monitoring: refreshedMonitoring };
    },
    [deviceId, sessionId, user, refreshMonitoringState, stopLoop, stopStateRefreshLoop]
  );

  // ------------------------------------------------------------------
  // Camera lifecycle: request/open the stream only while a monitoring
  // session is actually running, and preload the face-api models so
  // the first real tick isn't stalled behind a model download.
  // ------------------------------------------------------------------
  useEffect(() => {
    if (!monitoringSessionId && !returningUserVerification) {
      setCameraState("idle");
      return;
    }
    setCameraState((prev) => (prev === "ready" ? prev : "requesting"));
    loadModels().catch(() => {
      /* face-api models failed to load -> ticks will still run with
         cameraAvailable=false until the stream/model recovers */
    });
  }, [monitoringSessionId, returningUserVerification]);

  // Heartbeat loop — runs at the configured interval, independent of
  // whether the camera has finished opening yet (an unopened/denied
  // camera still produces a valid tick: cameraAvailable=false).
  useEffect(() => {
    stopLoop();
    if (!monitoringSessionId) return undefined;
    console.log("[MONITORING] heartbeat started", { monitoringSessionId, intervalMs: MONITORING_INTERVAL_MS });
    intervalRef.current = setInterval(() => tick(monitoringSessionId), MONITORING_INTERVAL_MS);
    return stopLoop;
  }, [monitoringSessionId, tick, stopLoop]);

  // PART 22/23 — the separate, slower "what is my CURRENT
  // authoritative state" refresh loop, distinct from the heartbeat
  // above. Exactly ONE interval, cleared/recreated the same way the
  // heartbeat loop is, keyed only to monitoringSessionId so it can
  // never accumulate duplicates across remounts/re-renders.
  useEffect(() => {
    stopStateRefreshLoop();
    if (!monitoringSessionId) return undefined;
    console.log("[Monitoring] state refresh loop started", { intervalMs: STATE_REFRESH_INTERVAL_MS });
    stateRefreshIntervalRef.current = setInterval(refreshMonitoringState, STATE_REFRESH_INTERVAL_MS);
    return stopStateRefreshLoop;
  }, [monitoringSessionId, refreshMonitoringState, stopStateRefreshLoop]);

  // LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED. Runs once
  // per mount (i.e. once per navigation into the authenticated shell)
  // when there's a pending confidence value from a just-completed
  // face verification/enrollment and no session running yet.
  useEffect(() => {
    let cancelled = false;

    async function bootstrapMonitoring() {
      if (!user || !deviceId || !sessionId || monitoringSessionId || monitoringStartInFlightRef.current) return;

      // First recover an already-running monitoring session after a page
      // refresh/navigation. This is read-only and never uses cached face
      // confidence as proof.
      try {
        const existing = await getMonitoringForSession(sessionId);
        if (!cancelled && existing?.monitoring_session_id) {
          monitoringGenerationRef.current += 1;
          applySnapshot(existing);
          setMonitoringSessionId(existing.monitoring_session_id);
          sessionStorage.setItem("ibqc_monitoring_session_id", existing.monitoring_session_id);
          setReauthRequired(existing.status === "revoked");
          setDeviceRevoked(false);
          lastStartedSessionKeyRef.current = `${user.userId}:${deviceId}:${sessionId}`;
          await refreshMonitoringState(existing.monitoring_session_id);
          return;
        }
      } catch (err) {
        // 404 means there is no active monitoring session to recover.
        // Other failures are logged, then the normal post-login bootstrap
        // below gets a chance to establish monitoring.
        if (err?.status !== 404) console.warn("[Monitoring] existing-session recovery failed", err?.message);
      }

      const pending = sessionStorage.getItem(PENDING_CONFIDENCE_KEY);
      const canStart = Boolean(pending && !cancelled && !monitoringSessionId && !monitoringStartInFlightRef.current);
      if (canStart) {
        console.log("[MONITORING] bootstrap trigger", { userId: user.userId, deviceId, sessionId, pending });
        sessionStorage.removeItem(PENDING_CONFIDENCE_KEY);
        try {
          await startSession(parseFloat(pending));
        } catch (err) {
          if (!cancelled) setError(err.message || "failed to start monitoring");
        }
      } else if (!cancelled) {
        // Returning authenticated user: the persisted application session
        // is not sufficient to silently trust an old face result. Start a
        // fresh camera verification and, once verified, establish a new
        // live monitoring session automatically.
        await refreshMonitoringState();
        if (!pending && !monitoringSessionId) {
          returningVerificationInFlightRef.current = false;
          setReturningUserVerification(true);
        }
      }
    }

    bootstrapMonitoring();
    return () => { cancelled = true; };
    // monitoringSessionId is intentionally part of the guard; the effect
    // runs again only when the provider transitions between session states.
  }, [user, deviceId, sessionId, monitoringSessionId, startSession, refreshMonitoringState]);

  // Returning-session bootstrap: use the hidden camera surface to obtain
  // a FRESH face descriptor. This is intentionally separate from the
  // normal heartbeat loop so cached login confidence is never reused.
  useEffect(() => {
    if (!returningUserVerification || monitoringSessionId || !user || !deviceId || !sessionId) {
      return undefined;
    }

    if (cameraState !== "ready" || returningVerificationInFlightRef.current) {
      return undefined;
    }

    let cancelled = false;
    returningVerificationInFlightRef.current = true;

    async function verifyAndStart() {
      try {
        await loadModels();
        const video = webcamRef.current?.video;
        if (!video || video.readyState !== 4) throw new Error("Camera is not ready yet.");

        const detection = await detectFaceLite(video);
        const quality = assessQuality(detection, video);
        if (!detection || !quality.ok) throw new Error("Face not ready for verification.");

        const descriptor = await extractDescriptor(video);
        if (!descriptor) throw new Error("Unable to capture a usable face descriptor.");

        const result = await verifyFace(descriptor);
        const confidence = Number(result?.confidence);
        if (!Number.isFinite(confidence)) throw new Error("Face verification did not return a valid confidence.");

        if (!cancelled) {
          setReturningUserVerification(false);
          await startSession(confidence);
        }
      } catch (err) {
        if (!cancelled) {
          // Keep the camera open and retry on the next interval. No stale
          // confidence is cached or promoted to authorization.
          console.log("[MONITORING] returning-user face verification retry", err?.message);
        }
      } finally {
        returningVerificationInFlightRef.current = false;
      }
    }

    verifyAndStart();
    const retryInterval = setInterval(verifyAndStart, MONITORING_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(retryInterval);
    };
  }, [returningUserVerification, monitoringSessionId, user, deviceId, sessionId, cameraState, startSession]);

  // Session ends (logout) -> stop monitoring entirely, including the
  // camera.
  useEffect(() => {
    if (!user) {
      monitoringGenerationRef.current += 1;
      console.log("[MONITORING] logout detected; stopping monitoring");
      stopLoop();
      stopStateRefreshLoop();
      setMonitoringSessionId(null);
      setReturningUserVerification(false);
      returningVerificationInFlightRef.current = false;
      snapshotRevisionRef.current = -1;
      snapshotSessionRef.current = null;
      setSnapshot(null);
      setCameraState("idle");
      setReauthRequired(false);
      setDeviceRevoked(false);
      setDeviceStatus(null);
      setSessionStatus(null);
      setLastRefreshedAt(null);
      lastStartedSessionKeyRef.current = "";
      console.log("[Monitoring] stopped");
    }
  }, [user, stopLoop, stopStateRefreshLoop]);

  // Browser tab hidden -> the camera loop is still technically
  // running, but a hidden tab can't meaningfully assert "the enrolled
  // user is present" — surface it as a warning-worthy fact via a
  // forced failed tick rather than silently continuing to report
  // ACTIVE off a frame nobody can see change. Monitoring itself is
  // NOT stopped while hidden (PART 12) — it continues logically at
  // the backend/session level; becoming visible again re-pulls the
  // authoritative state rather than assuming nothing changed while
  // backgrounded.
  useEffect(() => {
    function onVisibility() {
      if (!monitoringSessionId) return;
      if (document.hidden) {
        pendingFailuresRef.current = Math.max(pendingFailuresRef.current, 1);
      } else {
        console.log("[Monitoring] tab visible again — refreshing state");
        refreshMonitoringState();
      }
    }
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [monitoringSessionId, refreshMonitoringState]);

  return (
    <MonitoringContext.Provider
      value={{
        monitoringSessionId,
        snapshot,
        error,
        // Exposed so consumers (AccessRequestPanel, MonitoringBadge)
        // can tell an ADMIN's OWN revoked device apart from anyone
        // else's: an admin has no higher authority to file an
        // approval request with, so the backend now self-restores
        // their own device on a successful reauthenticate() face
        // check (see api/routers/authorization.py's
        // admin_self_service_restore) instead of 403ing forever.
        isAdmin: user?.role === "ADMIN",
        cameraState,
        connectionState,
        reauthRequired,
        deviceRevoked,
        isMonitoring: !!monitoringSessionId,
        startSession,
        stopSession,
        simulateFaceFailure,
        reauthenticate,
        // Part 1/10 (foundation-security fix pass): exposed so
        // MonitoringBadge (and any other consumer) can show the
        // REAL device-trust state instead of a hardcoded label.
        // Also exposed to dashboard widgets (current device, live
        // location, cookie/session integrity) so they can reuse the
        // SAME device/session identifiers monitoring itself uses,
        // without prop-drilling them through every page — this is
        // not new state, just the props this provider already
        // received.
        deviceId,
        sessionId,
        // Fix pass (continuous-monitoring-lifecycle): the ONE
        // authoritative device/session state, replacing what used to
        // be two separate, independently-polling copies inside
        // CurrentDeviceCard and CookieSessionIntegrityCard (see
        // refreshMonitoringState above for why that was the root
        // cause of the reported desync). `null` means "not fetched
        // yet", not "revoked" — consumers should render a loading/
        // unknown state for null, never assume revoked.
        deviceStatus,
        sessionStatus,
        lastRefreshedAt,
        refreshMonitoringState,
        // Exposed so a user-visible Live Monitoring panel (see
        // LiveMonitoringPanel.jsx) can attach the SAME already-open
        // camera stream to a <video> element, instead of mounting a
        // second <Webcam> and requesting camera permission twice
        // (spec section 19).
        webcamRef,
      }}
    >
      {children}
      {/* Hidden capture surface for the continuous-monitoring loop.
          Rendered off-screen (never display:none, which some browsers
          use to pause decoding) whenever a monitoring session is
          active, and unmounted — which releases the camera device —
          the instant it isn't. No frame from this element is ever
          uploaded; only derived booleans/confidence leave the
          browser. */}
      {(monitoringSessionId || returningUserVerification) && (
        <div
          aria-hidden="true"
          style={{ position: "fixed", top: 0, left: 0, width: 1, height: 1, overflow: "hidden", opacity: 0, pointerEvents: "none" }}
        >
          <Webcam
            ref={webcamRef}
            audio={false}
            videoConstraints={CAMERA_CONSTRAINTS}
            onUserMedia={() => setCameraState("ready")}
            onUserMediaError={() => setCameraState("unavailable")}
          />
        </div>
      )}
    </MonitoringContext.Provider>
  );
}

export function useMonitoringContext() {
  const ctx = useContext(MonitoringContext);
  if (!ctx) {
    throw new Error("useMonitoringContext must be used within a MonitoringProvider");
  }
  return ctx;
}
