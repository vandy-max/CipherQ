import { useEffect, useMemo, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Gauge,
  Fingerprint,
  Laptop2,
  KeySquare,
  Eye,
  RefreshCw,
  Loader2,
  Radio,
  DatabaseZap,
  Activity,
  Info,
} from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import CipherQMascot from "../components/mascot/CipherQMascot";
import QiraAvatar from "../components/qira/QiraAvatar";
import RiskCore from "../components/quantum/RiskCore";
import QuantumField from "../components/quantum/QuantumField";
import { useMonitoringContext } from "../context/MonitoringContext";
import { useQiraContext } from "../context/QiraContext";
import { formatTimestamp } from "../utils/formatTimestamp";
import { verifyAuditChain } from "../services/api";

/*
 * QIRA DISPLAY CONTRACT
 * ---------------------
 * The backend QiraDecision is authoritative. This page NEVER invents a
 * security verdict from the visual monitoring fields. Monitoring and
 * system/audit integrity are displayed separately so a state such as:
 *
 *   Monitoring = SECURE
 *   Audit integrity = FAILED
 *   Qira = SECURE
 *
 * is shown deliberately: audit integrity remains a separate system-level
 * control and does not poison the current session's risk verdict.
 */
const STATE_META = {
  SECURE: {
    label: "SECURE",
    description: "All authoritative security checks are within acceptable limits.",
    tone: "text-cq-secondary",
    dot: "bg-cq-secondary",
    border: "border-cq-secondary/30",
    surface: "bg-cq-secondary/10",
    Icon: ShieldCheck,
  },
  SECURITY_WARNING: {
    label: "SECURITY WARNING",
    description: "A security anomaly requires attention, but access has not been classified as compromised.",
    tone: "text-amber-400",
    dot: "bg-amber-400",
    border: "border-amber-400/30",
    surface: "bg-amber-400/10",
    Icon: ShieldAlert,
  },
  COMPROMISED: {
    label: "COMPROMISED",
    description: "An authoritative security control has failed or access has been compromised.",
    tone: "text-cq-error",
    dot: "bg-cq-error",
    border: "border-cq-error/30",
    surface: "bg-cq-error/10",
    Icon: ShieldX,
  },
};

const IDENTITY_LABELS = {
  IDENTITY_CONFIRMED: "Identity Confirmed",
  IDENTITY_MISMATCH: "Identity Mismatch",
  NO_FACE: "No Face Detected",
  CAMERA_UNAVAILABLE: "Camera Unavailable",
  LIVENESS_UNCERTAIN: "Liveness Uncertain",
};

const SIGNAL_META = {
  audit_chain_tampered: { label: "Audit chain integrity failed", tone: "text-cq-error", icon: ShieldX },
  monitoring_revoked: { label: "Continuous monitoring revoked access", tone: "text-cq-error", icon: ShieldX },
  session_revoked: { label: "Authorization session revoked", tone: "text-cq-error", icon: ShieldX },
  device_revoked: { label: "Trusted device revoked", tone: "text-cq-error", icon: ShieldX },
  face_mismatch: { label: "Face identity mismatch", tone: "text-cq-error", icon: Fingerprint },
  repeated_monitoring_anomalies: { label: "Repeated monitoring anomalies", tone: "text-amber-400", icon: Activity },
  repeated_face_failures: { label: "Repeated face/liveness failures", tone: "text-amber-400", icon: Fingerprint },
  monitoring_warning: { label: "Monitoring warning", tone: "text-amber-400", icon: Activity },
  risk_engine_critical: { label: "Deterministic risk engine: critical", tone: "text-cq-error", icon: Gauge },
  risk_engine_high: { label: "Deterministic risk engine: high", tone: "text-amber-400", icon: Gauge },
};

function humanize(value) {
  if (!value) return "—";
  return String(value)
    .toLowerCase()
    .replaceAll("_", " ")
    .replace(/^\w/, (c) => c.toUpperCase());
}

function StatusRow({ icon: Icon, label, value, tone = "text-cq-on-surface" }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2.5 border-b border-white/[0.06] last:border-b-0">
      <div className="flex items-center gap-2.5 text-[13px] text-cq-on-surface-variant min-w-0">
        <Icon size={15} className="text-cq-outline shrink-0" />
        <span>{label}</span>
      </div>
      <div className={`text-[13px] font-semibold text-right ${tone}`}>{value}</div>
    </div>
  );
}

function SignalChip({ signal }) {
  const meta = SIGNAL_META[signal] || { label: humanize(signal), tone: "text-cq-on-surface-variant", icon: Info };
  const Icon = meta.icon;
  return (
    <li className="flex items-center gap-2 rounded-cq-md bg-cq-surface-container-high px-3 py-2 border border-white/[0.05]">
      <Icon size={13} className={meta.tone} />
      <span className={`text-[12px] font-medium ${meta.tone}`}>{meta.label}</span>
    </li>
  );
}

export default function VisualizationPage() {
  const { monitoringSessionId, snapshot, isMonitoring, deviceStatus, sessionStatus } = useMonitoringContext();
  const { decision, assessing, error, refresh } = useQiraContext();
  const [auditVerification, setAuditVerification] = useState(null);

  useEffect(() => {
    let cancelled = false;
    verifyAuditChain().then((result) => {
      if (!cancelled) setAuditVerification(result);
    }).catch(() => {
      if (!cancelled) setAuditVerification(null);
    });
    const id = window.setInterval(() => {
      verifyAuditChain().then((result) => {
        if (!cancelled) setAuditVerification(result);
      }).catch(() => {});
    }, 5000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  // IMPORTANT: only the backend QiraDecision determines the Qira verdict.
  // snapshot.security_state is the monitoring posture and is intentionally
  // not used as a substitute for the Qira decision.
  // While Qira is assessing, the latest monitoring snapshot is the
  // authoritative live security state. Showing that state immediately
  // prevents the risk-analysis card from visually lagging behind a
  // recovered WARNING -> SECURE (or any other) monitoring transition.
  // Once the assessment completes, the backend Qira decision becomes the
  // displayed verdict again. No frontend state is invented here.
  const stateKey = assessing
    ? snapshot?.security_state || decision?.security_state
    : decision?.security_state || snapshot?.security_state;
  const meta = STATE_META[stateKey] || null;
  // Mascot status vocabulary mirrors monitoringState.js's four states;
  // translate the Qira-specific SECURE/SECURITY_WARNING/COMPROMISED
  // labels onto it. Purely cosmetic — the backend decision above
  // remains the sole source of truth for the page itself.
  const mascotStatus =
    stateKey === "SECURE" ? "active" : stateKey === "SECURITY_WARNING" ? "warning" : stateKey === "COMPROMISED" ? "revoked" : undefined;

  const identityKey = snapshot?.identity_state;
  const identityLabel = IDENTITY_LABELS[identityKey] || humanize(identityKey);
  const identityTone =
    identityKey === "IDENTITY_CONFIRMED"
      ? "text-cq-secondary"
      : identityKey === "IDENTITY_MISMATCH"
      ? "text-cq-error"
      : "text-cq-on-surface-variant";

  const sessionLabel = sessionStatus == null ? "—" : sessionStatus.revoked ? "Revoked" : "Active";
  const sessionTone = sessionStatus == null ? "text-cq-on-surface-variant" : sessionStatus.revoked ? "text-cq-error" : "text-cq-secondary";

  const deviceLabel = deviceStatus == null ? "—" : deviceStatus.revoked ? "Revoked" : "Trusted";
  const deviceTone = deviceStatus == null ? "text-cq-on-surface-variant" : deviceStatus.revoked ? "text-cq-error" : "text-cq-secondary";

  const livenessLabel = snapshot ? (snapshot.liveness ? "Live" : "Not Detected") : "—";
  const livenessTone = snapshot == null ? "text-cq-on-surface-variant" : snapshot.liveness ? "text-cq-secondary" : "text-cq-on-surface-variant";

  const monitoringLabel = !snapshot ? "—" : humanize(snapshot.status);
  const monitoringTone =
    snapshot?.status === "active"
      ? "text-cq-secondary"
      : snapshot?.status === "revoked"
      ? "text-cq-error"
      : snapshot?.status
      ? "text-amber-400"
      : "text-cq-on-surface-variant";

  const auditTampered = auditVerification ? !auditVerification.valid : decision?.audit_chain_intact === false;
  const signals = decision?.signals || [];
  const riskLevel = decision?.risk_level || snapshot?.current_risk;
  const riskScore = decision?.risk_score ?? snapshot?.risk_score;
  const recommendation = decision?.enforced_action || decision?.recommended_action;
  const reason = decision?.reason || decision?.ai_explanation;

  const assessmentTime = useMemo(
    () => (decision?.timestamp ? formatTimestamp(decision.timestamp) : null),
    [decision?.timestamp]
  );

  const telemetry = [
    ["Monitoring session", monitoringSessionId || "—"],
    ["Monitoring state", monitoringLabel],
    ["Face confidence", snapshot?.face_match_confidence != null ? `${(Number(snapshot.face_match_confidence) * 100).toFixed(1)}%` : "—"],
    ["Risk level", riskLevel ? humanize(riskLevel) : "—"],
    ["Risk score", riskScore != null ? Math.round(Number(riskScore)) : "—"],
    ["Last update", snapshot?.timestamp ? formatTimestamp(snapshot.timestamp) : "—"],
  ];

  return (
    <div>
      <PageHeader
        icon="radar"
        eyebrow="Qira Risk Analysis"
        title="Qira Risk Analysis"
        description="Qira automatically analyzes authoritative security telemetry — no manual risk input required."
      />

      <div className="flex items-center justify-between gap-4 mb-5">
        <div className="text-[11px] text-cq-outline flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-cq-secondary" />
          Backend-authoritative assessment
          {assessmentTime ? ` · assessed ${assessmentTime}` : ""}
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={refresh}
          loading={assessing}
          icon={RefreshCw}
          disabled={!monitoringSessionId}
        >
          Refresh Analysis
        </Button>
      </div>

      {!isMonitoring ? (
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg flex flex-col items-center text-center gap-4 py-12">
          <QiraAvatar state="off" size={96} trackCursor={false} />
          <div>
            <div className="text-[15px] font-bold text-cq-on-surface">QIRA — AI Security Guardian</div>
            <p className="mt-1.5 text-[13px] text-cq-on-surface-variant max-w-lg">
              Qira is waiting for an active continuous monitoring session. No security verdict is invented while authoritative telemetry is unavailable.
            </p>
          </div>
        </div>
      ) : (
        <div className="relative grid grid-cols-1 xl:grid-cols-[minmax(0,340px)_1fr] gap-5 items-start">
          <QuantumField density="low" tone="mixed" className="opacity-25 -z-10" />
          {/* QIRA summary */}
          <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg flex flex-col items-center text-center sticky top-4">
            <QiraAvatar
              state={assessing ? "scanning" : stateKey}
              size={96}
              trackCursor={false}
            />
            <div className="mt-3 text-[15px] font-bold text-cq-on-surface tracking-tight">QIRA</div>
            <div className="text-[11px] font-semibold text-cq-outline uppercase tracking-[0.2em]">AI Security Guardian</div>

            <div className={`mt-5 w-full rounded-cq-lg border px-5 py-4 ${meta ? `${meta.surface} ${meta.border}` : "bg-cq-surface-container-high border-white/10"}`}>
              {meta ? (
                <>
                  <div className="flex items-center justify-center gap-2 mb-1">
                    <span className={`w-2 h-2 rounded-full ${meta.dot} ${assessing ? "animate-pulse" : ""}`} />
                    <meta.Icon size={17} className={meta.tone} />
                    <span className={`text-[14px] font-bold ${meta.tone}`}>{meta.label}</span>
                  </div>
                  <div className="text-[11px] text-cq-on-surface-variant leading-relaxed">{meta.description}</div>
                </>
              ) : (
                <div className="text-[13px] text-cq-on-surface-variant">
                  {assessing ? "Analyzing authoritative telemetry…" : "Awaiting assessment"}
                </div>
              )}
              {decision?.severity && (
                <div className="text-[11.5px] text-cq-on-surface-variant mt-2">Qira severity: {humanize(decision.severity)}</div>
              )}
            </div>

            <div className="mt-5 flex justify-center">
              <RiskCore
                score={riskScore != null ? Number(riskScore) : undefined}
                level={riskLevel ? riskLevel.toUpperCase() : undefined}
                state={stateKey === "SECURE" ? "active" : stateKey === "SECURITY_WARNING" ? "warning" : stateKey === "COMPROMISED" ? "revoked" : "off"}
                loading={assessing && riskScore == null}
                size={168}
              />
            </div>

            <div className="mt-4 w-full grid grid-cols-1 gap-3">
              <div className="rounded-cq-md bg-cq-surface-container-high px-3 py-3">
                <div className="text-[10.5px] uppercase tracking-wide text-cq-outline mb-1">Recommended Action</div>
                <div className={`text-[12.5px] font-semibold ${recommendation === "REVOKE" ? "text-cq-error" : recommendation === "REAUTHENTICATE" ? "text-amber-400" : "text-cq-on-surface"}`}>
                  {humanize(recommendation) || "—"}
                </div>
              </div>
            </div>

            {auditTampered && (
              <div className="mt-3 w-full rounded-cq-md border border-cq-error/25 bg-cq-error/10 px-3 py-2.5 text-left">
                <div className="flex items-center gap-2 text-[12px] font-bold text-cq-error">
                  <DatabaseZap size={14} /> System integrity alert
                </div>
                <div className="mt-1 text-[10.5px] leading-relaxed text-cq-on-surface-variant">
                  The audit chain is reported as tampered by the backend. This is a separate system-integrity alert; the current Qira session verdict is still based on live monitoring, authorization, identity, and risk telemetry.
                </div>
              </div>
            )}

            {assessmentTime && <div className="mt-3 text-[10.5px] text-cq-outline">Assessment timestamp: {assessmentTime}</div>}
          </div>

          {/* Detailed authoritative analysis */}
          <div className="flex flex-col gap-5">
            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <div className="flex items-center justify-between gap-4 mb-2">
                <div className="flex items-center gap-2">
                  <Gauge size={17} className="text-cq-primary" />
                  <h2 className="text-[16px] font-bold text-cq-on-surface">Current Security State</h2>
                </div>
                {meta && <span className={`text-[11px] font-bold uppercase tracking-wide ${meta.tone}`}>Qira: {meta.label}</span>}
              </div>

              <Alert type="error">{error}</Alert>

              <div className="mt-2">
                <StatusRow icon={Fingerprint} label="Identity Status" value={identityLabel} tone={identityTone} />
                <StatusRow icon={KeySquare} label="Session Status" value={sessionLabel} tone={sessionTone} />
                <StatusRow icon={Laptop2} label="Device Status" value={deviceLabel} tone={deviceTone} />
                <StatusRow icon={Eye} label="Liveness Status" value={livenessLabel} tone={livenessTone} />
                <StatusRow icon={Activity} label="Monitoring Status" value={monitoringLabel} tone={monitoringTone} />
                <StatusRow icon={DatabaseZap} label="Audit Integrity" value={auditVerification ? (auditVerification.valid ? "VERIFIED" : "FAILED — REVIEW REQUIRED") : "—"} tone={auditVerification ? (auditVerification.valid ? "text-cq-secondary" : "text-cq-error") : "text-cq-on-surface-variant"} />
              </div>

              {auditVerification && (
                <div className={`mt-4 rounded-cq-md border px-3 py-3 ${auditVerification.valid ? "border-cq-secondary/20 bg-cq-secondary/5" : "border-cq-error/20 bg-cq-error/10"}`}>
                  <div className={`text-[11.5px] font-bold ${auditVerification.valid ? "text-cq-secondary" : "text-cq-error"}`}>
                    {auditVerification.valid ? "Audit integrity verified" : "Audit integrity failed — review required"}
                  </div>
                  <div className="mt-2 grid grid-cols-2 md:grid-cols-5 gap-2">
                    {[
                      ["Genesis", auditVerification.checks?.genesis],
                      ["Continuity", auditVerification.checks?.chain_continuity],
                      ["Hash", auditVerification.checks?.hash_verification],
                      ["Fields", auditVerification.checks?.required_fields],
                      ["Order", auditVerification.checks?.chronological_order],
                    ].map(([label, ok]) => (
                      <div key={label} className="rounded-cq-sm bg-black/10 px-2 py-1.5">
                        <div className="text-[9px] text-cq-outline">{label}</div>
                        <div className={`text-[10.5px] font-bold ${ok ? "text-cq-secondary" : "text-cq-error"}`}>{ok ? "PASS" : "FAIL"}</div>
                      </div>
                    ))}
                  </div>
                  {!auditVerification.valid && (
                    <div className="mt-2 text-[10.5px] text-cq-on-surface-variant">
                      {auditVerification.reason} · First invalid entry: {auditVerification.first_invalid_index ?? "—"}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <div className="flex items-center justify-between gap-4 mb-4">
                <div className="flex items-center gap-2">
                  <Radio size={17} className="text-cq-primary" />
                  <h2 className="text-[16px] font-bold text-cq-on-surface">Detected Security Signals</h2>
                </div>
                <span className={`text-[11px] font-semibold ${signals.length ? (meta?.tone || "text-amber-400") : "text-cq-secondary"}`}>
                  {signals.length ? `${signals.length} detected` : "All Clear"}
                </span>
              </div>

              {signals.length > 0 ? (
                <ul className="flex flex-wrap gap-2">
                  {signals.map((signal, i) => <SignalChip signal={signal} key={`${signal}-${i}`} />)}
                </ul>
              ) : assessing ? (
                <div className="text-[13px] text-cq-on-surface-variant inline-flex items-center gap-1.5">
                  <Loader2 size={13} className="animate-spin" /> Analyzing telemetry…
                </div>
              ) : (
                <div className="rounded-cq-md border border-cq-secondary/15 bg-cq-secondary/5 px-3 py-2.5 text-[12.5px] text-cq-secondary">
                  No security signals were reported by the current backend assessment.
                </div>
              )}
            </div>

            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <div className="flex items-center justify-between gap-4 mb-4">
                <div className="flex items-center gap-2">
                  <Gauge size={17} className="text-cq-primary" />
                  <h2 className="text-[16px] font-bold text-cq-on-surface">Risk Analysis</h2>
                  <CipherQMascot size="xs" status={mascotStatus} tooltip={meta?.label} />
                </div>
                <span className="text-[11px] font-bold uppercase tracking-wide text-cq-on-surface-variant">Backend score</span>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-cq-md bg-cq-surface-container-high px-4 py-3">
                  <div className="text-[10.5px] uppercase tracking-wide text-cq-outline mb-1">Risk Score</div>
                  <div className="text-[28px] font-bold font-display text-cq-on-surface">
                    {riskScore != null ? Math.round(Number(riskScore)) : "—"}
                  </div>
                </div>
                <div className="rounded-cq-md bg-cq-surface-container-high px-4 py-3">
                  <div className="text-[10.5px] uppercase tracking-wide text-cq-outline mb-1">Risk Level</div>
                  <div className={`text-[18px] font-bold ${riskLevel === "low" ? "text-cq-secondary" : riskLevel === "medium" ? "text-amber-400" : "text-cq-error"}`}>
                    {riskLevel ? humanize(riskLevel) : "—"}
                  </div>
                </div>
              </div>
              <div className="mt-3 text-[11.5px] text-cq-on-surface-variant">
                The score is derived from the authoritative monitoring and authorization telemetry for the current session.
              </div>
            </div>

            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck size={17} className={meta?.tone || "text-cq-primary"} />
                <h2 className="text-[16px] font-bold text-cq-on-surface">Qira Explanation</h2>
              </div>
              <p className="text-[13.5px] leading-relaxed text-cq-on-surface-variant">
                {reason || (assessing ? "Qira is reviewing the current telemetry…" : "No explanation available yet.")}
              </p>
              {decision?.ai_available === false && (
                <div className="mt-3 text-[11px] text-cq-outline">
                  Advisory AI model unavailable — this result is the deterministic backend security assessment. It is still authoritative for this page.
                </div>
              )}
            </div>

            <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
              <div className="flex items-center gap-2 mb-4">
                <Radio size={17} className="text-cq-primary" />
                <h2 className="text-[16px] font-bold text-cq-on-surface">Telemetry Snapshot</h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
                {telemetry.map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between gap-4 py-2.5 border-b border-white/[0.06]">
                    <span className="text-[11.5px] text-cq-on-surface-variant">{label}</span>
                    <span className="text-[11.5px] font-semibold text-cq-on-surface text-right break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}