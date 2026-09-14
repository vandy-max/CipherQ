import { useEffect, useState } from "react";
import { RefreshCw, CheckCircle2, XCircle, FlaskConical } from "lucide-react";
import Button from "../components/ui/Button";
import { faceStatus } from "../services/api";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import PageHeader from "../components/ui/PageHeader";

function Pill({ ok, children }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap " +
        (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
      }
    >
      {ok ? <CheckCircle2 size={13} strokeWidth={2.5} /> : <XCircle size={13} strokeWidth={2.5} />}
      {children}
    </span>
  );
}

export default function FaceAuthTestPage() {
  const [status, setStatus] = useState(null); // null loading, else { enrolled }
  const [statusError, setStatusError] = useState("");
  const [mode, setMode] = useState("verify"); // "verify" | "enroll"
  const [panelKey, setPanelKey] = useState(0);
  const [lastResult, setLastResult] = useState(null);

  function loadStatus() {
    setStatus(null);
    setStatusError("");
    faceStatus()
      .then(setStatus)
      .catch((err) => setStatusError(err.detail?.toString?.() || err.message || "Failed to load status"));
  }

  useEffect(loadStatus, []);

  function resetPanel() {
    setLastResult(null);
    setPanelKey((k) => k + 1);
  }

  return (
    <div>
      <PageHeader
        icon="face"
        eyebrow="Development"
        title="Face Authentication"
        description="Debug-only page: check enrollment status, exercise the camera, and run a live verification against your enrolled descriptor. This never touches Encrypt or Decrypt."
      />

      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="text-[16px] font-bold text-cq-on-surface mb-3">Enrollment Status</h2>
          {statusError ? (
            <div className="text-[13px] text-cq-error">{statusError}</div>
          ) : status === null ? (
            <div className="text-[13px] text-cq-on-surface-variant">Checking…</div>
          ) : (
            <Pill ok={status.enrolled}>{status.enrolled ? "Enrolled" : "Not enrolled"}</Pill>
          )}
          <Button variant="ghost" size="sm" icon={RefreshCw} className="mt-4" onClick={loadStatus}>
            Refresh
          </Button>

          <div className="mt-6 pt-5 border-t border-cq-outline-variant/15">
            <h2 className="text-[16px] font-bold text-cq-on-surface mb-3">Test Mode</h2>
            <div className="flex gap-2">
              <Button
                variant={mode === "verify" ? "brand" : "outline"}
                size="sm"
                onClick={() => {
                  setMode("verify");
                  resetPanel();
                }}
              >
                Verify
              </Button>
              <Button
                variant={mode === "enroll" ? "brand" : "outline"}
                size="sm"
                onClick={() => {
                  setMode("enroll");
                  resetPanel();
                }}
              >
                Re-enroll
              </Button>
            </div>
            <p className="mt-3 text-[12px] text-cq-on-surface-variant leading-relaxed">
              Verify checks your live face against the stored descriptor and reports a confidence
              score. Re-enroll overwrites the stored descriptor with a fresh capture.
            </p>
          </div>

          {lastResult && (
            <div className="mt-6 pt-5 border-t border-cq-outline-variant/15">
              <h2 className="text-[16px] font-bold text-cq-on-surface mb-2">Last Result</h2>
              <div className="flex items-center gap-2 mb-2">
                {lastResult.ok ? (
                  <CheckCircle2 size={16} className="text-cq-secondary" />
                ) : (
                  <XCircle size={16} className="text-cq-error" />
                )}
                <span className="text-[13.5px] font-semibold text-cq-on-surface">
                  {lastResult.ok ? "Success" : "Failed"}
                </span>
              </div>
              {lastResult.confidence != null && (
                <div className="text-[12.5px] text-cq-on-surface-variant">
                  Confidence: {(lastResult.confidence * 100).toFixed(1)}%
                </div>
              )}
            </div>
          )}
        </div>

        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-4">
            <FlaskConical size={17} className="text-cq-primary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">
              {mode === "enroll" ? "Test Enrollment" : "Test Verification"}
            </h2>
          </div>
          <FaceAuthPanel
            key={panelKey}
            mode={mode}
            title={mode === "enroll" ? "Re-enroll Face (Test)" : "Verify Face (Test)"}
            subtitle="Runs the same reusable camera pipeline used by Registration, Encrypt, and Decrypt."
            onSuccess={(payload) => {
              setLastResult({ ok: true, confidence: payload.confidence ?? null });
              loadStatus();
            }}
            onCancel={resetPanel}
          />
        </div>
      </div>
    </div>
  );
}
