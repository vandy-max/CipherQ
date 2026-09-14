import { useMemo, useRef, useState } from "react";
import { Mic, Send, ShieldAlert, ShieldCheck, ShieldX, X, Loader2 } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { deriveMonitoringState } from "../monitoring/monitoringState";
import { useQiraContext } from "../../context/QiraContext";
import { formatTimestamp } from "../../utils/formatTimestamp";
import FaceAuthPanel from "../face/FaceAuthPanel";
import QiraAvatar from "./QiraAvatar";

// Qira's living-character state is the SAME vocabulary as
// deriveMonitoringState()'s output, plus "scanning" layered on top
// while an assessment is actively in flight — it is never a separate
// interpretation of security state, only a richer animation for the
// existing one.
function qiraAvatarState(monitoringState, assessing) {
  if (assessing && (monitoringState === "active" || monitoringState === "off")) return "scanning";
  return monitoringState;
}

// UI phase: the floating Qira widget follows the same authoritative live
// monitoring state shown elsewhere. Qira's analysis remains available in
// the widget, but a stale Qira decision must never make healthy monitoring
// look compromised.
const STATE_META = {
  active: { label: "Secure", tone: "text-cq-primary", dot: "bg-cq-secondary", Icon: ShieldCheck },
  warning: { label: "Security Warning", tone: "text-amber-400", dot: "bg-amber-400", Icon: ShieldAlert },
  reauth_required: { label: "Re-authentication Required", tone: "text-amber-400", dot: "bg-amber-400", Icon: ShieldAlert },
  revoked: { label: "Access Revoked", tone: "text-cq-error", dot: "bg-cq-error", Icon: ShieldX },
  off: { label: "Monitoring Off", tone: "text-cq-on-surface-variant", dot: "bg-cq-outline", Icon: ShieldAlert },
};


const QUICK_PROMPTS = [
  { label: "Explain my risk", question: "Explain my current risk score and level." },
  { label: "Check audit integrity", question: "What does the audit integrity status mean?" },
  { label: "Check device trust", question: "Is my device trusted?" },
  { label: "Check monitoring", question: "What is my current monitoring and liveness status?" },
  { label: "What should I do next?", question: "What should I do next?" },
];

export default function QiraWidget({ user }) {
  // PART 5 — an ADMIN is already an authorized security operator, not
  // someone who needs to be told to go find one. Only a non-admin
  // gets pointed at an administrator; an admin sees their own
  // available recovery action instead.
  const isAdmin = user?.role === "ADMIN";

  const { monitoringSessionId, snapshot, isMonitoring, connectionState, reauthRequired, reauthenticate } = useMonitoringContext();
  const { assessing, error: assessError, decision, refresh: runAssessment, ask } = useQiraContext();

  const [open, setOpen] = useState(false);
  const [hover, setHover] = useState(false);
  const [reauthOpen, setReauthOpen] = useState(false);
  const [reauthError, setReauthError] = useState("");

  const [messages, setMessages] = useState([]); // {role:"user"|"qira", text, ts}
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [voiceSupported] = useState(() =>
    Boolean(typeof window !== "undefined" && (window.SpeechRecognition || window.webkitSpeechRecognition))
  );
  const [listening, setListening] = useState(false);
  const [voiceError, setVoiceError] = useState("");

  const recognitionRef = useRef(null);

  const monitoringState = deriveMonitoringState({ isMonitoring, snapshot, connectionState, reauthRequired });
  const meta = STATE_META[monitoringState] || STATE_META.off;

  // Qira is advisory in this UI phase. Live monitoring remains the
  // authoritative source for the visible security status and recovery controls.
  const needsReauth = monitoringState === "reauth_required";
  const revoked = monitoringState === "revoked";

  async function submitQuestion(rawQuestion) {
    const q = rawQuestion.trim();
    if (!q || !monitoringSessionId || asking) return;
    setMessages((m) => [...m, { role: "user", text: q, ts: new Date().toISOString() }]);
    setQuestion("");
    setAsking(true);
    try {
      const res = await ask(q);
      setMessages((m) => [
        ...m,
        { role: "qira", text: res.answer, ts: new Date().toISOString(), aiAvailable: res.ai_available },
      ]);
    } catch (err) {
      setMessages((m) => [
        ...m,
        { role: "qira", text: err.message || "Qira couldn't answer that right now.", ts: new Date().toISOString(), aiAvailable: false },
      ]);
    } finally {
      setAsking(false);
    }
  }

  async function handleQuickPrompt(prompt) {
    await submitQuestion(prompt);
  }

  async function handleAsk(e) {
    e?.preventDefault();
    const q = question.trim();
    if (!q) return;
    await submitQuestion(q);
  }

  // Part 26 — microphone permission is requested ONLY on this explicit
  // click, never implicitly because the widget exists.
  function handleMicClick() {
    setVoiceError("");
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      setVoiceError("Voice input unavailable — text chat remains available.");
      return;
    }
    if (listening) {
      recognitionRef.current?.stop();
      return;
    }
    const recognition = new SpeechRecognition();
    recognition.lang = "en-US";
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;
    recognition.onstart = () => setListening(true);
    recognition.onerror = () => {
      setListening(false);
      setVoiceError("Voice input unavailable — text chat remains available.");
    };
    recognition.onend = () => setListening(false);
    recognition.onresult = (event) => {
      const transcript = event.results?.[0]?.[0]?.transcript;
      if (transcript) setQuestion(transcript);
    };
    recognitionRef.current = recognition;
    try {
      recognition.start();
    } catch {
      setVoiceError("Voice input unavailable — text chat remains available.");
    }
  }

  const disabled = !monitoringSessionId;

  const summary = useMemo(() => `Monitoring: ${meta.label}`, [meta]);
  const avatarState = qiraAvatarState(monitoringState, assessing);

  return (
    <div className="fixed bottom-5 right-5 z-40 flex flex-col items-end gap-3" data-qira-track>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.98 }}
            transition={{ duration: 0.22, ease: "easeOut" }}
            className="w-[368px] max-h-[600px] flex flex-col bg-cq-surface-container border border-white/10 rounded-cq-xl shadow-cq-popover overflow-hidden relative"
          >
          {/* faint quantum seam along the top of the command panel */}
          <div
            className="absolute top-0 left-0 right-0 h-[2px] opacity-70"
            style={{ background: `linear-gradient(90deg, transparent, ${meta.dot === "bg-cq-error" ? "#ffb4ab" : "#63f7ff"}, transparent)` }}
          />
          {/* Header — Qira as a living character, not a static avatar image */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 bg-cq-surface-container-high">
            <div className="flex items-center gap-3">
              <QiraAvatar state={avatarState} size={38} trackCursor={false} />
              <div>
                <div className="text-[13px] font-bold text-cq-on-surface leading-tight">Qira</div>
                <div className="text-[10.5px] text-cq-on-surface-variant leading-tight">CipherQ Security Guardian</div>
              </div>
            </div>
            <button onClick={() => setOpen(false)} className="text-cq-on-surface-variant hover:text-cq-on-surface">
              <X size={16} />
            </button>
          </div>

          {/* Status strip — the SAME three-state value everywhere else
              in the app shows (Part 4/25). */}
          <div className="px-4 py-2.5 border-b border-white/10 flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${meta.dot} ${assessing ? "animate-pulse" : ""}`} />
            <meta.Icon size={13} className={meta.tone} />
            <span className={`text-[12px] font-bold ${meta.tone}`}>{summary}</span>
            {snapshot?.current_risk && (
              <span className="ml-auto text-[10.5px] text-cq-on-surface-variant uppercase tracking-wide">
                Risk: {snapshot.current_risk}
              </span>
            )}
          </div>

          {assessError && (
            <div className="px-4 py-2 text-[11px] text-cq-error bg-cq-error-container/10 border-b border-white/10">
              {assessError}
            </div>
          )}

          {/* Security alert / recovery panel — status comes only from live monitoring. */}
          {(needsReauth || revoked) && (
            <div className="px-4 py-3 border-b border-white/10 bg-cq-error-container/10">
              <div className="text-[12px] font-bold text-cq-error mb-1">
                {revoked ? "🔴 ACCESS REVOKED" : "⚠ RE-AUTHENTICATION REQUIRED"}
              </div>
              <div className="text-[11.5px] text-cq-on-surface-variant mb-2">
                <span className="font-semibold text-cq-on-surface">Reason: </span>
                {snapshot?.warnings?.length ? snapshot.warnings.join(" · ") : "Live monitoring requires a fresh authorization state."}
              </div>
              {revoked ? (
                <div className="text-[11.5px] text-cq-on-surface">
                  {isAdmin ? (
                    <>
                      Protected access has been revoked. As the authenticated administrator, you can
                      restore this device or session from Admin Dashboard → Devices & Sessions.
                    </>
                  ) : (
                    <>
                      Protected access has been revoked. Contact an authorized administrator to restore
                      access, or reauthenticate when the policy permits it.
                    </>
                  )}
                </div>
              ) : reauthOpen ? (
                <>
                  {reauthError && (
                    <div className="mb-2 rounded-cq-sm bg-cq-error-container/15 px-2.5 py-2 text-[11.5px] text-cq-error">
                      {reauthError}
                    </div>
                  )}
                  <FaceAuthPanel
                    mode="verify"
                    title="Reauthenticate"
                    subtitle="A fresh face verification is required to continue."
                    onSuccess={async ({ descriptor }) => {
                      try {
                        await reauthenticate(descriptor);
                        setReauthOpen(false);
                        setReauthError("");
                        await runAssessment();
                      } catch (err) {
                        setReauthError(err.message || "Reauthentication failed");
                      }
                    }}
                    onCancel={() => setReauthOpen(false)}
                  />
                </>
              ) : (
                <button
                  onClick={() => setReauthOpen(true)}
                  className="w-full text-[12px] font-bold px-3 py-2 rounded-cq bg-cq-primary-container text-cq-on-primary-container hover:brightness-110"
                >
                  Reauthenticate
                </button>
              )}
            </div>
          )}

          {/* Reflects the ACTUAL, live Qira decision — including whether it
              was produced by the configured AI provider or (when no
              AI_PROVIDER/AI_API_KEY is configured, or the provider call
              failed) the deterministic backend policy alone. Never a
              hardcoded/static placeholder line. */}
          {!needsReauth && !revoked && (
            <>
              <div className="px-4 py-2.5 border-b border-white/10 text-[11px] text-cq-on-surface-variant">
                {decision
                  ? decision.ai_available
                    ? `Dynamic AI risk analysis is active. Qira: ${decision.reason}`
                    : `Qira is using deterministic security policy (no AI provider configured). ${decision.reason}`
                  : "Qira is aligned with the current live monitoring status."}
              </div>

              {decision && (
                <div className="px-4 py-3 border-b border-white/10">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-bold uppercase tracking-wide text-cq-on-surface">Risk Analysis</span>
                    <span className="text-[10px] text-cq-on-surface-variant">Authoritative backend score</span>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="rounded-cq-md bg-cq-surface-container-high px-2.5 py-2">
                      <div className="text-[9.5px] text-cq-on-surface-variant">Qira State</div>
                      <div className="text-[12px] font-bold text-cq-primary mt-0.5">{decision.security_state?.replaceAll("_", " ")}</div>
                    </div>
                    <div className="rounded-cq-md bg-cq-surface-container-high px-2.5 py-2">
                      <div className="text-[9.5px] text-cq-on-surface-variant">Risk Level</div>
                      <div className="text-[12px] font-bold text-cq-on-surface mt-0.5">{String(decision.risk_level || "unknown").toUpperCase()}</div>
                    </div>
                    <div className="rounded-cq-md bg-cq-surface-container-high px-2.5 py-2">
                      <div className="text-[9.5px] text-cq-on-surface-variant">Risk Score</div>
                      <div className="text-[12px] font-bold text-cq-on-surface mt-0.5">{decision.risk_score ?? "—"} / 100</div>
                    </div>
                  </div>
                  {!decision.audit_chain_intact && (
                    <div className="mt-2 rounded-cq-md bg-amber-500/10 px-2.5 py-2 text-[10.5px] text-amber-300">
                      Audit-chain integrity requires administrative review. It is separate from the current live-session risk verdict.
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* Chat */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-2.5 min-h-[120px]">
            {messages.length === 0 && (
              <div className="space-y-3">
                <div className="text-[11.5px] text-cq-on-surface-variant">
                  What would you like me to investigate?
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-cq-outline mb-2">Quick checks</div>
                  <div className="flex flex-wrap gap-1.5">
                    {QUICK_PROMPTS.map((item) => (
                      <button
                        key={item.label}
                        type="button"
                        onClick={() => handleQuickPrompt(item.question)}
                        disabled={disabled || asking}
                        className="rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-[10.5px] text-cq-on-surface-variant hover:text-cq-on-surface hover:border-cq-primary/30 disabled:opacity-50"
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                <div
                  className={`max-w-[85%] rounded-cq-md px-3 py-2 text-[12px] ${
                    m.role === "user"
                      ? "bg-cq-primary-container text-cq-on-primary-container"
                      : "bg-cq-surface-container-high text-cq-on-surface"
                  }`}
                >
                  {m.text}
                  <div className="text-[9.5px] opacity-60 mt-1">{formatTimestamp(m.ts)}</div>
                </div>
              </div>
            ))}
            {messages.length > 0 && !asking && (
              <div className="pt-1">
                <div className="text-[9.5px] text-cq-outline mb-1.5">Quick checks</div>
                <div className="flex flex-wrap gap-1.5">
                  {QUICK_PROMPTS.map((item) => (
                    <button
                      key={item.label}
                      type="button"
                      onClick={() => handleQuickPrompt(item.question)}
                      disabled={disabled || asking}
                      className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-1 text-[9.5px] text-cq-on-surface-variant hover:text-cq-on-surface disabled:opacity-50"
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {asking && (
              <div className="flex items-center gap-1.5 text-[11px] text-cq-on-surface-variant">
                <Loader2 size={12} className="animate-spin" /> Qira is thinking…
              </div>
            )}
          </div>

          {voiceError && <div className="px-4 pb-1 text-[10.5px] text-cq-on-surface-variant">{voiceError}</div>}

          {/* Input */}
          <form onSubmit={handleAsk} className="flex items-center gap-2 p-3 border-t border-white/10">
            <input
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask Qira..."
              disabled={disabled}
              className="flex-1 bg-cq-surface-container-high border border-white/10 rounded-cq px-3 py-2 text-[12.5px] text-cq-on-surface placeholder:text-cq-on-surface-variant/60 focus:outline-none focus:border-cq-primary/40"
            />
            <button
              type="button"
              onClick={handleMicClick}
              disabled={disabled}
              title={voiceSupported ? "Voice input" : "Voice input unavailable"}
              className={`w-9 h-9 flex items-center justify-center rounded-cq border border-white/10 ${
                listening ? "bg-cq-error-container text-cq-error animate-pulse" : "bg-white/[0.03] text-cq-on-surface-variant hover:text-cq-on-surface"
              }`}
            >
              <Mic size={14} />
            </button>
            <button
              type="submit"
              disabled={disabled || !question.trim() || asking}
              className="w-9 h-9 flex items-center justify-center rounded-cq bg-cq-primary-container text-cq-on-primary-container hover:brightness-110 disabled:opacity-50"
            >
              <Send size={14} />
            </button>
          </form>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Launcher — Qira as a floating living character, no chat-bubble
          icon or generic orb. Hovering reveals a small contextual
          status chip; clicking opens the full command interface above. */}
      <div className="relative flex flex-col items-end gap-2">
        <AnimatePresence>
          {!open && hover && !disabled && (
            <motion.div
              initial={{ opacity: 0, x: 8 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 8 }}
              transition={{ duration: 0.15 }}
              className="mr-1 rounded-cq-md border border-white/10 bg-cq-surface-container-high px-3 py-2 shadow-cq-popover"
            >
              <div className="flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${meta.dot} cq-telemetry-dot`} />
                <span className={`text-[11px] font-semibold whitespace-nowrap ${meta.tone}`}>{summary}</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        <button
          onClick={() => setOpen((o) => !o)}
          onMouseEnter={() => setHover(true)}
          onMouseLeave={() => setHover(false)}
          onFocus={() => setHover(true)}
          onBlur={() => setHover(false)}
          disabled={disabled}
          className="relative flex items-center justify-center disabled:opacity-40 cq-focusable rounded-full"
          title="Qira — CipherQ Security Guardian"
        >
          <QiraAvatar state={avatarState} size={64} trackCursor />
        </button>
      </div>
    </div>
  );
}
