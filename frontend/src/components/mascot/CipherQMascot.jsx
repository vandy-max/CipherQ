import "./CipherQMascot.css";

// CipherQMascot — a small, reusable brand/UX element: a futuristic owl
// guardian representing CipherQ. It is DECORATIVE ONLY.
//
// IMPORTANT: this component never determines, computes, or guesses any
// security state. Callers must always pass a `status` derived from the
// SAME authoritative source every other monitoring surface already uses
// (e.g. `deriveMonitoringState()` from
// ../monitoring/monitoringState.js, or another real backend field).
// When no status is available/relevant, the mascot simply renders its
// calm default appearance — that default is a branding choice, not a
// claim about system security.

const SIZE_PRESETS = {
  xs: 16,
  sm: 24,
  md: 32,
  lg: 48,
  xl: 72,
};

// One shared vocabulary with monitoringState.js's MONITORING_UI_META —
// intentionally the same four keys (active / warning / reauth_required /
// revoked) so a snapshot-derived stateKey can be passed straight through
// as `status` with no translation layer.
const STATUS_META = {
  active: {
    glow: "#63f7ff", // cq-secondary
    label: "Secure",
  },
  warning: {
    glow: "#f59e0b", // amber-500, matches existing WARNING styling app-wide
    label: "Warning — vigilant",
  },
  reauth_required: {
    glow: "#f59e0b",
    label: "Re-authentication required",
  },
  revoked: {
    glow: "#ffb4ab", // cq-error
    label: "Revoked — protective stance",
  },
};

/**
 * <CipherQMascot />
 *
 * Props:
 *  - size: preset key ("xs"|"sm"|"md"|"lg"|"xl") or a number (px). Default "sm" (24px).
 *  - status: "active" | "warning" | "reauth_required" | "revoked" | undefined.
 *            Must be derived from real backend/session state by the caller.
 *            Omit for a neutral/calm default appearance (no security claim implied).
 *  - tooltip: optional string shown as a native title/aria-describedby hint.
 *  - animate: boolean, default true. When false, renders a static frame
 *             (also automatically respected via prefers-reduced-motion).
 *  - className: optional extra class(es) for layout/positioning by the caller.
 */
export default function CipherQMascot({
  size = "sm",
  status,
  tooltip,
  animate = true,
  className = "",
}) {
  const px = typeof size === "number" ? size : SIZE_PRESETS[size] || SIZE_PRESETS.sm;
  const meta = STATUS_META[status] || null;
  const glow = meta?.glow || "#63f7ff";
  const isRevoked = status === "revoked";
  const statusClass = animate && status ? `cq-mascot--${status}` : "";
  const describedLabel = tooltip || (meta ? `CipherQ Security Guardian — ${meta.label}` : "CipherQ Security Guardian");

  return (
    <span
      className={`cq-mascot ${statusClass} ${className}`.trim()}
      style={{ width: px, height: px, color: glow }}
      title={tooltip}
    >
      <svg
        viewBox="0 0 64 64"
        width={px}
        height={px}
        role="img"
        aria-label="CipherQ Security Guardian"
      >
        <title>{describedLabel}</title>
        <defs>
          <radialGradient id="cqm-body-sheen" cx="35%" cy="25%" r="75%">
            <stop offset="0%" stopColor="#282933" />
            <stop offset="100%" stopColor="#0c0e17" />
          </radialGradient>
          <filter id="cqm-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="1.6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Hood / body — a single continuous silhouette (two soft
            ear-tuft points tapering into a rounded torso), kept
            deliberately simple so it stays legible at very small sizes. */}
        <path
          d="M32 3.5
             C 26.5 3.5 22.5 7.4 20.5 9.6
             C 11.5 12.8 5.5 21.2 5.5 31.5
             C 5.5 46.5 15.5 58.5 32 60.5
             C 48.5 58.5 58.5 46.5 58.5 31.5
             C 58.5 21.2 52.5 12.8 43.5 9.6
             C 41.5 7.4 37.5 3.5 32 3.5 Z"
          fill="url(#cqm-body-sheen)"
          stroke="#434656"
          strokeWidth="0.75"
        />

        {/* Subtle feather-line details on the hood — kept minimal. */}
        <path
          d="M16 15 C 13 20 11.5 25.5 11.5 31"
          fill="none"
          stroke="#c4c5d9"
          strokeOpacity="0.18"
          strokeWidth="1"
          strokeLinecap="round"
        />
        <path
          d="M48 15 C 51 20 52.5 25.5 52.5 31"
          fill="none"
          stroke="#c4c5d9"
          strokeOpacity="0.18"
          strokeWidth="1"
          strokeLinecap="round"
        />

        {/* Face plate */}
        <ellipse cx="32" cy="29" rx="18" ry="15.5" fill="#1d1f29" />

        {/* Eyes + glow group (status pulse animation targets this group) */}
        <g className="cq-mascot-glow-group" filter="url(#cqm-glow)">
          {isRevoked ? (
            <>
              {/* Narrowed, still eyes — a serious/protective expression,
                  deliberately not round/soft like the other states. */}
              <ellipse cx="24" cy="29" rx="6" ry="3" fill={glow} />
              <ellipse cx="40" cy="29" rx="6" ry="3" fill={glow} />
            </>
          ) : (
            <>
              <circle cx="24" cy="29" r="6" fill={glow} />
              <circle cx="40" cy="29" r="6" fill={glow} />
            </>
          )}
          {/* Pupils */}
          <circle cx="24" cy="29" r="2.1" fill="#0c0e17" />
          <circle cx="40" cy="29" r="2.1" fill="#0c0e17" />
        </g>

        {/* Eyelids — animated only in the "active" state (gentle blink) */}
        <rect className="cq-mascot-eyelid" x="17.5" y="22" width="13" height="13" rx="6.5" fill="#1d1f29" />
        <rect className="cq-mascot-eyelid" x="33.5" y="22" width="13" height="13" rx="6.5" fill="#1d1f29" />

        {/* Small beak, subtle silver */}
        <path d="M32 33.5 L35 38 L29 38 Z" fill="#c4c5d9" fillOpacity="0.55" />

        {/* Wing accents — thin silver curves along both flanks */}
        <path
          d="M10 36 C 7.5 43 9 50 15 55"
          fill="none"
          stroke="#c4c5d9"
          strokeOpacity="0.3"
          strokeWidth="1.3"
          strokeLinecap="round"
        />
        <path
          d="M54 36 C 56.5 43 55 50 49 55"
          fill="none"
          stroke="#c4c5d9"
          strokeOpacity="0.3"
          strokeWidth="1.3"
          strokeLinecap="round"
        />

        {/* Chest emblem — a small lock/Q mark in the CipherQ purple accent */}
        <g transform="translate(32 49)">
          <rect x="-5.5" y="-5.5" width="11" height="11" rx="2.5" transform="rotate(45)" fill="#a03ad3" stroke="#e9b3ff" strokeWidth="0.6" />
          <circle cx="0" cy="-1" r="1.6" fill="#e9b3ff" />
          <rect x="-0.7" y="0" width="1.4" height="3" rx="0.7" fill="#e9b3ff" />
        </g>
      </svg>
    </span>
  );
}
