import { useState } from "react";
import clsx from "clsx";
import { motion } from "framer-motion";

/**
 * SecurityFieldGraph — interactive node topology:
 *   User -> Identity -> Device -> Session -> Quantum Channel
 *
 * Every node's status text is derived from the real monitoring
 * snapshot fields passed in via `snapshot` (see
 * api/schemas.py::MonitoringSnapshotResponse) — never invented. A
 * field that isn't present on the snapshot renders as "—" rather than
 * a fabricated value.
 *
 * Props:
 *  - snapshot: the live MonitoringSnapshotResponse-shaped object (or null)
 *  - quantumOnline: boolean — real quantum backend availability
 *  - stateColor: hex color for the active accent (matches current
 *    monitoring state, from monitoringState.js)
 */
function truncateId(id) {
  if (!id) return "—";
  return id.length > 10 ? `${id.slice(0, 6)}…${id.slice(-4)}` : id;
}

export default function SecurityFieldGraph({ snapshot, quantumOnline, stateColor = "#63f7ff" }) {
  const [active, setActive] = useState(null);

  const nodes = [
    {
      id: "identity",
      label: "IDENTITY",
      icon: "face",
      status: snapshot ? (snapshot.identity_state || (snapshot.face_present ? "verified" : "no_face")) : "—",
      detail: snapshot
        ? `Face present: ${snapshot.face_present ? "yes" : "no"} · Liveness: ${snapshot.liveness ? "confirmed" : "unconfirmed"}${
            typeof snapshot.face_match_confidence === "number" ? ` · Confidence: ${Math.round(snapshot.face_match_confidence * 100)}%` : ""
          }`
        : "No active session",
      ok: snapshot ? Boolean(snapshot.face_present && snapshot.liveness) : false,
    },
    {
      id: "device",
      label: "DEVICE",
      icon: "devices",
      status: snapshot?.current_device ? truncateId(snapshot.current_device) : "—",
      detail: snapshot?.current_device ? `Device ID ${snapshot.current_device}` : "No device bound",
      ok: Boolean(snapshot?.current_device),
    },
    {
      id: "session",
      label: "SESSION",
      icon: "vpn_key",
      status: snapshot?.current_authorization_state || "—",
      detail: snapshot?.current_session ? `Session ${truncateId(snapshot.current_session)}` : "No session",
      ok: snapshot?.current_authorization_state ? !["revoked", "reauth_required"].includes(snapshot.current_authorization_state) : false,
    },
    {
      id: "quantum",
      label: "QUANTUM CHANNEL",
      icon: "hub",
      status: quantumOnline ? "Online" : "Offline",
      detail: quantumOnline ? "BB84 backend reachable" : "Quantum backend unavailable",
      ok: Boolean(quantumOnline),
    },
  ];

  // Simple horizontal chain layout with the quantum node branching below.
  return (
    <div className="relative w-full overflow-x-auto cq-no-scrollbar">
      <svg viewBox="0 0 760 200" className="w-full min-w-[560px] h-[200px]">
        <defs>
          <marker id="sfg-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill={stateColor} fillOpacity="0.5" />
          </marker>
        </defs>

        {/* User -> Identity -> Device -> Session chain */}
        <line x1="60" y1="70" x2="200" y2="70" stroke={stateColor} strokeOpacity="0.25" strokeWidth="1.5" markerEnd="url(#sfg-arrow)" />
        <line x1="260" y1="70" x2="400" y2="70" stroke={stateColor} strokeOpacity="0.25" strokeWidth="1.5" markerEnd="url(#sfg-arrow)" />
        <line x1="460" y1="70" x2="600" y2="70" stroke={stateColor} strokeOpacity="0.25" strokeWidth="1.5" markerEnd="url(#sfg-arrow)" />
        {/* Session -> Quantum Channel branch */}
        <line x1="630" y1="90" x2="630" y2="150" stroke="#a03ad3" strokeOpacity="0.3" strokeWidth="1.5" markerEnd="url(#sfg-arrow)" />

        {/* travelling particles along the main chain, only when the graph is healthy */}
        {nodes.every((n) => n.ok) && (
          <>
            <circle r="2.2" fill={stateColor}>
              <animateMotion dur="3.4s" repeatCount="indefinite" path="M60,70 L600,70" />
            </circle>
            <circle r="1.8" fill="#a03ad3">
              <animateMotion dur="2.1s" repeatCount="indefinite" path="M630,90 L630,150" />
            </circle>
          </>
        )}

        {/* User origin marker */}
        <g transform="translate(30,70)">
          <circle r="14" fill="#1d1f29" stroke="#434656" strokeWidth="1" />
          <text textAnchor="middle" dy="4" className="fill-cq-on-surface-variant text-[10px] font-bold">U</text>
        </g>
      </svg>

      {/* Node cards, absolutely positioned to align with the svg chain (percentage-based so it scales) */}
      <div className="absolute inset-0 pointer-events-none">
        {[
          { ...nodes[0], leftPct: (230 / 760) * 100, topPct: (70 / 200) * 100 },
          { ...nodes[1], leftPct: (430 / 760) * 100, topPct: (70 / 200) * 100 },
          { ...nodes[2], leftPct: (630 / 760) * 100, topPct: (70 / 200) * 100 },
          { ...nodes[3], leftPct: (630 / 760) * 100, topPct: (185 / 200) * 100 },
        ].map((n) => (
          <motion.button
            type="button"
            key={n.id}
            onMouseEnter={() => setActive(n.id)}
            onMouseLeave={() => setActive((a) => (a === n.id ? null : a))}
            onFocus={() => setActive(n.id)}
            onClick={() => setActive((a) => (a === n.id ? null : n.id))}
            className="pointer-events-auto absolute flex flex-col items-center gap-1.5 -translate-x-1/2 -translate-y-1/2 group cq-focusable rounded-cq-md"
            style={{ left: `${n.leftPct}%`, top: `${n.topPct}%` }}
            whileHover={{ scale: 1.06 }}
          >
            <span
              className={clsx(
                "flex items-center justify-center w-11 h-11 rounded-cq-md border transition-colors",
                n.ok ? "bg-cq-surface-container-high border-cq-secondary/30" : "bg-cq-surface-container-high border-cq-error/30"
              )}
              style={{ boxShadow: active === n.id ? `0 0 16px ${n.ok ? stateColor : "#ffb4ab"}55` : "none" }}
            >
              <span
                className="material-symbols-outlined text-[18px]"
                style={{ color: n.ok ? stateColor : "#ffb4ab" }}
              >
                {n.icon}
              </span>
            </span>
            <span className="text-[9px] font-bold tracking-[0.14em] text-cq-on-surface-variant whitespace-nowrap">
              {n.label}
            </span>
          </motion.button>
        ))}
      </div>

      {/* Detail panel for active node */}
      {active && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-3 rounded-cq-md border border-cq-outline-variant/25 bg-cq-surface-container-high px-4 py-3"
        >
          {(() => {
            const n = nodes.find((x) => x.id === active);
            if (!n) return null;
            return (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-[12px] font-bold tracking-widest text-cq-on-surface uppercase">{n.label}</span>
                  <span
                    className="text-[10.5px] font-semibold px-2 py-0.5 rounded-full"
                    style={{ color: n.ok ? stateColor : "#ffb4ab", background: `${n.ok ? stateColor : "#ffb4ab"}1a` }}
                  >
                    {n.status}
                  </span>
                </div>
                <p className="text-[12px] text-cq-on-surface-variant mt-1">{n.detail}</p>
              </>
            );
          })()}
        </motion.div>
      )}
    </div>
  );
}
