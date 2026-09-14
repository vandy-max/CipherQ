// Dark/CipherQ counterpart to Badge.jsx's <LifecycleBadge>. Kept as a
// separate component (rather than editing Badge.jsx) because Badge.jsx
// is still used, in its original light styling, by several pages that
// haven't been migrated yet.
const TONES = {
  draft: { bg: "rgba(196,197,217,0.12)", fg: "#c4c5d9" },
  approved: { bg: "rgba(184,195,255,0.15)", fg: "#b8c3ff" },
  rejected: { bg: "rgba(255,180,171,0.15)", fg: "#ffb4ab" },
  used: { bg: "rgba(99,247,255,0.15)", fg: "#63f7ff" },
  expired: { bg: "rgba(251,191,36,0.15)", fg: "#fbbf24" },
  archived: { bg: "rgba(196,197,217,0.12)", fg: "#c4c5d9" },
  destroyed: { bg: "rgba(255,180,171,0.15)", fg: "#ffb4ab" },
};

export default function LifecyclePill({ state }) {
  const t = TONES[state?.toLowerCase()] || TONES.draft;
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap capitalize"
      style={{ background: t.bg, color: t.fg }}
    >
      {state}
    </span>
  );
}
