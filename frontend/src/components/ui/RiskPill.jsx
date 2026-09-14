// Dark/CipherQ counterpart to Badge.jsx's <RiskBadge>. Kept separate
// (rather than editing Badge.jsx) since RiskBadge/Badge are still used,
// in their original light styling, by other pages not yet migrated
// (e.g. PolicyManagementPage).
const TONES = {
  low: { bg: "rgba(99,247,255,0.15)", fg: "#63f7ff" },
  medium: { bg: "rgba(251,191,36,0.15)", fg: "#fbbf24" },
  high: { bg: "rgba(255,180,171,0.15)", fg: "#ffb4ab" },
};

export default function RiskPill({ level }) {
  const t = TONES[level?.toLowerCase()] || { bg: "rgba(196,197,217,0.12)", fg: "#c4c5d9" };
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap capitalize"
      style={{ background: t.bg, color: t.fg }}
    >
      {level}
    </span>
  );
}
