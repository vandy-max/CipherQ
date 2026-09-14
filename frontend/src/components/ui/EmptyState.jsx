import { Inbox } from "lucide-react";

/**
 * EmptyState — "nothing here yet" placeholder for in-panel lists
 * (e.g. IntentHistoryPage when the user has no intents). Purely
 * presentational, matches the dark CipherQ surface styling used by
 * Alert/RiskPill/GlassPanel.
 */
export default function EmptyState({ title = "Nothing here yet", desc, icon: Icon = Inbox }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-cq-lg border border-dashed border-cq-outline-variant/30 py-10 text-center">
      <Icon size={22} className="text-cq-on-surface-variant/60" />
      <span className="text-[13.5px] font-semibold text-cq-on-surface">{title}</span>
      {desc && <span className="text-[12.5px] text-cq-on-surface-variant max-w-xs">{desc}</span>}
    </div>
  );
}
