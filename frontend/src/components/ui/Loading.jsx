import { Loader2 } from "lucide-react";

/**
 * Loading — small inline spinner + label for in-panel async states
 * (e.g. a list still fetching). Not a full-page loader; use inside a
 * GlassPanel/BentoCard-style container the same way IntentHistoryPage
 * does.
 */
export default function Loading({ label = "Loading…" }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2.5 py-10 text-cq-on-surface-variant">
      <Loader2 size={22} className="animate-spin text-cq-primary" />
      <span className="text-[13px] font-medium">{label}</span>
    </div>
  );
}
