import clsx from "clsx";

// Exact icon set + copy from the Stitch dashboard workflow strip:
// Intent -> QKD -> Binding -> Encryption -> Validation -> Audit -> Decryption.
const DEFAULT_STEPS = [
  { id: "intent", label: "Intent", icon: "bolt" },
  { id: "qkd", label: "QKD", icon: "hub" },
  { id: "binding", label: "Binding", icon: "link" },
  { id: "encryption", label: "Encryption", icon: "lock" },
  { id: "validation", label: "Validation", icon: "verified" },
  { id: "audit", label: "Audit", icon: "history_edu" },
  { id: "decryption", label: "Decryption", icon: "key_off" },
];

/**
 * WorkflowBreadcrumb — shows where the current page sits in the
 * intent-bound cryptography pipeline. Presentational only; `current`
 * just highlights a step, it does not drive navigation or state.
 */
export default function WorkflowBreadcrumb({ current, steps = DEFAULT_STEPS, className }) {
  return (
    <div className={clsx("flex items-center gap-cq-stack-md w-full overflow-x-auto cq-no-scrollbar py-2", className)}>
      <span className="text-[10px] uppercase tracking-tighter text-cq-outline shrink-0">Workflow:</span>
      <div className="flex items-center gap-2">
        {steps.map((step, i) => {
          const active = step.id === current;
          return (
            <div key={step.id} className="flex items-center gap-2 shrink-0">
              <div
                className={clsx(
                  "flex items-center gap-1.5 text-cq-label-md",
                  active ? "text-cq-primary" : "text-cq-on-surface-variant"
                )}
              >
                <span className="material-symbols-outlined text-[14px]">{step.icon}</span>
                {step.label}
              </div>
              {i < steps.length - 1 && (
                <span className="material-symbols-outlined text-cq-outline text-[12px]">chevron_right</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
