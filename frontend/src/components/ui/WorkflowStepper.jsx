// Dark/CipherQ counterparts to Misc.jsx's <Stepper> and
// <ProgressChecklist>. Kept separate (rather than editing Misc.jsx)
// since those exports currently have only two consumers — Encryption
// and Decryption — both of which are migrated to the dark theme
// together, so a small shared primitive avoids duplicating this twice.
export function WorkflowStepper({ steps, activeIndex }) {
  return (
    <div className="flex items-center gap-1.5 mb-6 overflow-x-auto">
      {steps.map((s, i) => {
        const done = i < activeIndex;
        const active = i === activeIndex;
        return (
          <div key={s} className="flex items-center gap-1.5 shrink-0">
            <div
              className={
                "flex items-center gap-2 rounded-full px-3 py-1.5 text-[12.5px] font-semibold transition-colors " +
                (done
                  ? "bg-cq-secondary-container/15 text-cq-secondary"
                  : active
                  ? "bg-cq-primary-container/20 text-cq-primary"
                  : "bg-cq-surface-container-highest/60 text-cq-on-surface-variant")
              }
            >
              <span
                className={
                  "flex items-center justify-center rounded-full text-[10px] font-bold w-[18px] h-[18px] " +
                  (done
                    ? "bg-cq-secondary text-cq-on-secondary"
                    : active
                    ? "bg-cq-primary text-cq-on-primary"
                    : "bg-cq-outline-variant/40 text-cq-on-surface-variant")
                }
              >
                {done ? "✓" : i + 1}
              </span>
              {s}
            </div>
            {i < steps.length - 1 && <div className="w-4 h-px bg-cq-outline-variant/30 shrink-0" />}
          </div>
        );
      })}
    </div>
  );
}

export function TaskChecklist({ items }) {
  return (
    <div className="space-y-2.5">
      {items.map((item) => (
        <div
          key={item.label}
          className="flex items-center gap-3 rounded-cq-md bg-cq-surface-container-high px-3.5 py-2.5"
        >
          <StepIcon status={item.status} />
          <div className="min-w-0 flex-1">
            <div className="text-[13.5px] font-semibold text-cq-on-surface">{item.label}</div>
            {item.detail && <div className="text-[12px] text-cq-on-surface-variant mt-0.5">{item.detail}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function StepIcon({ status }) {
  if (status === "done")
    return (
      <span className="flex items-center justify-center w-6 h-6 rounded-full bg-cq-secondary-container/15 text-cq-secondary shrink-0 text-[13px]">
        ✓
      </span>
    );
  if (status === "fail")
    return (
      <span className="flex items-center justify-center w-6 h-6 rounded-full bg-cq-error-container/20 text-cq-error shrink-0 text-[13px]">
        ✕
      </span>
    );
  if (status === "active")
    return (
      <span className="flex items-center justify-center w-6 h-6 rounded-full bg-cq-primary-container/20 shrink-0">
        <span className="w-2.5 h-2.5 rounded-full bg-cq-primary animate-pulse" />
      </span>
    );
  return <span className="flex items-center justify-center w-6 h-6 rounded-full bg-cq-surface-container-highest/60 shrink-0" />;
}
