/**
 * PageHeader — the eyebrow-icon + display-lg title + body-lg description
 * pattern used at the top of every non-dashboard Stitch screen (see
 * audit_trail_1, encryption_pipeline_1, policy_engine_1, risk_analysis_1,
 * decryption_verification_1, quantum_key_distribution/code.html).
 * Presentational only — pages pass their own copy + optional right-hand
 * visual/action slot.
 */
export default function PageHeader({ icon, eyebrow, title, description, right }) {
  return (
    <section className="flex flex-col md:flex-row gap-cq-gutter items-start justify-between mb-cq-stack-lg">
      <div className="flex flex-col gap-1 max-w-2xl">
        {(icon || eyebrow) && (
          <div className="flex items-center gap-cq-stack-sm text-cq-primary mb-1">
            {icon && <span className="material-symbols-outlined text-[20px]">{icon}</span>}
            {eyebrow && (
              <span className="font-label-md text-cq-label-md uppercase tracking-[0.2em]">{eyebrow}</span>
            )}
          </div>
        )}
        <h1 className="font-display-lg text-[32px] sm:text-cq-display-lg text-cq-on-surface tracking-tighter">
          {title}
        </h1>
        {description && (
          <p className="font-body-lg text-cq-body-lg text-cq-on-surface-variant mt-1">{description}</p>
        )}
      </div>
      {right && <div className="w-full md:w-auto shrink-0">{right}</div>}
    </section>
  );
}
