import clsx from "clsx";
import { ChevronDown } from "lucide-react";

// CipherQ / Stitch form controls. Per DESIGN.md: inputs sit darker than
// the card background, with a Secondary (Cyan) 1px border on focus.
const baseInput =
  "w-full rounded-cq-md border border-cq-outline-variant/30 bg-cq-surface-container-lowest px-3.5 py-2.5 text-[14px] text-cq-on-surface " +
  "placeholder:text-cq-outline/60 transition-colors duration-150 outline-none focus:border-cq-secondary/60 focus:ring-2 focus:ring-cq-secondary/15";

export function Label({ children, hint }) {
  return (
    <label className="block text-cq-label-md font-label-md uppercase tracking-wide text-cq-on-surface-variant mb-2">
      {children}
      {hint && <span className="ml-1.5 normal-case font-normal text-cq-outline">{hint}</span>}
    </label>
  );
}

export function Field({ label, hint, children, className }) {
  return (
    <div className={clsx("mb-4", className)}>
      {label && <Label hint={hint}>{label}</Label>}
      {children}
    </div>
  );
}

export function TextField({ mono, className, ...props }) {
  return <input className={clsx(baseInput, mono && "font-mono text-[13px]", className)} {...props} />;
}

export function TextAreaField({ className, ...props }) {
  return <textarea className={clsx(baseInput, "resize-y leading-relaxed", className)} {...props} />;
}

export function SelectField({ children, className, ...props }) {
  return (
    <div className="relative">
      <select
        className={clsx(baseInput, "appearance-none pr-9 cursor-pointer", className)}
        {...props}
      >
        {children}
      </select>
      <ChevronDown
        size={16}
        className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-cq-outline"
      />
    </div>
  );
}

export function Toggle({ checked, onChange, label }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="inline-flex items-center gap-2.5"
    >
      <span
        className={clsx(
          "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors duration-200",
          checked ? "bg-cq-primary-container shadow-cq-glow-primary" : "bg-cq-surface-container-highest"
        )}
      >
        <span
          className={clsx(
            "inline-block h-[18px] w-[18px] transform rounded-full bg-cq-on-primary-container shadow transition-transform duration-200",
            checked ? "translate-x-[22px]" : "translate-x-[3px]"
          )}
        />
      </span>
      {label && <span className="text-[13.5px] font-medium text-cq-on-surface-variant">{label}</span>}
    </button>
  );
}

export function CheckboxField({ checked, onChange, label }) {
  return (
    <label className="inline-flex items-center gap-2 cursor-pointer select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-4 h-4 rounded accent-[#b8c3ff]"
      />
      <span className="text-[13.5px] font-medium text-cq-on-surface-variant">{label}</span>
    </label>
  );
}
