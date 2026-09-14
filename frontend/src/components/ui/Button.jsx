import { forwardRef } from "react";
import clsx from "clsx";
import { Loader2 } from "lucide-react";

// CipherQ / Stitch button system. Per DESIGN.md: solid Electric Blue
// (primary-container) for primary actions; ghost buttons with a 1px
// white(10%) border + hover-glow for secondary actions; 8px radius.
const VARIANTS = {
  primary:
    "bg-cq-primary-container text-cq-on-primary-container hover:brightness-110 shadow-cq-glow-primary disabled:opacity-50 border border-transparent",
  brand:
    "bg-cq-primary-container text-cq-on-primary-container hover:brightness-110 shadow-cq-glow-primary disabled:opacity-50 border border-transparent",
  accent:
    "bg-cq-tertiary-container text-cq-on-tertiary-container hover:brightness-110 shadow-cq-glow-tertiary disabled:opacity-50 border border-transparent",
  ghost:
    "bg-white/[0.03] text-cq-on-surface border border-white/10 hover:bg-white/[0.07] hover:border-white/20 hover:shadow-cq-glow-primary",
  outline:
    "bg-transparent text-cq-on-surface border border-cq-outline-variant/40 hover:bg-cq-surface-container-high hover:border-cq-outline-variant",
  danger:
    "bg-cq-error-container text-cq-on-error-container hover:brightness-110 border border-transparent disabled:opacity-50",
  subtle:
    "bg-cq-surface-container-high text-cq-on-surface hover:bg-cq-surface-container-highest border border-transparent",
};

const SIZES = {
  sm: "text-[13px] px-3 py-1.5 gap-1.5 rounded-cq",
  md: "text-[14px] px-4 py-2.5 gap-2 rounded-cq",
  lg: "text-[15px] px-5 py-3 gap-2 rounded-cq-md",
};

const ACCENT_BG = {
  indigo: "#2e5bff",
  violet: "#a03ad3",
  mint: "#00f4fe",
  peach: "#e8672a",
  sky: "#00f4fe",
  amber: "#b9760b",
  rose: "#ffb4ab",
};

const Button = forwardRef(function Button(
  {
    variant = "primary",
    size = "md",
    accent,
    icon: Icon,
    iconRight: IconRight,
    loading = false,
    full = false,
    className,
    children,
    disabled,
    ...props
  },
  ref
) {
  const style = variant === "accent" && accent ? { backgroundColor: ACCENT_BG[accent] || ACCENT_BG.indigo } : undefined;
  return (
    <button
      ref={ref}
      className={clsx(
        "inline-flex items-center justify-center font-semibold tracking-[-0.01em] transition-all duration-150",
        "active:scale-[0.98] disabled:cursor-not-allowed disabled:active:scale-100",
        VARIANTS[variant],
        SIZES[size],
        full && "w-full",
        className
      )}
      style={style}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <Loader2 size={16} className="animate-spin" />
      ) : (
        Icon && <Icon size={16} strokeWidth={2.25} />
      )}
      {children}
      {!loading && IconRight && <IconRight size={16} strokeWidth={2.25} />}
    </button>
  );
});

export default Button;
