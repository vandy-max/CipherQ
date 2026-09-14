import clsx from "clsx";
import { motion } from "framer-motion";

/**
 * BentoCard — CipherQ metric/stat tile used in bento-style grids
 * (design reference: Stitch `dashboard_1` / `dashboard_2`).
 *
 * This is a presentational primitive only: it takes a value/label/icon
 * and an optional trend chip. Pages remain responsible for fetching
 * real data via `services/api.js` and passing it in as props — no
 * network calls or dummy numbers live here.
 *
 * Example:
 *   <BentoCard icon={ShieldCheck} label="System Health" value="99.8%" trend="+0.2%" />
 */
export default function BentoCard({
  icon: Icon,
  label,
  value,
  trend,
  trendTone = "secondary", // "secondary" (positive/live) | "muted"
  className,
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: "easeOut" }}
      className={clsx(
        "bg-cq-surface-container rounded-cq-xl p-cq-stack-lg",
        "hover:bg-cq-surface-container-high transition-colors group",
        className
      )}
    >
      <div className="flex justify-between items-start mb-cq-stack-md">
        {Icon && (
          <Icon
            size={20}
            className="text-cq-primary group-hover:scale-110 transition-transform"
          />
        )}
        {trend && (
          <span
            className={clsx(
              "text-cq-label-md font-mono tracking-wide",
              trendTone === "secondary" ? "text-cq-secondary" : "text-cq-on-surface-variant"
            )}
          >
            {trend}
          </span>
        )}
      </div>
      <div className="text-cq-on-surface-variant text-cq-label-md uppercase tracking-wider mb-1">
        {label}
      </div>
      <div className="text-cq-headline-lg font-semibold text-cq-on-surface tabular-nums">
        {value}
      </div>
    </motion.div>
  );
}
