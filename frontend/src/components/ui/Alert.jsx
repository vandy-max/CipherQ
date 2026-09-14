import { AlertOctagon, CheckCircle2, Info } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

// CipherQ tone mapping: error -> error/error-container, success -> secondary
// (cyan "safe" indicator per DESIGN.md), info -> primary.
const KIND = {
  error: { bg: "rgba(255,180,171,0.10)", border: "rgba(255,180,171,0.25)", fg: "#ffb4ab", icon: AlertOctagon },
  success: { bg: "rgba(99,247,255,0.10)", border: "rgba(99,247,255,0.25)", fg: "#63f7ff", icon: CheckCircle2 },
  info: { bg: "rgba(184,195,255,0.10)", border: "rgba(184,195,255,0.25)", fg: "#b8c3ff", icon: Info },
};

export default function Alert({ type = "error", children }) {
  if (!children) return null;
  const k = KIND[type] || KIND.error;
  const Icon = k.icon;
  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, height: 0 }}
        animate={{ opacity: 1, height: "auto" }}
        exit={{ opacity: 0, height: 0 }}
        className="overflow-hidden"
      >
        <div
          className="flex items-start gap-2.5 rounded-cq-md px-4 py-3 text-[13.5px] font-medium leading-relaxed mb-4 border"
          style={{ background: k.bg, color: k.fg, borderColor: k.border }}
        >
          <Icon size={17} className="shrink-0 mt-0.5" />
          <span>{children}</span>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}
