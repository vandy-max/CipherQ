import { useState } from "react";
import { Copy, Check } from "lucide-react";

export default function CopyBox({ value, label }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  };
  return (
    <div className="mb-4 last:mb-0">
      {label && (
        <div className="text-cq-label-md font-label-md uppercase tracking-wide text-cq-on-surface-variant mb-1.5">
          {label}
        </div>
      )}
      <div className="flex items-stretch gap-2 rounded-cq-md border border-cq-outline-variant/25 bg-cq-surface-container-lowest pl-3.5 pr-1.5 py-1.5">
        <code className="flex-1 self-center text-[13px] leading-relaxed text-cq-on-surface-variant font-mono break-all">
          {value}
        </code>
        <button
          type="button"
          onClick={copy}
          className="shrink-0 inline-flex items-center gap-1.5 rounded-cq px-3 py-1.5 text-[12.5px] font-semibold transition-colors"
          style={{
            background: copied ? "rgba(99,247,255,0.15)" : "rgba(255,255,255,0.06)",
            color: copied ? "#63f7ff" : "#c4c5d9",
          }}
        >
          {copied ? <Check size={14} /> : <Copy size={14} />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}
