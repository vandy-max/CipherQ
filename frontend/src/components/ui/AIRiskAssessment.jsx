// Read-only display of the backend's autonomous AI risk analysis
// (see backend policy/ai_risk_service.py). Nothing here is editable —
// every field is computed server-side and handed back on the
// encrypt/decrypt response. The user never selects or enters a risk
// level; this component only shows what the backend already decided.
export default function AIRiskAssessment({ result }) {
  if (!result) return null;

  const patterns = result.ai_detected_patterns || [];
  const hasAssessment = result.ai_explanation || patterns.length > 0;
  if (!hasAssessment) return null;

  return (
    <div className="mt-3 rounded-cq-md bg-cq-surface-container-high/60 px-4 py-3 text-[12.5px] leading-relaxed text-cq-on-surface-variant">
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-semibold text-cq-on-surface">AI Security Assessment</span>
        <span className="text-[11px] opacity-70">
          {result.ai_risk_available ? "advisory model active" : "deterministic fallback"}
        </span>
      </div>

      {result.ai_risk_confidence != null && (
        <div className="mb-1">
          Confidence: {(result.ai_risk_confidence * 100).toFixed(0)}%
        </div>
      )}

      {patterns.length > 0 && (
        <ul className="list-disc list-inside mb-1">
          {patterns.map((pattern) => (
            <li key={pattern}>{pattern.replaceAll("_", " ")}</li>
          ))}
        </ul>
      )}

      {result.ai_explanation && <div className="opacity-80">{result.ai_explanation}</div>}
    </div>
  );
}
