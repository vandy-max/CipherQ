import { useEffect, useMemo, useState } from "react";
import { RefreshCcw, ShieldAlert, Download, ListChecks, CheckCircle2, XCircle, X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import BentoCard from "../components/ui/BentoCard";
import DataTable from "../components/ui/DataTable";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import PageHeader from "../components/ui/PageHeader";
import { listAuditLogs, verifyAuditChain } from "../services/api";
import { formatTimestamp, byTimestampDesc } from "../utils/formatTimestamp";

function Pill({ ok, children }) {
  return (
    <span
      className={
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px] font-semibold whitespace-nowrap " +
        (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
      }
    >
      {ok ? <CheckCircle2 size={13} strokeWidth={2.5} /> : <XCircle size={13} strokeWidth={2.5} />}
      {children}
    </span>
  );
}

function exportCsv(sortedLogs) {
  // CSV export must use the SAME newest-first ordering as the visible
  // audit table — `sortedLogs` is the exact array already sorted for
  // display, not the raw API response.
  const header = ["timestamp", "user_id", "action", "result", "intent_hash", "current_log_hash"];
  const rows = sortedLogs.map((l) => header.map((h) => JSON.stringify(l[h] ?? "")).join(","));
  const csv = [header.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ibqc-audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [verification, setVerification] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null); // the investigation-panel row

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [logsResponse, verifyResponse] = await Promise.all([
        listAuditLogs(),
        verifyAuditChain(),
      ]);
      setLogs(logsResponse);
      setVerification(verifyResponse);
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const stats = useMemo(() => {
    const success = logs.filter((l) => /success|ok|approved|granted/i.test(l.result)).length;
    const rejected = logs.length - success;
    const last24h = logs.filter((l) => Date.now() - new Date(l.timestamp).getTime() < 86400000).length;
    return { total: logs.length, success, rejected, last24h };
  }, [logs]);

  const columns = [
    {
      key: "timestamp",
      label: "Timestamp",
      sortable: true,
      mono: true,
      render: (r) => formatTimestamp(r.timestamp),
    },
    { key: "user_id", label: "User", sortable: true, render: (r) => r.user_id ?? "—" },
    { key: "action", label: "Action", sortable: true },
    {
      key: "result",
      label: "Result",
      sortable: true,
      render: (r) => <Pill ok={/success|ok|approved|granted/i.test(r.result)}>{r.result}</Pill>,
    },
    {
      key: "intent_hash",
      label: "Intent Hash",
      mono: true,
      render: (r) => (r.intent_hash ? r.intent_hash.slice(0, 12) + "…" : "—"),
    },
    {
      key: "current_log_hash",
      label: "Log Hash",
      mono: true,
      render: (r) => r.current_log_hash.slice(0, 12) + "…",
    },
  ];

  // Audit log must always display NEWEST -> OLDEST. Explicitly sort by
  // timestamp descending (stable tie-break on the original hash-chain/
  // API order) rather than trusting the API's response order — the
  // hash-chain semantics themselves are untouched; only this
  // presentation ordering changes.
  const rows = useMemo(() => {
    const withIndex = logs.map((l, i) => ({ ...l, id: i }));
    withIndex.sort(byTimestampDesc("timestamp", "id"));
    return withIndex;
  }, [logs]);

  return (
    <div>
      <PageHeader
        icon="verified_user"
        eyebrow="Forensic Integrity Verified"
        title="Audit Trail"
        description="The CipherQ immutable ledger uses a hash-chained architecture. Every administrative action and intent modification is cryptographically linked to the preceding entry, giving mathematical proof of non-repudiation."
        right={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" icon={Download} onClick={() => exportCsv(rows)} disabled={!logs.length}>
              Export CSV
            </Button>
            <Button variant="outline" size="sm" icon={RefreshCcw} onClick={load}>
              Refresh
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 mb-6">
        <BentoCard icon={ListChecks} label="Total Events" value={stats.total} />
        <BentoCard icon={CheckCircle2} label="Successful" value={stats.success} />
        <BentoCard icon={XCircle} label="Rejected" value={stats.rejected} trendTone="muted" />
        <BentoCard icon={ShieldAlert} label="Last 24h" value={stats.last24h} />
      </div>

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
        <div className="flex items-center justify-between flex-wrap gap-3">
          {verification && (
            <Pill ok={verification.valid}>
              {verification.valid ? "VERIFIED — all integrity checks passed" : "FAILED — integrity check requires review"}
            </Pill>
          )}
        </div>
        {verification && (
          <div className="mt-3.5 grid grid-cols-2 md:grid-cols-5 gap-2">
            {[
              ["Genesis", verification.checks?.genesis],
              ["Chain continuity", verification.checks?.chain_continuity],
              ["Hash verification", verification.checks?.hash_verification],
              ["Required fields", verification.checks?.required_fields],
              ["Chronological order", verification.checks?.chronological_order],
            ].map(([label, ok]) => (
              <div key={label} className="rounded-cq-md bg-cq-surface-container-high px-3 py-2">
                <div className="text-[10px] text-cq-outline mb-1">{label}</div>
                <div className={`text-[11.5px] font-bold ${ok ? "text-cq-secondary" : "text-cq-error"}`}>{ok ? "PASS" : "FAIL"}</div>
              </div>
            ))}
          </div>
        )}
        {verification && !verification.valid && (
          <div className="mt-3.5 flex items-start gap-2.5 rounded-cq-md bg-cq-error-container/15 px-4 py-3 text-[13px] text-cq-error">
            <ShieldAlert size={16} className="shrink-0 mt-0.5" />
            <div>
              <div>{verification.reason}</div>
              <div className="mt-1 text-[11px] text-cq-on-surface-variant">First invalid entry: {verification.first_invalid_index ?? "—"} · Entries checked: {verification.checked_entries ?? 0}</div>
            </div>
          </div>
        )}
      </div>

      <Alert type="error">{error}</Alert>

      {loading ? (
        <div className="bg-cq-surface-container rounded-cq-xl p-14 flex flex-col items-center justify-center gap-4 text-center mt-6">
          <div className="relative w-11 h-11">
            <motion.div className="absolute inset-0 rounded-full border-[3px] border-cq-primary/20" />
            <motion.div
              className="absolute inset-0 rounded-full border-[3px] border-transparent border-t-cq-primary border-r-cq-secondary"
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 0.9, ease: "linear" }}
            />
          </div>
          <p className="text-cq-body-md text-cq-on-surface-variant">Loading audit trail…</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-5 mt-6 items-start">
          <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
            <DataTable
              columns={columns}
              rows={rows}
              searchKeys={["action", "result", "user_id", "intent_hash"]}
              searchPlaceholder="Search action, result, user, or hash…"
              emptyTitle="No audit entries yet"
              emptyDesc="Actions across the platform will appear here as they occur."
              onRowClick={(row) => setSelected(row)}
              selectedRowId={selected?.id}
            />
          </div>

          {/* Investigation panel — opens for the selected event; every
              field shown is exactly what the audit API returned for
              that row (AuditLogEntryResponse), nothing synthesized. */}
          <div className="xl:sticky xl:top-[7.5rem]">
            <AnimatePresence mode="wait">
              {selected ? (
                <motion.div
                  key={selected.id}
                  initial={{ opacity: 0, x: 12 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 12 }}
                  transition={{ duration: 0.18 }}
                  className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg"
                >
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-[11px] font-bold tracking-[0.16em] text-cq-on-surface-variant uppercase">
                      Event Investigation
                    </span>
                    <button onClick={() => setSelected(null)} className="text-cq-on-surface-variant hover:text-cq-on-surface">
                      <X size={16} />
                    </button>
                  </div>

                  <Pill ok={/success|ok|approved|granted/i.test(selected.result)}>{selected.result}</Pill>
                  <div className="mt-3 text-[15px] font-bold text-cq-on-surface">{selected.action}</div>
                  <div className="text-[12px] text-cq-on-surface-variant font-mono mt-0.5">{formatTimestamp(selected.timestamp)}</div>

                  <div className="mt-4 space-y-2.5 text-[12.5px]">
                    <DetailRow label="User" value={selected.user_id ?? "—"} />
                    <DetailRow label="Resource" value={selected.resource ?? "—"} />
                    <DetailRow label="Operation" value={selected.operation ?? "—"} />
                    <DetailRow label="Device" value={selected.device_id ?? "—"} mono />
                    <DetailRow label="Session" value={selected.session_id ?? "—"} mono />
                    <DetailRow label="Risk" value={selected.risk ?? "—"} />
                    {selected.reason && <DetailRow label="Reason" value={selected.reason} />}
                  </div>

                  <div className="mt-4 pt-4 border-t border-cq-outline-variant/15 space-y-2">
                    <div>
                      <div className="text-[10px] font-bold tracking-widest text-cq-on-surface-variant uppercase mb-1">Intent Hash</div>
                      <div className="text-[11.5px] font-mono text-cq-on-surface break-all">{selected.intent_hash || "—"}</div>
                    </div>
                    <div>
                      <div className="text-[10px] font-bold tracking-widest text-cq-on-surface-variant uppercase mb-1">Chain Hash</div>
                      <div className="text-[11.5px] font-mono text-cq-on-surface break-all">{selected.current_log_hash}</div>
                    </div>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="bg-cq-surface-container/50 border border-dashed border-cq-outline-variant/25 rounded-cq-xl p-cq-stack-lg text-center"
                >
                  <span className="material-symbols-outlined text-[26px] text-cq-outline mb-2 inline-block">search</span>
                  <p className="text-[12.5px] text-cq-on-surface-variant">Select an event to investigate its full record.</p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value, mono }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-cq-on-surface-variant shrink-0">{label}</span>
      <span className={`text-cq-on-surface font-medium text-right truncate ${mono ? "font-mono text-[11.5px]" : ""}`}>{value}</span>
    </div>
  );
}