import { useMemo, useState } from "react";
import { Search, ArrowUp, ArrowDown, ChevronLeft, ChevronRight, ArrowUpDown } from "lucide-react";

const PAGE_SIZE = 8;

// This table's only consumer is AuditLogsPage (dark/CipherQ page), so
// it's styled directly with cq-* tokens rather than kept light + reused
// like Field/Button/Alert — no other page depends on its current look.
function TableEmptyState({ title, desc }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-14 px-6">
      <div className="text-[14.5px] font-semibold text-cq-on-surface">{title}</div>
      {desc && <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">{desc}</div>}
    </div>
  );
}

/**
 * columns: [{ key, label, sortable, render(row), mono }]
 * rows: array of plain objects
 * All filtering/sorting/pagination happens client-side over data the
 * caller already fetched from the backend — no data is invented here.
 */
export default function DataTable({ columns, rows, searchKeys, searchPlaceholder = "Search…", emptyTitle = "No results", emptyDesc, toolbar, onRowClick, selectedRowId }) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState(null);
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    if (!query.trim()) return rows;
    const q = query.toLowerCase();
    const keys = searchKeys || columns.map((c) => c.key);
    return rows.filter((row) =>
      keys.some((k) => String(row[k] ?? "").toLowerCase().includes(q))
    );
  }, [rows, query, searchKeys, columns]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    const copy = [...filtered];
    copy.sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av == null) return 1;
      if (bv == null) return -1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      return 0;
    });
    return copy;
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const clampedPage = Math.min(page, totalPages - 1);
  const pageRows = sorted.slice(clampedPage * PAGE_SIZE, clampedPage * PAGE_SIZE + PAGE_SIZE);

  function toggleSort(col) {
    if (!col.sortable) return;
    if (sortKey === col.key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(col.key);
      setSortDir("desc");
    }
    setPage(0);
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2.5 mb-4">
        <div className="relative flex-1 min-w-[180px]">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-cq-outline" />
          <input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
            placeholder={searchPlaceholder}
            className="w-full rounded-cq-md bg-cq-surface-container-high pl-9 pr-3 py-2 text-[13.5px] text-cq-on-surface placeholder:text-cq-outline focus:bg-cq-surface-container-highest transition-colors outline-none"
          />
        </div>
        {toolbar}
      </div>

      {rows.length === 0 ? (
        <TableEmptyState title={emptyTitle} desc={emptyDesc} />
      ) : sorted.length === 0 ? (
        <TableEmptyState title="No matches" desc="Try a different search term." />
      ) : (
        <>
          <div className="overflow-x-auto -mx-2 sm:mx-0">
            <table className="w-full text-left border-collapse min-w-[560px]">
              <thead className="sticky top-0 bg-cq-surface-container z-[1]">
                <tr className="border-b border-cq-outline-variant/25">
                  {columns.map((col) => (
                    <th
                      key={col.key}
                      onClick={() => toggleSort(col)}
                      className={
                        "py-2.5 px-3 text-[11.5px] font-bold uppercase tracking-wide text-cq-on-surface-variant select-none " +
                        (col.sortable ? "cursor-pointer hover:text-cq-on-surface" : "")
                      }
                    >
                      <span className="inline-flex items-center gap-1">
                        {col.label}
                        {col.sortable &&
                          (sortKey === col.key ? (
                            sortDir === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />
                          ) : (
                            <ArrowUpDown size={11} className="opacity-40" />
                          ))}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pageRows.map((row, i) => (
                  <tr
                    key={row.id ?? i}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={
                      "transition-colors " +
                      (onRowClick ? "cursor-pointer " : "") +
                      (onRowClick && selectedRowId != null && row.id === selectedRowId
                        ? "bg-cq-primary-container/10 hover:bg-cq-primary-container/15"
                        : "hover:bg-cq-surface-container-high")
                    }
                  >
                    {columns.map((col) => (
                      <td
                        key={col.key}
                        className={
                          "py-3 px-3 text-[13.5px] text-cq-on-surface-variant border-b border-cq-outline-variant/15 " +
                          (col.mono ? "font-mono text-[12.5px]" : "")
                        }
                      >
                        {col.render ? col.render(row) : String(row[col.key] ?? "—")}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between mt-4 pt-3 border-t border-cq-outline-variant/15">
            <span className="text-[12.5px] text-cq-on-surface-variant">
              {sorted.length} result{sorted.length !== 1 ? "s" : ""} · page {clampedPage + 1} of {totalPages}
            </span>
            <div className="flex items-center gap-1.5">
              <button
                disabled={clampedPage === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="inline-flex items-center justify-center w-8 h-8 rounded-cq-sm border border-cq-outline-variant/30 text-cq-on-surface-variant disabled:opacity-35 hover:bg-cq-surface-container-high transition-colors"
              >
                <ChevronLeft size={15} />
              </button>
              <button
                disabled={clampedPage >= totalPages - 1}
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                className="inline-flex items-center justify-center w-8 h-8 rounded-cq-sm border border-cq-outline-variant/30 text-cq-on-surface-variant disabled:opacity-35 hover:bg-cq-surface-container-high transition-colors"
              >
                <ChevronRight size={15} />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
