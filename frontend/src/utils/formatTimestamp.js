// ---------------------------------------------------------------------
// Centralized timestamp formatting.
//
// The backend audit/monitoring/authorization systems always store and
// return timestamps in UTC (see backend/audit/service.py,
// backend/monitoring/state.py). This is the ONLY place in the
// frontend that should convert a backend timestamp into a
// user-facing string — every page must import from here instead of
// calling `.toLocaleString()`/`.toLocaleDateString()` directly, so
// there is exactly one conversion rule for the whole app.
//
// Rules this file exists to guarantee:
//   - Never manually add/subtract a fixed offset (e.g. "+5:30" or
//     "-12h"). The browser's `Intl`/`Date` APIs already know the
//     user's local timezone; we just ask for it.
//   - Always parse the backend's ISO-8601 UTC string as UTC. If the
//     backend ever returns a string WITHOUT a trailing `Z`/offset
//     (some datetime serializers omit it even though the value is
//     UTC), `ensureUtcIso` fixes that up before handing it to `Date`,
//     because `new Date("2026-08-22T12:07:21")` is otherwise
//     (incorrectly) interpreted as LOCAL time by the browser — this is
//     the exact class of bug that produces a "12 hour off" or
//     "5:30 off" display error.
// ---------------------------------------------------------------------

/**
 * Normalizes a backend datetime value so the browser always parses it
 * as UTC, regardless of whether the serializer included an explicit
 * `Z`/`+00:00` suffix.
 */
function ensureUtcIso(value) {
  if (value instanceof Date) return value;
  if (typeof value === "number") return new Date(value);
  if (typeof value !== "string") return null;

  let s = value.trim();
  if (!s) return null;

  // Already has an explicit UTC/offset marker -> trust it as-is.
  const hasExplicitOffset = /Z$|[+-]\d{2}:?\d{2}$/.test(s);
  if (!hasExplicitOffset) {
    // Bare "YYYY-MM-DDTHH:MM:SS[.ffffff]" (or with a space instead of
    // "T") from a naive backend datetime that is, by contract, always
    // UTC (see backend/database/models.py / audit/service.py) — pin
    // it explicitly rather than letting `Date` assume local time.
    s = s.replace(" ", "T");
    s += "Z";
  }
  return new Date(s);
}

/**
 * The one shared format used everywhere in the app for an exact
 * event timestamp: `DD/MM/YYYY, hh:mm:ss AM/PM`, e.g.
 *   22/08/2026, 05:37:21 PM
 * Rendered in the browser's local timezone automatically (IST,
 * UTC+05:30, for a user in India — computed by the browser, never
 * hard-coded here).
 */
export function formatTimestamp(value, { timeZone } = {}) {
  const date = ensureUtcIso(value);
  if (!date || Number.isNaN(date.getTime())) return "—";

  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone, // undefined -> browser's own local timezone
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).format(date);

  const time = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(date);

  return `${parts}, ${time}`;
}

/** Date only: `22/08/2026`. */
export function formatDate(value, { timeZone } = {}) {
  const date = ensureUtcIso(value);
  if (!date || Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    timeZone,
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).format(date);
}

/** Time only: `05:37:21 PM`. */
export function formatTime(value, { timeZone } = {}) {
  const date = ensureUtcIso(value);
  if (!date || Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-US", {
    timeZone,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(date);
}

/**
 * Milliseconds since epoch for a backend timestamp, safe to use for
 * sorting (descending: newest first). Returns 0 for anything
 * unparsable so malformed rows sort last rather than throwing.
 */
export function timestampMillis(value) {
  const date = ensureUtcIso(value);
  if (!date || Number.isNaN(date.getTime())) return 0;
  return date.getTime();
}

/**
 * Stable "newest first" comparator for arrays of objects that carry a
 * timestamp field. Falls back to a secondary key (e.g. an
 * id/index/intent_id) when two timestamps tie, so ordering never
 * depends on whatever order the API/DB happened to return.
 */
export function byTimestampDesc(timestampKey = "timestamp", tieBreakKey = null) {
  return (a, b) => {
    const diff = timestampMillis(b?.[timestampKey]) - timestampMillis(a?.[timestampKey]);
    if (diff !== 0) return diff;
    if (tieBreakKey) {
      const av = a?.[tieBreakKey];
      const bv = b?.[tieBreakKey];
      if (av != null && bv != null) return bv > av ? 1 : bv < av ? -1 : 0;
    }
    return 0;
  };
}

/** The actual current browser/system time — for "current time" style
 * displays, never a fabricated/static value. */
export function formatNow(options) {
  return formatTimestamp(new Date(), options);
}
