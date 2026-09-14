// Client-side UI preferences, persisted locally. Nothing here touches
// the backend — these are presentation-only settings (sidebar default
// state, density) that this browser remembers between visits.
const KEY = "ibqc:preferences";

const DEFAULTS = {
  sidebarCollapsedDefault: false,
  density: "comfortable", // "comfortable" | "compact"
};

export function loadPreferences() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULTS };
  }
}

export function savePreferences(prefs) {
  try {
    localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    // ignore storage failures (private browsing, quota, etc.)
  }
}
