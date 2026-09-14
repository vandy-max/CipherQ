import { useEffect, useRef, useState } from "react";
import { Menu, LogOut, ChevronDown } from "lucide-react";
import MonitoringBadge from "../monitoring/MonitoringBadge";

const TITLES = {
  dashboard: "Overview",
  "create-intent": "Create Intent",
  "intent-history": "Intent History",
  bb84: "Quantum Lab",
  encrypt: "Encryption",
  decrypt: "Decryption",
  audit: "Audit",
  policies: "Policy Engine",
  visualize: "Risk Intelligence",
  settings: "Settings",
  profile: "Profile",
  "face-test": "Identity",
};

// Mirrors the Stitch header markup shared across every screen: a global
// search field on the left (bg-surface-container-lowest, pill-shaped),
// and a right-hand cluster of a version chip, a pulsing "session secure"
// chip, and utility icons. The account menu (avatar + sign out) is an
// IBQC-only addition since Stitch's static mockups don't model auth.
export default function Topbar({ page, user, logout, setMobileOpen, search, setSearch }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onDoc(e) {
      if (ref.current && !ref.current.contains(e.target)) setMenuOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  return (
    <header className="sticky top-0 z-40 h-16 bg-cq-surface/80 backdrop-blur-md flex items-center gap-cq-stack-md px-cq-margin-mobile sm:px-cq-margin-desktop border-b border-cq-outline-variant/10">
      <button
        className="lg:hidden inline-flex items-center justify-center w-9 h-9 rounded-cq-sm text-cq-on-surface-variant hover:bg-cq-surface-container-highest shrink-0"
        onClick={() => setMobileOpen(true)}
      >
        <Menu size={19} />
      </button>

      <div className="flex items-center flex-1 min-w-0 gap-cq-stack-md">
        <div className="hidden sm:flex items-center bg-cq-surface-container-lowest rounded-full px-cq-stack-md py-2 w-full max-w-md border border-cq-outline-variant/30">
          <span className="material-symbols-outlined text-cq-outline text-[18px]">search</span>
          <input
            value={search ?? ""}
            onChange={(e) => setSearch?.(e.target.value)}
            className="bg-transparent border-none outline-none text-cq-body-md px-cq-stack-sm w-full text-cq-on-surface placeholder:text-cq-outline/60"
            placeholder="Global Telemetry Search…"
            type="text"
          />
        </div>
        <h1 className="sm:hidden text-[15px] font-bold text-cq-on-surface truncate">{TITLES[page] || "CipherQ"}</h1>
      </div>

      <div className="flex items-center gap-cq-stack-lg shrink-0">
        <div className="hidden md:flex items-center gap-1 px-cq-stack-md py-1.5 rounded-full bg-cq-surface-container-low border border-cq-outline-variant/20 text-cq-label-md text-cq-on-surface-variant font-mono uppercase">
          v2.4.0
        </div>
        <div className="hidden sm:flex items-center gap-1.5 px-cq-stack-md py-1.5 rounded-full bg-cq-primary/10 border border-cq-primary/20">
          <div className="w-2 h-2 rounded-full bg-cq-secondary shadow-cq-dot-secondary animate-pulse" />
          <span className="font-label-md text-cq-label-md text-cq-primary">SESSION SECURE</span>
        </div>
        <MonitoringBadge />
        <div className="hidden sm:flex items-center gap-cq-stack-md">
          <span className="material-symbols-outlined text-cq-on-surface-variant hover:text-cq-primary cursor-pointer transition-colors text-[22px]">help</span>
          <span className="material-symbols-outlined text-cq-on-surface-variant hover:text-cq-primary cursor-pointer transition-colors text-[22px]">notifications</span>
        </div>

        <div className="relative" ref={ref}>
          <button
            onClick={() => setMenuOpen((v) => !v)}
            className="flex items-center gap-2 rounded-full pl-1.5 pr-2.5 py-1.5 hover:bg-cq-surface-container-highest transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-cq-primary-container text-cq-on-primary-container text-[12.5px] font-bold flex items-center justify-center">
              {user?.username?.[0]?.toUpperCase() || "U"}
            </div>
            <span className="hidden lg:block text-[13px] font-semibold text-cq-on-surface max-w-[110px] truncate">
              {user?.username}
            </span>
            <ChevronDown size={14} className="text-cq-on-surface-variant" />
          </button>

          {menuOpen && (
            <div className="absolute right-0 mt-2 w-52 rounded-cq-md border border-cq-outline-variant/20 bg-cq-surface-container-low/95 backdrop-blur-xl shadow-cq-popover py-1.5 overflow-hidden">
              <div className="px-3.5 py-2.5 border-b border-cq-outline-variant/20">
                <div className="text-[13px] font-semibold text-cq-on-surface truncate">{user?.username}</div>
                <div className="text-[11.5px] text-cq-on-surface-variant capitalize">{user?.role || "member"}</div>
              </div>
              <button
                onClick={logout}
                className="w-full flex items-center gap-2 px-3.5 py-2.5 text-[13px] font-medium text-cq-error hover:bg-cq-error-container/10 transition-colors"
              >
                <LogOut size={15} />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
