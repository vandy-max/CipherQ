import { useEffect, useState } from "react";
import { Settings2, LayoutTemplate, Gauge, ShieldCheck, KeyRound } from "lucide-react";
import { Toggle } from "../components/ui/Field";
import PageHeader from "../components/ui/PageHeader";
import { loadPreferences, savePreferences } from "../services/preferences";

function Row({ icon: Icon, label, desc, control }) {
  return (
    <div className="flex items-center justify-between gap-4 py-3.5 border-b border-cq-outline-variant/15 last:border-b-0">
      <div className="flex items-start gap-3 min-w-0">
        <span className="inline-flex items-center justify-center w-9 h-9 rounded-cq-md bg-cq-surface-container-high text-cq-on-surface-variant shrink-0">
          <Icon size={16} />
        </span>
        <div className="min-w-0">
          <div className="text-[13.5px] font-semibold text-cq-on-surface">{label}</div>
          {desc && <div className="text-[12.5px] text-cq-on-surface-variant mt-0.5">{desc}</div>}
        </div>
      </div>
      <div className="shrink-0">{control}</div>
    </div>
  );
}

export default function SettingsPage({ user }) {
  const [prefs, setPrefs] = useState(loadPreferences);

  useEffect(() => {
    savePreferences(prefs);
    document.documentElement.classList.toggle("density-compact", prefs.density === "compact");
  }, [prefs]);

  return (
    <div>
      <PageHeader
        icon="settings"
        eyebrow="Account"
        title="Settings"
        description="Preferences for how the CipherQ console looks and behaves in this browser."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-1">
            <Settings2 size={17} className="text-cq-primary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Appearance</h2>
          </div>
          <p className="text-[13px] text-cq-on-surface-variant mb-2">Saved to this browser only.</p>

          <Row
            icon={LayoutTemplate}
            label="Collapse sidebar by default"
            desc="Start each session with a compact navigation rail."
            control={
              <Toggle
                checked={prefs.sidebarCollapsedDefault}
                onChange={(v) => setPrefs((p) => ({ ...p, sidebarCollapsedDefault: v }))}
              />
            }
          />
          <Row
            icon={Gauge}
            label="Compact density"
            desc="Tighter spacing across cards and tables."
            control={
              <Toggle
                checked={prefs.density === "compact"}
                onChange={(v) => setPrefs((p) => ({ ...p, density: v ? "compact" : "comfortable" }))}
              />
            }
          />
        </div>

        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-1">
            <ShieldCheck size={17} className="text-cq-secondary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Security</h2>
          </div>
          <p className="text-[13px] text-cq-on-surface-variant mb-2">Your current authenticated session.</p>

          <Row
            icon={KeyRound}
            label="Signed in as"
            desc={user?.role ? `Role: ${user.role}` : undefined}
            control={<span className="text-[13px] font-semibold text-cq-on-surface">{user?.username}</span>}
          />
          <Row
            icon={ShieldCheck}
            label="Session token"
            desc="Bearer JWT stored for this browser session"
            control={<span className="text-[12px] font-mono text-cq-on-surface-variant">active</span>}
          />
        </div>
      </div>
    </div>
  );
}
