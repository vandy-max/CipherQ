import { useState } from "react";
import clsx from "clsx";
import { motion, AnimatePresence } from "framer-motion";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import WorkflowBreadcrumb from "../ui/WorkflowBreadcrumb";
import { loadPreferences } from "../../services/preferences";
import { useMonitoringContext } from "../../context/MonitoringContext";

// Maps app page ids -> the workflow step they belong to, for the
// secondary breadcrumb bar under the header (Stitch: fixed, h-12,
// bg-surface-container-low/50, backdrop-blur-sm, sitting under a h-16
// header — see dashboard_1/code.html).
const WORKFLOW_STEP_BY_PAGE = {
  "create-intent": "intent",
  "intent-history": "intent",
  bb84: "qkd",
  encrypt: "encryption",
  decrypt: "decryption",
  audit: "audit",
};

export default function AppShell({ page, navigate, user, logout, children }) {
  const { snapshot, monitoringSessionId, reauthRequired } = useMonitoringContext();
  const monitoringBlocked = reauthRequired || !monitoringSessionId || ["reauth_required", "revoked"].includes(snapshot?.status);
  const [collapsed, setCollapsed] = useState(() => loadPreferences().sidebarCollapsedDefault);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [search, setSearch] = useState("");

  return (
    <div className="cq-app cq-matte-obsidian min-h-screen">
      <Sidebar
        currentPage={page}
        navigate={navigate}
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
        user={user}
        monitoringBlocked={monitoringBlocked}
      />
      <div
        className={clsx(
          "lg:transition-[margin] lg:duration-200 lg:ease-in-out",
          collapsed ? "lg:ml-[76px]" : "lg:ml-[280px]"
        )}
      >
        <Topbar page={page} user={user} logout={logout} setMobileOpen={setMobileOpen} search={search} setSearch={setSearch} />
        <div className="sticky top-16 z-30 h-12 bg-cq-surface-container-low/50 backdrop-blur-sm border-b border-cq-outline-variant/5 flex items-center px-cq-margin-mobile sm:px-cq-margin-desktop">
          <WorkflowBreadcrumb current={WORKFLOW_STEP_BY_PAGE[page] || null} />
        </div>
        <main className="relative min-h-screen bg-transparent p-cq-margin-mobile sm:p-cq-margin-desktop">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.22, ease: "easeOut" }}
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
