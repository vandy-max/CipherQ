import { useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { MonitoringProvider } from "./context/MonitoringContext";
import { QiraProvider } from "./context/QiraContext";
import AppShell from "./components/layout/AppShell";
import SecurityTelemetryConsent from "./components/security/SecurityTelemetryConsent";
import QiraWidget from "./components/qira/QiraWidget";

import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import Dashboard from "./pages/Dashboard";
import CreateIntentPage from "./pages/CreateIntentPage";
import IntentHistoryPage from "./pages/IntentHistoryPage";
import BB84SimulationPage from "./pages/BB84SimulationPage";
import EncryptionPage from "./pages/EncryptionPage";
import DecryptionPage from "./pages/DecryptionPage";
import AuditLogsPage from "./pages/AuditLogsPage";
import PolicyManagementPage from "./pages/PolicyManagementPage";
import VisualizationPage from "./pages/VisualizationPage";
import ProfilePage from "./pages/ProfilePage";
import SettingsPage from "./pages/SettingsPage";
import FaceAuthTestPage from "./pages/FaceAuthTestPage";
import AdminDashboard from "./pages/AdminDashboard";

const PUBLIC_PAGES = ["landing", "login", "register"];
const AUTH_TOKEN_KEY = "ibqc_token";

// `useAuth`'s `token` (and therefore `isAuthenticated`) is React state: it
// is only guaranteed to be up to date on the render AFTER `saveAuth()` (or
// any other localStorage write) has been applied. `navigate()` and the
// shell-vs-landing decision below can run in the SAME synchronous click
// handler that just established auth (e.g. "Allow & Continue" right after
// face verification), before that state has had a chance to flush to a
// render. Reading the persisted token directly gives protected-route
// navigation an immediate, correct answer during that transition, without
// ever weakening authentication: this flag only ever *widens* what counts
// as "authenticated enough to route past the Landing Page" — it never
// grants access to data. Every protected API call is still authorized
// server-side via `get_current_user`, independent of anything here.
function hasPersistedAuthToken() {
  try {
    return !!localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return false;
  }
}

export default function App() {
  const { token, user, deviceId, sessionId, saveAuth, logout, isAuthenticated } = useAuth();
  const [page, setPage] = useState("landing");
  // Simple cross-page scratch state so e.g. Encrypt can hand off a
  // record_id to Decrypt, or Create Intent can hand off a CID.
  const [shared, setShared] = useState({});
  const [accessReady, setAccessReady] = useState(
    () => sessionStorage.getItem("ibqc_security_access_consent") === "allow"
  );

  // Combines the React auth state with the persisted-token fallback above.
  // Recomputed on every render, so as soon as `token` itself catches up
  // this collapses back to being exactly `isAuthenticated`.
  const authedForRouting = isAuthenticated || hasPersistedAuthToken();

  const navigate = (p, extra) => {
    const authedNow = isAuthenticated || hasPersistedAuthToken();
    if (!authedNow && !PUBLIC_PAGES.includes(p)) {
      setPage("landing");
      return;
    }
    // LoginPage completes face verification and then grants the
    // application-level access consent. Sync the shell immediately so
    // the consent gate is not shown a second time after navigation.
    if (sessionStorage.getItem("ibqc_security_access_consent") === "allow") {
      setAccessReady(true);
    }
    if (extra) setShared((prev) => ({ ...prev, ...extra }));
    setPage(p);
  };

  const showShell = authedForRouting && !!user && !PUBLIC_PAGES.includes(page);

  if (!showShell) {
    // A logged-in navigation target (page is not landing/login/register)
    // while `user` hasn't caught up to the persisted token yet is a brief
    // in-flight transition, not an unauthenticated visitor — show a
    // lightweight loading state instead of bouncing back to marketing
    // Landing Page copy (which was the reported "must click Go to
    // Dashboard again" bug). This resolves itself on the very next render
    // once `useAuth`'s state settles; it is never a substitute for real
    // authorization, which the backend enforces on every request.
    if (authedForRouting && !PUBLIC_PAGES.includes(page)) {
      return (
        <div className="app-root min-h-screen flex items-center justify-center cq-matte-obsidian bg-cq-background text-cq-on-surface-variant text-[13.5px]">
          Loading your dashboard…
        </div>
      );
    }

    return (
      <div className="app-root">
        {page === "landing" && <LandingPage navigate={navigate} isAuthenticated={authedForRouting} />}
        {(page === "login" || page === "register") && (
          <LoginPage
            mode={page}
            saveAuth={saveAuth}
            logout={logout}
            navigate={navigate}
            deviceId={deviceId}
            sessionId={sessionId}
          />
        )}
      </div>
    );
  }

  if (!accessReady) {
    return (
      <SecurityTelemetryConsent
        onDecision={(decision) => {
          if (decision === "allow") {
            setAccessReady(true);
          } else {
            logout();
            setAccessReady(false);
            setPage("login");
          }
        }}
      />
    );
  }

  return (
    <MonitoringProvider user={user} deviceId={deviceId} sessionId={sessionId}>
      <QiraProvider>
        <AppShell page={page} navigate={navigate} user={user} logout={logout}>
          {page === "dashboard" && <Dashboard navigate={navigate} user={user} />}
          {page === "create-intent" && <CreateIntentPage navigate={navigate} shared={shared} user={user} />}
          {page === "intent-history" && <IntentHistoryPage navigate={navigate} shared={shared} user={user} />}
          {page === "bb84" && <BB84SimulationPage navigate={navigate} shared={shared} />}
          {page === "encrypt" && <EncryptionPage navigate={navigate} shared={shared} user={user} />}
          {page === "decrypt" && <DecryptionPage navigate={navigate} shared={shared} user={user} />}
          {page === "audit" && <AuditLogsPage navigate={navigate} />}
          {page === "policies" && <PolicyManagementPage navigate={navigate} />}
          {page === "visualize" && <VisualizationPage navigate={navigate} />}
          {page === "settings" && <SettingsPage navigate={navigate} user={user} />}
          {page === "profile" && <ProfilePage navigate={navigate} user={user} />}
          {page === "face-test" && <FaceAuthTestPage navigate={navigate} />}
          {page === "admin" && <AdminDashboard user={user} />}
        </AppShell>
        {/* Qira floats above every authenticated page — it reads the
            SAME shared QiraContext decision every other consumer
            (topbar badge, dashboard card) reads, so they can never
            contradict each other (Part 4). */}
        <QiraWidget user={user} />
      </QiraProvider>
    </MonitoringProvider>
  );
}
