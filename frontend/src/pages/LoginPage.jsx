import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldHalf } from "lucide-react";
import { login, register, faceStatus } from "../services/api";
import { Field, TextField, SelectField } from "../components/ui/Field";
import Button from "../components/ui/Button";
import Alert from "../components/ui/Alert";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import SecurityTelemetryConsent from "../components/security/SecurityTelemetryConsent";
import QuantumField from "../components/quantum/QuantumField";

// Handed from face verification to the (freshly mounted, post-navigate)
// MonitoringProvider so it can start the continuous-monitoring session
// with the confidence from THIS login's verification — see
// MonitoringContext's bootstrap effect.
const PENDING_CONFIDENCE_KEY = "ibqc_pending_monitoring_face_confidence";

export default function LoginPage({ mode, saveAuth, logout, navigate, deviceId }) {
  const isRegister = mode === "register";
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Only the two ordinary user tiers are ever offered here — there is no
  // "admin" option on this form, on purpose. Admin accounts are fixed,
  // confidential, and provisioned out-of-band (seed script / an existing
  // admin promoting someone from the Admin Dashboard), never via signup.
  const [role, setRole] = useState("USER_LEVEL_1");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  // After a successful registration we drop straight into face
  // enrollment before the account can reach the dashboard.
  const [awaitingEnrollment, setAwaitingEnrollment] = useState(false);
  const [awaitingPermissions, setAwaitingPermissions] = useState(false);
  // LOGIN -> FACE VERIFIED -> MONITORING SESSION STARTED: a login for
  // an already-enrolled user must pass a face check before the
  // dashboard (and its continuous monitoring session) opens.
  const [awaitingFaceVerification, setAwaitingFaceVerification] = useState(false);

  function continueAfterPermissions() {
    setError("");
    setAwaitingPermissions(false);
    navigate("dashboard");
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    // Every explicit sign-in/registration attempt must complete the
    // face -> access-permission sequence for that login.
    sessionStorage.removeItem("ibqc_security_access_consent");
    sessionStorage.removeItem("ibqc_face_verified_this_login");
    try {
      const result = isRegister
        ? await register(username, email, password, role)
        : await login(username, password);

      await saveAuth(result);

      // IMPORTANT LOGIN ORDER:
      // 1) credentials/account authentication
      // 2) face enrollment/verification
      // 3) security access permissions
      // 4) protected dashboard + continuous monitoring
      let enrolled = false;
      try {
        const status = await faceStatus();
        enrolled = !!status?.enrolled;
      } catch {
        enrolled = false;
      }

      if (enrolled) {
        setAwaitingFaceVerification(true);
      } else {
        setAwaitingEnrollment(true);
      }
    } catch (err) {
      setError(err.detail?.toString?.() || err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  if (awaitingPermissions) {
    return (
      <>
        <SecurityTelemetryConsent
          onDecision={(decision) => {
            if (decision === "allow") {
              continueAfterPermissions();
            } else {
              logout?.();
              setAwaitingPermissions(false);
              navigate("login");
            }
          }}
        />
        <div className="min-h-screen cq-matte-obsidian bg-cq-background" />
      </>
    );
  }

  if (awaitingEnrollment) {
    return (
      <div className="min-h-screen flex items-center justify-center cq-matte-obsidian bg-cq-background px-4 py-12">
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="w-full max-w-[460px]"
        >
          <div className="text-center mb-5">
            <h2 className="text-[20px] font-bold text-cq-on-surface">Secure your account</h2>
            <p className="mt-1.5 text-[13.5px] text-cq-on-surface-variant">
              Account created. Enroll your face now — this is required before Encrypt or Decrypt
              can be used.
            </p>
          </div>
          <FaceAuthPanel
            mode="enroll"
            onSuccess={() => {
              // Enrollment establishes the biometric reference. A separate
              // live verification immediately follows so registration and
              // login share the same security sequence.
              setAwaitingEnrollment(false);
              setAwaitingFaceVerification(true);
            }}
          />
          <button
            className="mt-4 w-full text-center text-[12.5px] font-semibold text-cq-on-surface-variant hover:text-cq-on-surface"
            onClick={() => { logout?.(); navigate("login"); }}
          >
            Having camera trouble? Return to sign in.
          </button>
        </motion.div>
      </div>
    );
  }

  if (awaitingFaceVerification) {
    return (
      <div className="min-h-screen flex items-center justify-center cq-matte-obsidian bg-cq-background px-4 py-12">
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="w-full max-w-[460px]"
        >
          <div className="text-center mb-5">
            <h2 className="text-[20px] font-bold text-cq-on-surface">Verify it's you</h2>
            <p className="mt-1.5 text-[13.5px] text-cq-on-surface-variant">
              Authentication alone doesn't grant lasting access — verify your face to start a
              continuously-monitored session.
            </p>
          </div>
          <FaceAuthPanel
            mode="verify"
            onSuccess={({ confidence }) => {
              sessionStorage.setItem(PENDING_CONFIDENCE_KEY, String(confidence));
              sessionStorage.setItem("ibqc_face_verified_this_login", "1");
              setAwaitingFaceVerification(false);
              setAwaitingPermissions(true);
            }}
          />
        </motion.div>
      </div>
    );
  }


  return (
    <div className="min-h-screen flex items-center justify-center cq-matte-obsidian bg-cq-background px-4 py-12">
      <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
        <QuantumField density="low" tone="mixed" className="opacity-40" />
        <div className="absolute -top-24 left-1/3 w-[420px] h-[420px] rounded-full bg-cq-primary-container/15 blur-[110px]" />
        <div className="absolute bottom-0 right-1/4 w-[380px] h-[380px] rounded-full bg-cq-tertiary-container/15 blur-[110px]" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="cq-glass-chrome w-full max-w-[420px] rounded-cq-xl border p-8 sm:p-9"
      >
        <div className="flex items-center justify-center w-11 h-11 rounded-cq-md bg-cq-primary-container shadow-cq-glow-primary mb-6 mx-auto">
          <ShieldHalf size={20} className="text-cq-on-primary-container" strokeWidth={2.25} />
        </div>

        <div className="text-center mb-7">
          <h2 className="text-[22px] font-bold text-cq-on-surface">
            {isRegister ? "Create your account" : "Welcome back"}
          </h2>
          <p className="mt-1.5 text-[13.5px] text-cq-on-surface-variant">
            {isRegister ? "Set up secure access to the CipherQ platform" : "Sign in to continue to CipherQ"}
          </p>
        </div>

        <Alert type="error">{error}</Alert>

        <form onSubmit={handleSubmit}>
          <Field label="Username">
            <TextField value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
          </Field>
          {isRegister && (
            <Field label="Email">
              <TextField type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </Field>
          )}
          <Field label="Password">
            <TextField
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={isRegister ? 8 : undefined}
            />
          </Field>
          {isRegister && (
            <Field label="Access level" hint="you can choose your starting tier">
              <SelectField value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="USER_LEVEL_1">User — Level 1</option>
                <option value="USER_LEVEL_2">User — Level 2</option>
              </SelectField>
            </Field>
          )}
          <Button type="submit" variant="brand" full loading={loading} className="mt-1">
            {isRegister ? "Create account" : "Sign in"}
          </Button>
        </form>

        <div className="mt-6 text-center text-[13.5px] text-cq-on-surface-variant">
          {isRegister ? (
            <>
              Already have an account?{" "}
              <button className="font-semibold text-cq-primary hover:underline" onClick={() => navigate("login")}>
                Sign in
              </button>
            </>
          ) : (
            <>
              Need an account?{" "}
              <button className="font-semibold text-cq-primary hover:underline" onClick={() => navigate("register")}>
                Register
              </button>
            </>
          )}
        </div>
      </motion.div>
    </div>
  );
}
