import { useEffect, useState } from "react";
import { Camera, Cookie, MapPin, ShieldCheck, ShieldX } from "lucide-react";
import Button from "../ui/Button";
import GlassPanel from "../ui/GlassPanel";

// This is an application-level security permission gate. Browser camera
// and location permissions are requested through their real APIs; the
// cookie/session item is an explicit CipherQ consent because browsers do
// not expose a native "allow cookies" prompt to web applications.
const CONSENT_KEY = "ibqc_security_access_consent"; // "allow" | "deny"

export function getSecurityTelemetryConsent() {
  return sessionStorage.getItem(CONSENT_KEY);
}

export function hasAnsweredSecurityTelemetryConsent() {
  return getSecurityTelemetryConsent() !== null;
}

async function requestCameraPermission() {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("Camera access is not available in this browser.");
  }
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "user" },
    audio: false,
  });
  stream.getTracks().forEach((track) => track.stop());
}

async function requestLocationPermission() {
  if (!navigator.geolocation) {
    throw new Error("Location access is not available in this browser.");
  }
  await new Promise((resolve, reject) => {
    navigator.geolocation.getCurrentPosition(
      () => resolve(),
      (error) => reject(new Error(error.code === 1 ? "Location permission was denied." : "Location could not be verified.")),
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  });
}

/**
 * Mandatory security gate shown for each authenticated login/session.
 * The browser permissions are requested only after the user explicitly
 * chooses Allow. A denial blocks entry to the protected application.
 */
export default function SecurityTelemetryConsent({ onDecision }) {
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState({ camera: false, location: false, cookie: false });

  useEffect(() => {
    if (getSecurityTelemetryConsent() === "allow") {
      onDecision?.("allow");
    }
  }, [onDecision]);

  async function allow() {
    setWorking(true);
    setError("");
    try {
      // The explicit application consent is the first gate; the next two
      // operations trigger the browser's real permission prompts.
      setStatus((s) => ({ ...s, cookie: true }));
      await requestCameraPermission();
      setStatus((s) => ({ ...s, camera: true }));
      await requestLocationPermission();
      setStatus({ camera: true, location: true, cookie: true });
      sessionStorage.setItem(CONSENT_KEY, "allow");
      onDecision?.("allow");
    } catch (err) {
      sessionStorage.setItem(CONSENT_KEY, "deny");
      setError(err?.message || "A required security permission was denied.");
      onDecision?.("deny", err?.message || "A required security permission was denied.");
    } finally {
      setWorking(false);
    }
  }

  function deny() {
    sessionStorage.setItem(CONSENT_KEY, "deny");
    onDecision?.("deny", "Required security permissions were not granted.");
  }

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-black/70 backdrop-blur-md px-4">
      <GlassPanel className="max-w-lg w-full p-cq-stack-lg border border-cq-outline-variant/20">
        <div className="flex items-center gap-2.5 mb-2">
          <ShieldCheck size={21} className="text-cq-primary" />
          <h2 className="text-[17px] font-bold text-cq-on-surface">Secure Access Permissions</h2>
        </div>
        <p className="text-[13px] text-cq-on-surface-variant mb-5 leading-relaxed">
          CipherQ requires these permissions before protected access can begin. They are used to
          maintain device, location and continuous session security.
        </p>

        <div className="space-y-2.5 mb-5">
          <PermissionRow icon={Camera} title="Camera / Device Access" description="Required for continuous face verification." ok={status.camera} />
          <PermissionRow icon={MapPin} title="Location Access" description="Required to verify the authorized access location." ok={status.location} />
          <PermissionRow icon={Cookie} title="Cookie / Session Consent" description="Required to maintain the secure authenticated session." ok={status.cookie} />
        </div>

        {error && (
          <div className="mb-4 rounded-cq-md border border-cq-error/25 bg-cq-error-container/10 px-3 py-2.5 text-[12px] text-cq-error">
            <div className="flex items-center gap-2 font-semibold mb-1">
              <ShieldX size={14} /> Access blocked
            </div>
            {error}
          </div>
        )}

        <div className="flex gap-3">
          <Button variant="brand" className="flex-1" loading={working} onClick={allow}>
            Allow & Continue
          </Button>
          <Button variant="ghost" className="flex-1" disabled={working} onClick={deny}>
            Deny & Exit
          </Button>
        </div>
        <p className="mt-3 text-[10.5px] text-cq-on-surface-variant text-center">
          Denying any mandatory permission blocks access to the protected CipherQ dashboard.
        </p>
      </GlassPanel>
    </div>
  );
}

function PermissionRow({ icon: Icon, title, description, ok }) {
  return (
    <div className="flex items-center gap-3 rounded-cq-md bg-cq-surface-container-high px-3 py-2.5">
      <span className="w-8 h-8 rounded-cq-md bg-cq-surface-container flex items-center justify-center text-cq-primary">
        <Icon size={16} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-[12.5px] font-semibold text-cq-on-surface">{title}</div>
        <div className="text-[11px] text-cq-on-surface-variant">{description}</div>
      </div>
      <span className={`text-[10px] font-bold ${ok ? "text-cq-primary" : "text-cq-on-surface-variant"}`}>
        {ok ? "READY" : "REQUIRED"}
      </span>
    </div>
  );
}
