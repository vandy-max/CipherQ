import { useCallback, useEffect, useRef, useState } from "react";
import Webcam from "react-webcam";
import { motion, AnimatePresence } from "framer-motion";
import {
  ScanFace,
  CheckCircle2,
  XCircle,
  RotateCcw,
  X,
  Camera,
  ShieldCheck,
} from "lucide-react";
import Button from "../ui/Button";
import QiraAvatar from "../qira/QiraAvatar";
import { extractDescriptor, detectFaceLite, assessQuality } from "../../services/faceIdentity";
import { enrollFace, verifyFace } from "../../services/api";

const ENROLL_POSES = [
  { key: "straight", label: "Look straight at the camera" },
  { key: "left", label: "Turn slightly left" },
  { key: "right", label: "Turn slightly right" },
  { key: "up", label: "Tilt your chin up slightly" },
  { key: "down", label: "Tilt your chin down slightly" },
];

const VERIFY_FRAME_TARGET = 5;
const VERIFY_WINDOW_MS = 2600;

function averageDescriptors(descriptors) {
  const len = descriptors[0].length;
  const out = new Array(len).fill(0);
  for (const d of descriptors) {
    for (let i = 0; i < len; i++) out[i] += d[i];
  }
  return out.map((v) => v / descriptors.length);
}

/**
 * mode: "enroll" | "verify"
 * onSuccess(payload):
 *   enroll -> called after the descriptor has been enrolled server-side
 *   verify -> called with { descriptor, confidence } — the caller still
 *             sends `descriptor` along with its own protected request
 *             (encrypt/decrypt), which re-verifies server-side. This
 *             panel's own /face/verify call is for live UX feedback only.
 * onCancel(): user backed out.
 */
export default function FaceAuthPanel({ mode = "verify", title, subtitle, onSuccess, onCancel }) {
  const webcamRef = useRef(null);
  const rafRef = useRef(null);
  const capturedRef = useRef([]);
  const startedAtRef = useRef(0);
  const poseIndexRef = useRef(0);

  const [cameraReady, setCameraReady] = useState(false);
  const [cameraError, setCameraError] = useState("");
  const [quality, setQuality] = useState(null);
  const [box, setBox] = useState(null);
  const [phase, setPhase] = useState("idle"); // idle | capturing | processing | success | fail
  const [progress, setProgress] = useState(0); // 0-1
  const [poseIndex, setPoseIndex] = useState(0);
  const [confidence, setConfidence] = useState(null);
  const [error, setError] = useState("");

  const stopLoop = useCallback(() => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
    rafRef.current = null;
  }, []);

  // Continuous lightweight detection loop -> drives the bounding box +
  // quality indicator. Runs whenever the panel is mounted and idle/capturing.
  useEffect(() => {
    let cancelled = false;
    let lastRun = 0;

    async function loop(ts) {
      if (cancelled) return;
      const video = webcamRef.current?.video;
      if (video && video.readyState === 4 && ts - lastRun > 180) {
        lastRun = ts;
        try {
          const detection = await detectFaceLite(video);
          if (!cancelled) {
            const q = assessQuality(detection, video, "enrollment");
            setQuality(q);
            setBox(detection ? detection.detection.box : null);
          }
        } catch {
          /* transient — next tick retries */
        }
      }
      rafRef.current = requestAnimationFrame(loop);
    }

    if (phase === "idle" || phase === "capturing") {
      rafRef.current = requestAnimationFrame(loop);
    }
    return () => {
      cancelled = true;
      stopLoop();
    };
  }, [phase, stopLoop]);

  async function handleStart() {
    setError("");
    capturedRef.current = [];
    poseIndexRef.current = 0;
    setPoseIndex(0);
    setProgress(0);
    setPhase("capturing");
    startedAtRef.current = Date.now();
    runCapture();
  }

  async function captureOneFrame() {
    const video = webcamRef.current?.video;
    if (!video) return null;
    const detection = await detectFaceLite(video);
    const q = assessQuality(detection, video, "enrollment");
    if (!q.ok) return null;
    const descriptor = await extractDescriptor(video);
    return descriptor;
  }

  async function runCapture() {
    if (mode === "enroll") {
      await runEnrollCapture();
    } else {
      await runVerifyCapture();
    }
  }

  async function runEnrollCapture() {
    for (let i = 0; i < ENROLL_POSES.length; i++) {
      poseIndexRef.current = i;
      setPoseIndex(i);
      const descriptor = await waitForGoodFrame(4000);
      if (!descriptor) {
        setPhase("fail");
        setError("Couldn't get a clear frame in time — try again in better lighting.");
        return;
      }
      capturedRef.current.push(descriptor);
      setProgress((i + 1) / ENROLL_POSES.length);
    }
    setPhase("processing");
    try {
      const avg = averageDescriptors(capturedRef.current);
      await enrollFace(avg);
      setPhase("success");
      onSuccess?.({ descriptor: avg });
    } catch (err) {
      setPhase("fail");
      setError(err.detail?.toString?.() || err.message || "Enrollment failed");
    }
  }

  async function runVerifyCapture() {
    const deadline = Date.now() + VERIFY_WINDOW_MS;
    const collected = [];
    let bestScore = -1;
    let bestDescriptor = null;

    while (Date.now() < deadline && collected.length < VERIFY_FRAME_TARGET) {
      const video = webcamRef.current?.video;
      if (video) {
        const detection = await detectFaceLite(video);
        const q = assessQuality(detection, video, "enrollment");
        if (q.ok && detection) {
          const descriptor = await extractDescriptor(video);
          if (descriptor) {
            collected.push(descriptor);
            if (detection.detection.score > bestScore) {
              bestScore = detection.detection.score;
              bestDescriptor = descriptor;
            }
          }
        }
      }
      setProgress(Math.min(1, collected.length / VERIFY_FRAME_TARGET));
      // small yield between samples
      await new Promise((r) => setTimeout(r, 220));
    }

    if (!bestDescriptor) {
      setPhase("fail");
      setError("No clear face detected in time — try again.");
      return;
    }

    setPhase("processing");
    try {
      const result = await verifyFace(bestDescriptor);
      setConfidence(result.confidence);
      if (!result.verified) {
        setPhase("fail");
        setError("Face did not match your enrolled identity.");
        return;
      }
      setPhase("success");
      onSuccess?.({ descriptor: bestDescriptor, confidence: result.confidence });
    } catch (err) {
      setPhase("fail");
      setError(err.detail?.toString?.() || err.message || "Verification failed");
    }
  }

  async function waitForGoodFrame(timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const descriptor = await captureOneFrame();
      if (descriptor) return descriptor;
      await new Promise((r) => setTimeout(r, 200));
    }
    return null;
  }

  function handleRetry() {
    setError("");
    setConfidence(null);
    handleStart();
  }

  const statusLabel = !cameraReady
    ? "Requesting camera access…"
    : phase === "idle"
    ? "Position your face in the guide"
    : phase === "capturing"
    ? mode === "enroll"
      ? ENROLL_POSES[poseIndex]?.label
      : "Hold still — verifying…"
    : phase === "processing"
    ? "Checking result…"
    : phase === "success"
    ? mode === "enroll"
      ? "Enrollment complete"
      : "Identity verified"
    : "Verification failed";

  const qiraAvatarState =
    phase === "success" ? "active" : phase === "fail" ? "revoked" : phase === "capturing" || phase === "processing" ? "scanning" : "off";

  return (
    <div className="rounded-cq-lg bg-cq-surface-container-high p-5 sm:p-6">
      <div className="flex items-center gap-2 mb-1">
        <ScanFace size={18} className="text-cq-primary" />
        <h3 className="text-[15.5px] font-bold text-cq-on-surface">
          {title || (mode === "enroll" ? "Face Enrollment" : "Face Verification")}
        </h3>
        <QiraAvatar state={qiraAvatarState} size={22} trackCursor={false} className="ml-1" />
      </div>
      {subtitle && <p className="text-[12.5px] text-cq-on-surface-variant mb-4 leading-relaxed">{subtitle}</p>}

      <div className="relative w-full max-w-[420px] mx-auto rounded-cq-lg overflow-hidden border border-cq-outline-variant/25 bg-black">
        <Webcam
          ref={webcamRef}
          audio={false}
          width={420}
          height={315}
          onUserMedia={() => {
            setCameraReady(true);
            setCameraError("");
          }}
          onUserMediaError={() => setCameraError("Camera access denied or unavailable.")}
          className="w-full h-auto block"
        />

        {/* Alignment guide */}
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div
            className="rounded-[50%] border-2 transition-colors duration-150"
            style={{
              width: "58%",
              height: "78%",
              borderColor:
                phase === "success"
                  ? "#0ea678"
                  : phase === "fail"
                  ? "#e0234f"
                  : quality?.ok
                  ? "#0ea678"
                  : "rgba(255,255,255,0.55)",
            }}
          />
        </div>

        {/* Bounding box */}
        {box && webcamRef.current?.video && (
          <div
            className="pointer-events-none absolute border-2 rounded-md"
            style={{
              borderColor: quality?.ok ? "#0ea678" : "#f59e0b",
              left: `${(box.x / webcamRef.current.video.videoWidth) * 100}%`,
              top: `${(box.y / webcamRef.current.video.videoHeight) * 100}%`,
              width: `${(box.width / webcamRef.current.video.videoWidth) * 100}%`,
              height: `${(box.height / webcamRef.current.video.videoHeight) * 100}%`,
            }}
          />
        )}

        {/* Quantum scanning sweep — purely decorative, driven by the same
            `phase` already gating everything else in this panel; never an
            independent claim about verification progress. */}
        {(phase === "capturing" || phase === "processing") && (
          <div className="pointer-events-none absolute inset-0 overflow-hidden">
            <motion.div
              className="absolute inset-x-0 h-16"
              style={{ background: "linear-gradient(180deg, transparent, rgba(99,247,255,0.22), transparent)" }}
              animate={{ y: ["-15%", "115%"] }}
              transition={{ duration: 1.7, repeat: Infinity, ease: "easeInOut" }}
            />
            <div className="absolute top-2.5 right-2.5 flex items-center gap-1.5 rounded-full bg-black/55 px-2.5 py-1 text-[10px] font-bold tracking-widest text-cq-primary uppercase">
              <span className="w-1.5 h-1.5 rounded-full bg-cq-primary cq-telemetry-dot" />
              Scanning
            </div>
          </div>
        )}

        {/* Camera status */}
        <div className="absolute top-2.5 left-2.5 flex items-center gap-1.5 rounded-full bg-black/55 px-2.5 py-1 text-[11px] font-semibold text-white">
          <span
            className={`w-1.5 h-1.5 rounded-full ${cameraReady ? "bg-emerald-400 animate-pulse" : "bg-rose-400"}`}
          />
          {cameraReady ? "Camera live" : "Camera off"}
        </div>

        {/* Success / fail overlay */}
        <AnimatePresence>
          {(phase === "success" || phase === "fail") && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 flex items-center justify-center bg-black/45"
            >
              <motion.div
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: "spring", stiffness: 260, damping: 18 }}
              >
                {phase === "success" ? (
                  <CheckCircle2 size={56} className="text-emerald-400" strokeWidth={1.75} />
                ) : (
                  <XCircle size={56} className="text-rose-400" strokeWidth={1.75} />
                )}
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {cameraError && (
        <div className="mt-3 rounded-cq-md bg-cq-error-container/15 px-3 py-2 text-[12.5px] text-cq-error">
          {cameraError}
        </div>
      )}

      {/* Quality indicator */}
      {phase !== "success" && (
        <div className="mt-4 flex flex-wrap gap-1.5">
          {["centered", "sized", "sharp"].map((k) => (
            <span
              key={k}
              className={`text-[11px] font-semibold px-2 py-1 rounded-full ${
                quality?.[k]
                  ? "bg-cq-secondary-container/15 text-cq-secondary"
                  : "bg-cq-surface-container-highest/60 text-cq-on-surface-variant"
              }`}
            >
              {k === "centered" ? "Centered" : k === "sized" ? "Distance OK" : "Sharp"}
            </span>
          ))}
        </div>
      )}

      {/* Progress */}
      {phase === "capturing" && (
        <div className="mt-3">
          <div className="h-1.5 w-full rounded-full bg-cq-surface-container-highest/60 overflow-hidden">
            <motion.div
              className="h-full bg-cq-primary"
              animate={{ width: `${progress * 100}%` }}
              transition={{ ease: "easeOut" }}
            />
          </div>
          {mode === "enroll" && (
            <div className="mt-1.5 text-[11.5px] text-cq-on-surface-variant">
              Pose {poseIndex + 1} of {ENROLL_POSES.length}
            </div>
          )}
        </div>
      )}

      <div className="mt-3 flex items-center justify-between gap-2">
        <div className="text-[13px] font-semibold text-cq-on-surface">{statusLabel}</div>
        {confidence != null && (
          <span className="inline-flex items-center gap-1 text-[12px] font-bold text-cq-primary">
            <ShieldCheck size={13} /> {(confidence * 100).toFixed(1)}% confidence
          </span>
        )}
      </div>

      {error && (
        <div className="mt-2 rounded-cq-md bg-cq-error-container/15 px-3 py-2 text-[12.5px] text-cq-error">{error}</div>
      )}

      <div className="mt-4 flex items-center gap-2.5">
        {phase === "idle" && (
          <Button variant="brand" icon={Camera} onClick={handleStart} disabled={!cameraReady}>
            {mode === "enroll" ? "Start Enrollment" : "Verify Face"}
          </Button>
        )}
        {phase === "fail" && (
          <Button variant="brand" icon={RotateCcw} onClick={handleRetry}>
            Retry
          </Button>
        )}
        {(phase === "idle" || phase === "fail" || phase === "capturing") && onCancel && (
          <Button variant="ghost" icon={X} onClick={onCancel}>
            Cancel
          </Button>
        )}
      </div>
    </div>
  );
}
