/**
 * Face identity extraction — client-side, via @vladmandic/face-api.
 *
 * The reference project's `faceApi.js` loaded `faceExpressionNet` and
 * used the detected *emotion* as a signal fed into key derivation.
 * This module intentionally does something different: it loads
 * `tinyFaceDetector`, `faceLandmark68Net`, and `faceRecognitionNet` to
 * produce a 128-d identity descriptor, matching what
 * `authentication.face_auth.FaceAuthService` on the backend expects.
 * Nothing here classifies expression, and the descriptor this module
 * produces is only ever sent to `/api/face/enroll` or included in a
 * `/api/decrypt` request's `face_descriptor` field — never used to
 * derive a key or populate a CID.
 */
import * as faceapi from "@vladmandic/face-api";

const MODEL_URL = "/models";
let modelsLoaded = false;

export async function loadModels() {
  if (modelsLoaded) return;
  await Promise.all([
    faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
    faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
    faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
  ]);
  modelsLoaded = true;
}

/**
 * Run detection + landmarks + descriptor extraction against a video
 * or canvas element. Returns a plain 128-length number[] (JSON-safe),
 * or null if no face was detected.
 */
export async function extractDescriptor(mediaElement) {
  if (!modelsLoaded) await loadModels();

  const detection = await faceapi
    .detectSingleFace(mediaElement, new faceapi.TinyFaceDetectorOptions())
    .withFaceLandmarks()
    .withFaceDescriptor();

  if (!detection) return null;
  return Array.from(detection.descriptor);
}

export function isReady() {
  return modelsLoaded;
}

/**
 * Lightweight per-frame detection for the live camera overlay
 * (bounding box + landmarks, no 128-d descriptor — that's only
 * computed at actual capture moments, since it's the expensive step).
 */
export async function detectFaceLite(mediaElement) {
  if (!modelsLoaded) await loadModels();
  const detection = await faceapi
    .detectSingleFace(mediaElement, new faceapi.TinyFaceDetectorOptions())
    .withFaceLandmarks();
  return detection || null;
}

/**
 * Heuristic frame-quality assessment.
 *
 * This function is used for TWO different purposes, and they need
 * different tolerances:
 *
 *   1. Face ENROLLMENT — the user is deliberately asked to center
 *      their face in a guide, so it's reasonable to be strict there.
 *   2. Continuous MONITORING (every ~2.5s while the user works) — the
 *      user is not expected to stare at a center guide, sit
 *      perfectly still, or stay at one fixed distance. Continuous
 *      monitoring only needs the frame to be *usable* (a face that
 *      can reliably be matched against the enrolled identity), not
 *      *ideal*. See MonitoringContext.jsx / the monitoring brief,
 *      part 8: "Do NOT make the user constantly stare at the center
 *      of the screen."
 *
 * `mode` selects which tolerance set to apply. `centered` is still
 * computed and returned either way (useful for an on-screen alignment
 * hint), but for `mode: "monitoring"` it does NOT gate `ok` — only
 * whether the face is detectable, reasonably sized, and clear enough
 * to extract a usable descriptor from does.
 */
export function assessQuality(detection, mediaElement, mode = "monitoring") {
  if (!detection) {
    return { ok: false, centered: false, sized: false, sharp: false, lit: false, reasons: ["No face detected"] };
  }
  const { box } = detection.detection;
  const w = mediaElement.videoWidth || mediaElement.width || 1;
  const h = mediaElement.videoHeight || mediaElement.height || 1;

  const boxCenterX = box.x + box.width / 2;
  const boxCenterY = box.y + box.height / 2;
  const offsetX = Math.abs(boxCenterX - w / 2) / w;
  const offsetY = Math.abs(boxCenterY - h / 2) / h;

  const relativeSize = box.width / w;

  const landmarksOk = detection.landmarks?.positions?.length === 68;

  const strict = mode === "enrollment";

  // Enrollment: tight guide-box tolerance. Monitoring: generous —
  // normal head movement, a slightly off-center seat, or sitting
  // further back/closer than an enrollment guide shouldn't register
  // as a failure.
  const centered = strict ? offsetX < 0.18 && offsetY < 0.18 : offsetX < 0.4 && offsetY < 0.4;
  const sized = strict
    ? relativeSize > 0.22 && relativeSize < 0.85
    : relativeSize > 0.1 && relativeSize < 0.95;
  // face-api's detector score is a reasonable proxy for sharpness /
  // occlusion — a blurry or fully-hidden face scores lower. Monitoring
  // tolerates normal lighting variation and minor motion blur; only a
  // genuinely low-confidence detection counts as "not usable".
  const sharp = detection.detection.score > (strict ? 0.75 : 0.5);

  const reasons = [];
  if (!centered) reasons.push("Center your face in the guide");
  if (!sized) reasons.push(relativeSize <= (strict ? 0.22 : 0.1) ? "Move closer" : "Move back a little");
  if (!sharp) reasons.push("Hold still / improve lighting");
  if (!landmarksOk) reasons.push("Face not fully visible");

  // Enrollment requires the face centered in the guide box. Continuous
  // monitoring only requires a clear, appropriately-sized, landmark-
  // resolvable face — centering is informational only, not gating.
  const ok = strict ? centered && sized && sharp && landmarksOk : sized && sharp && landmarksOk;

  return {
    ok,
    centered,
    sized,
    sharp,
    lit: sharp,
    reasons,
  };
}
