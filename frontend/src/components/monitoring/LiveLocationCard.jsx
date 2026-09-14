import { useEffect, useRef, useState } from "react";
import { MapPin, MapPinOff } from "lucide-react";
import { useMonitoringContext } from "../../context/MonitoringContext";
import { formatTimestamp } from "../../utils/formatTimestamp";

// Section 4 — LIVE LOCATION.
//
// Deliberately entirely client-side: the browser Geolocation API is
// watched only while a monitoring session is active, and the
// coordinates never leave the browser (no backend call here, and
// therefore no risk of this ending up in an audit record's "exact GPS
// coordinates" — see the spec's explicit prohibition on that). This
// also trivially satisfies "only the current authenticated user...
// should be able to access [this]": there is nothing to authorize,
// because nothing is transmitted or stored server-side.
export default function LiveLocationCard() {
  const { isMonitoring } = useMonitoringContext();
  // 'not_requested' | 'granted' | 'denied'
  const [permission, setPermission] = useState("not_requested");
  const [coords, setCoords] = useState(null); // { lat, lng }
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState("");
  const watchIdRef = useRef(null);
  const requestedRef = useRef(false);

  // Reflect the browser's already-granted/denied permission state up
  // front where supported, WITHOUT prompting — prompting only happens
  // once, from the effect below, and only while monitoring is active.
  useEffect(() => {
    if (!navigator.permissions?.query) return;
    let cancelled = false;
    navigator.permissions
      .query({ name: "geolocation" })
      .then((status) => {
        if (cancelled) return;
        if (status.state === "granted") setPermission("granted");
        else if (status.state === "denied") setPermission("denied");
        status.onchange = () => {
          if (status.state === "granted") setPermission("granted");
          else if (status.state === "denied") setPermission("denied");
        };
      })
      .catch(() => {
        /* Permissions API not supported for geolocation on this browser */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    function stopWatch() {
      if (watchIdRef.current != null && navigator.geolocation) {
        navigator.geolocation.clearWatch(watchIdRef.current);
      }
      watchIdRef.current = null;
    }

    if (!isMonitoring) {
      stopWatch();
      return undefined;
    }

    if (!navigator.geolocation) {
      setError("Geolocation is not supported by this browser.");
      return undefined;
    }

    // Never re-prompt once we've already asked this session — if the
    // user denied it, we show that and stop, rather than nagging.
    if (requestedRef.current) return stopWatch;
    requestedRef.current = true;

    watchIdRef.current = navigator.geolocation.watchPosition(
      (pos) => {
        setPermission("granted");
        setError("");
        setCoords({ lat: pos.coords.latitude, lng: pos.coords.longitude });
        setLastUpdated(new Date());
      },
      (err) => {
        if (err.code === err.PERMISSION_DENIED) {
          setPermission("denied");
          setError("Location permission denied");
        } else {
          setError(err.message || "Unable to determine location");
        }
      },
      { enableHighAccuracy: false, maximumAge: 15000, timeout: 20000 }
    );

    return stopWatch;
  }, [isMonitoring]);

  // Monitoring ended (logout, revocation) -> reset so a future
  // monitoring session starts clean and re-asks appropriately.
  useEffect(() => {
    if (!isMonitoring) {
      requestedRef.current = false;
    }
  }, [isMonitoring]);

  const active = isMonitoring && permission === "granted" && !!coords;

  return (
    <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
      <div className="flex items-center gap-2 mb-3">
        <span
          className={`inline-flex w-7 h-7 items-center justify-center rounded-cq-md bg-cq-surface-container-high ${
            active ? "text-cq-primary" : "text-cq-on-surface-variant"
          }`}
        >
          {active ? <MapPin size={15} /> : <MapPinOff size={15} />}
        </span>
        <span className="text-[12px] font-bold uppercase tracking-wide text-cq-on-surface-variant">Live Location</span>
      </div>

      <div className="space-y-1 text-[12.5px]">
        <Row label="Location monitoring" value={active ? "ACTIVE" : "INACTIVE"} tone={active ? "ok" : "muted"} />
        <Row
          label="Permission"
          value={permission === "granted" ? "GRANTED" : permission === "denied" ? "DENIED" : "NOT REQUESTED"}
          tone={permission === "granted" ? "ok" : permission === "denied" ? "error" : "muted"}
        />
        <Row label="Latitude" value={coords ? coords.lat.toFixed(5) : "—"} mono />
        <Row label="Longitude" value={coords ? coords.lng.toFixed(5) : "—"} mono />
        <Row label="Last updated" value={lastUpdated ? formatTimestamp(lastUpdated) : "—"} />
      </div>

      {permission === "denied" && (
        <p className="mt-2.5 text-[11.5px] text-cq-on-surface-variant leading-relaxed">
          Location permission denied. The rest of CipherQ continues to work normally.
        </p>
      )}
      {error && permission !== "denied" && <p className="mt-2 text-[11px] text-cq-on-surface-variant">{error}</p>}
    </div>
  );
}

function Row({ label, value, tone, mono }) {
  const toneClass =
    tone === "error" ? "text-cq-error" : tone === "ok" ? "text-cq-primary" : tone === "muted" ? "text-cq-on-surface-variant" : "text-cq-on-surface";
  return (
    <div className="flex items-center justify-between py-0.5">
      <span className="text-cq-on-surface-variant">{label}</span>
      <span className={`font-semibold ${toneClass} ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}
