import { useEffect, useState } from "react";
import { ScanFace, CheckCircle2, XCircle, ShieldCheck, Activity } from "lucide-react";
import { listAuditLogs, faceStatus } from "../services/api";
import FaceAuthPanel from "../components/face/FaceAuthPanel";
import PageHeader from "../components/ui/PageHeader";
import { formatTimestamp, byTimestampDesc } from "../utils/formatTimestamp";

const SUCCESS_PATTERN = /success|ok|approved|granted/i;

export default function ProfilePage({ user }) {
  const [enrolled, setEnrolled] = useState(null); // null = unknown, else bool
  const [activity, setActivity] = useState(null);

  useEffect(() => {
    listAuditLogs()
      .then((logs) => {
        const mine = user?.userId != null ? logs.filter((l) => l.user_id === user.userId) : logs;
        // Same "explicit newest-first, never trust API order" rule as
        // the main Dashboard/Audit Log — see utils/formatTimestamp.js.
        const withIndex = mine.map((l, i) => ({ ...l, __idx: i }));
        withIndex.sort(byTimestampDesc("timestamp", "__idx"));
        setActivity(withIndex.slice(0, 6));
      })
      .catch(() => setActivity([]));
  }, [user?.userId]);

  useEffect(() => {
    faceStatus()
      .then((s) => setEnrolled(s.enrolled))
      .catch(() => setEnrolled(false));
  }, []);

  return (
    <div>
      <PageHeader
        icon="account_circle"
        eyebrow="Account"
        title="Profile"
        description="Your account identity and biometric enrollment for step-up decryption verification."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <h2 className="text-[16px] font-bold text-cq-on-surface mb-4">Account</h2>
          <div className="flex items-center gap-4 mb-6">
            <div className="w-14 h-14 rounded-cq-lg bg-cq-primary-container flex items-center justify-center text-cq-on-primary-container text-[22px] font-bold shrink-0">
              {user?.username?.[0]?.toUpperCase() || "U"}
            </div>
            <div className="min-w-0">
              <div className="text-[16px] font-bold text-cq-on-surface truncate">{user?.username}</div>
              <div className="text-[13px] text-cq-on-surface-variant capitalize">{user?.role || "member"}</div>
            </div>
          </div>

          <dl className="space-y-3">
            <div className="flex items-center justify-between py-2.5 border-t border-cq-outline-variant/15">
              <dt className="text-[13px] text-cq-on-surface-variant">User ID</dt>
              <dd className="text-[13px] font-mono text-cq-on-surface">{user?.userId}</dd>
            </div>
            <div className="flex items-center justify-between py-2.5 border-t border-cq-outline-variant/15">
              <dt className="text-[13px] text-cq-on-surface-variant">Role</dt>
              <dd className="text-[13px] font-semibold text-cq-on-surface capitalize">{user?.role || "member"}</dd>
            </div>
            <div className="flex items-center justify-between py-2.5 border-t border-b border-cq-outline-variant/15">
              <dt className="text-[13px] text-cq-on-surface-variant">Session</dt>
              <dd className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-cq-secondary">
                <ShieldCheck size={14} /> Active
              </dd>
            </div>
          </dl>
        </div>

        <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg">
          <div className="flex items-center gap-2 mb-1">
            <ScanFace size={18} className="text-cq-primary" />
            <h2 className="text-[16px] font-bold text-cq-on-surface">Face Enrollment</h2>
            {enrolled && (
              <span className="ml-auto inline-flex items-center gap-1.5 rounded-full bg-cq-secondary-container/15 px-2.5 py-1 text-[12px] font-semibold text-cq-secondary">
                <CheckCircle2 size={12} />
                Enrolled
              </span>
            )}
          </div>
          <p className="text-[13px] leading-relaxed text-cq-on-surface-variant mb-4">
            Required before Encrypt or Decrypt can be used. Only the face descriptor is stored —
            never a raw image — and it's never used to derive a key.
          </p>
          <FaceAuthPanel mode="enroll" onSuccess={() => setEnrolled(true)} />
        </div>
      </div>

      <div className="bg-cq-surface-container rounded-cq-xl p-cq-stack-lg mt-5">
        <div className="flex items-center gap-2 mb-1">
          <Activity size={17} className="text-cq-primary" />
          <h2 className="text-[16px] font-bold text-cq-on-surface">Activity Summary</h2>
        </div>
        <p className="text-[13px] text-cq-on-surface-variant mb-4">Recent entries attributed to your account in the audit chain.</p>
        {activity === null ? null : activity.length === 0 ? (
          <div className="flex flex-col items-center justify-center text-center py-14 px-6">
            <div className="text-[14.5px] font-semibold text-cq-on-surface">No activity recorded yet</div>
            <div className="mt-1 text-[13.5px] text-cq-on-surface-variant max-w-sm">Actions you take will appear here.</div>
          </div>
        ) : (
          <div className="divide-y divide-cq-outline-variant/15">
            {activity.map((l, i) => {
              const ok = SUCCESS_PATTERN.test(l.result);
              return (
                <div key={i} className="flex items-center gap-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="text-[13.5px] font-semibold text-cq-on-surface truncate">{l.action}</div>
                    <div className="text-[12px] text-cq-on-surface-variant">{formatTimestamp(l.timestamp)}</div>
                  </div>
                  <span
                    className={
                      "inline-flex items-center gap-1.5 text-[11px] font-semibold px-2 py-1 rounded-full " +
                      (ok ? "bg-cq-secondary-container/15 text-cq-secondary" : "bg-cq-error-container/20 text-cq-error")
                    }
                  >
                    {ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                    {l.result}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
