import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Camera, CameraOff, CheckCircle2, Fingerprint, KeyRound, Lock, ShieldCheck } from "lucide-react";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, StatusBadge, useToast } from "../components/ui";

type RoleChoice = "User" | "Employee" | "Admin";

function roleRoute(role?: string) {
  if (role === "Admin") return "/dashboard/admin";
  if (role === "Employee") return "/dashboard/employee";
  return "/dashboard/user";
}

function b64uToBuf(b64u: string): ArrayBuffer {
  const pad = b64u.length % 4 === 0 ? "" : "=".repeat(4 - (b64u.length % 4));
  const raw = atob(b64u.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64u(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function AuthPortalPage() {
  const navigate = useNavigate();
  const { session, setSession, logout } = useAuth();
  const { push } = useToast();

  const [step, setStep] = useState<"LOGIN" | "VERIFY" | "SUCCESS">("LOGIN");
  const [authMode, setAuthMode] = useState<"SIGNIN" | "REGISTER">("SIGNIN");
  const [identifier, setIdentifier] = useState("");
  const [regActorId, setRegActorId] = useState("");
  const [regLabel, setRegLabel] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [selectedRole, setSelectedRole] = useState<RoleChoice>("User");
  const [submitting, setSubmitting] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [regSuccess, setRegSuccess] = useState<string | null>(null);

  // Camera consent-based preview state (Face recognition is NOT IMPLEMENTED)
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [camStatus, setCamStatus] = useState<"IDLE" | "REQUESTING" | "ACTIVE" | "DENIED" | "UNAVAILABLE">("IDLE");
  const [camMessage, setCamMessage] = useState<string | null>(null);
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);

  const stopCameraTracks = () => {
    if (streamRef.current) {
      for (const t of streamRef.current.getTracks()) {
        t.stop();
      }
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCamStatus((prev) => (prev === "ACTIVE" ? "IDLE" : prev));
  };

  useEffect(() => {
    const onLogout = () => stopCameraTracks();
    window.addEventListener("qshield:logout", onLogout);
    return () => {
      window.removeEventListener("qshield:logout", onLogout);
      stopCameraTracks();
    };
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setRegSuccess(null);
    if (password !== confirmPassword) {
      setAuthError("Passwords do not match");
      return;
    }
    setSubmitting(true);
    try {
      const res = await api.registerUser({
        actor_id: regActorId.trim(),
        display_label: (regLabel || regActorId).trim(),
        email: regEmail.trim(),
        password,
        confirm_password: confirmPassword,
      });
      setPassword("");
      setConfirmPassword("");
      setSession({
        actorId: res.actor_id,
        deviceId: res.device_id,
        sessionId: res.session_id,
        sessionToken: res.session_token,
        peerId: res.peer_id,
        role: res.role,
        displayLabel: res.display_label,
        email: res.email,
        issuedAt: res.issued_at,
        expiresAt: res.expires_at,
        identityVerified: false,
        verificationMethod: "PASSWORD",
        sessionSecretBound: res.session_secret_bound,
      });
      push(`User account '${res.actor_id}' created and authenticated`, "success");
      navigate(roleRoute(res.role));
    } catch (err) {
      const msg = (err as Error).message || "Registration failed";
      setAuthError(msg);
      push(msg, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setRegSuccess(null);
    setSubmitting(true);
    try {
      const res = await api.roleLogin({
        identifier,
        password,
        expected_role: selectedRole,
      });
      setPassword("");
      setSession({
        actorId: res.actor_id,
        deviceId: res.device_id,
        sessionId: res.session_id,
        sessionToken: res.session_token,
        peerId: res.peer_id,
        role: res.role,
        displayLabel: res.display_label,
        email: res.email,
        issuedAt: res.issued_at,
        expiresAt: res.expires_at,
        identityVerified: res.identity_verified,
        verificationMethod: res.verification_method,
        sessionSecretBound: res.session_secret_bound,
      });
      push(`Authenticated as ${res.actor_id} (${res.role})`, "success");
      setStep("VERIFY");
    } catch (err) {
      const msg = (err as Error).message || "Authentication failed";
      setAuthError(msg);
      push(msg, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const handlePasskeyLogin = async () => {
    setAuthError(null);
    if (!identifier.trim()) {
      setAuthError("Enter your username or email first to sign in with Passkey / Windows Hello.");
      return;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setAuthError("WebAuthn / Windows Hello is not supported in this browser.");
      return;
    }
    setSubmitting(true);
    try {
      const rpId = window.location.hostname || "localhost";
      const opts = await api.passkeyLoginOptions(identifier.trim(), rpId);
      const rawOpts = opts.options as Record<string, unknown>;
      const allowCreds = Array.isArray(rawOpts.allowCredentials) ? rawOpts.allowCredentials : [];
      if (allowCreds.length === 0) {
        setAuthError("No passkey registered for this account. Sign in with password and register a passkey in Security Settings.");
        return;
      }
      const pubKeyOpts: PublicKeyCredentialRequestOptions = {
        challenge: b64uToBuf(String(rawOpts.challenge)),
        rpId: String(rawOpts.rpId || rpId),
        allowCredentials: allowCreds.map((c: Record<string, unknown>) => ({
          id: b64uToBuf(String(c.id)),
          type: "public-key",
        })),
        userVerification: "preferred",
      };
      const assertion = (await navigator.credentials.get({ publicKey: pubKeyOpts })) as PublicKeyCredential | null;
      if (!assertion) {
        setAuthError("Windows Hello / Passkey prompt was cancelled.");
        return;
      }
      const resp = assertion.response as AuthenticatorAssertionResponse;
      const res = await api.passkeyLoginVerify({
        identifier: identifier.trim(),
        challenge_id: opts.challenge_id,
        rp_id: rpId,
        origin: window.location.origin,
        credential: {
          id: assertion.id,
          rawId: bufToB64u(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: bufToB64u(resp.clientDataJSON),
            authenticatorData: bufToB64u(resp.authenticatorData),
            signature: bufToB64u(resp.signature),
            userHandle: resp.userHandle ? bufToB64u(resp.userHandle) : null,
          },
        },
      });
      setSession({
        actorId: res.actor_id,
        deviceId: res.device_id,
        sessionId: res.session_id,
        sessionToken: res.session_token,
        peerId: res.peer_id,
        role: res.role,
        displayLabel: res.display_label,
        email: res.email,
        issuedAt: res.issued_at,
        expiresAt: res.expires_at,
        identityVerified: true,
        verificationMethod: "WEBAUTHN",
        sessionSecretBound: res.session_secret_bound,
      });
      push(`Authenticated as ${res.actor_id} (${res.role}) via Passkey / Windows Hello`, "success");
      navigate(roleRoute(res.role));
    } catch (err) {
      const msg = (err as Error).message || "Passkey / Windows Hello authentication failed or was cancelled";
      setAuthError(msg);
      push(msg, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const requestCameraPermission = async () => {
    setCamMessage(null);
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setCamStatus("UNAVAILABLE");
      setCamMessage("Browser MediaDevices API unavailable. Use WebAuthn / Passkey or continue with password session.");
      return;
    }
    setCamStatus("REQUESTING");
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
      setCamStatus("ACTIVE");
      setCamMessage("Camera preview active (Face Recognition: NOT IMPLEMENTED — zero frames uploaded or stored).");
    } catch (err) {
      setCamStatus("DENIED");
      setCamMessage(`Camera permission denied (${(err as Error).message}).`);
      if (session) {
        await api
          .cameraCheckpoint(session.sessionId, session.sessionToken, {
            consent_granted: false,
            action: "DENIED",
          })
          .catch(() => {});
      }
    }
  };

  const completeCameraPreview = async () => {
    if (!session) return;
    stopCameraTracks();
    await api.cameraCheckpoint(session.sessionId, session.sessionToken, {
      consent_granted: true,
      action: "COMPLETED",
    });
    push("Camera preview closed; stream released (not a biometric verification)", "info");
    navigate(roleRoute(session.role));
  };

  const runRealWebAuthn = async () => {
    if (!session) return;
    setVerifyMessage(null);
    stopCameraTracks();
    if (!window.PublicKeyCredential || !navigator.credentials) {
      setVerifyMessage("WebAuthn is not supported in this browser environment.");
      return;
    }
    try {
      const rpId = window.location.hostname || "localhost";
      const opts = await api.authOptions(session.actorId, rpId);
      const rawOpts = opts.options as Record<string, unknown>;
      const allowCreds = Array.isArray(rawOpts.allowCredentials) ? rawOpts.allowCredentials : [];
      if (allowCreds.length === 0) {
        setVerifyMessage("No passkey registered for this account yet. Register a passkey in Security Integrity Center or continue with password session.");
        return;
      }
      const pubKeyOpts: PublicKeyCredentialRequestOptions = {
        challenge: b64uToBuf(String(rawOpts.challenge)),
        rpId: String(rawOpts.rpId || rpId),
        allowCredentials: allowCreds.map((c: Record<string, unknown>) => ({
          id: b64uToBuf(String(c.id)),
          type: "public-key",
        })),
        userVerification: "preferred",
      };
      const assertion = (await navigator.credentials.get({ publicKey: pubKeyOpts })) as PublicKeyCredential | null;
      if (!assertion) {
        setVerifyMessage("WebAuthn assertion was cancelled.");
        return;
      }
      const resp = assertion.response as AuthenticatorAssertionResponse;
      await api.authVerify({
        actor_id: session.actorId,
        challenge_id: opts.challenge_id,
        rp_id: rpId,
        origin: window.location.origin,
        credential: {
          id: assertion.id,
          rawId: bufToB64u(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: bufToB64u(resp.clientDataJSON),
            authenticatorData: bufToB64u(resp.authenticatorData),
            signature: bufToB64u(resp.signature),
            userHandle: resp.userHandle ? bufToB64u(resp.userHandle) : null,
          },
        },
      });
      setSession({ ...session, identityVerified: true, verificationMethod: "WEBAUTHN" });
      setStep("SUCCESS");
      push("WebAuthn passkey assertion cryptographically verified by backend", "success");
    } catch (err) {
      const msg = (err as Error).message || "WebAuthn verification failed";
      setVerifyMessage(msg);
      push(msg, "error");
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-white">
            Role-Based Authentication &amp; Identity Verification
          </h1>
          <p className="text-xs text-slate-500">
            Backend-verified RBAC (User, Employee, Admin), HttpOnly session cookies, 256-bit session secrets &amp; WebAuthn
          </p>
        </div>
        <StatusBadge label={`STEP: ${step}`} tone="info" />
      </div>

      {step === "LOGIN" && (
        <Card
          title={authMode === "SIGNIN" ? "Sign In with Assigned Account Role" : "Create Standard User Account"}
          subtitle={
            authMode === "SIGNIN"
              ? "Backend independently verifies username/email, scrypt password, and assigned role"
              : "Self-registration creates User accounts only. Employee and Admin accounts require Admin provisioning."
          }
          action={
            <div className="flex gap-1">
              <Button
                size="sm"
                variant={authMode === "SIGNIN" ? "primary" : "secondary"}
                onClick={() => {
                  setAuthMode("SIGNIN");
                  setAuthError(null);
                  setRegSuccess(null);
                }}
              >
                Sign In
              </Button>
              <Button
                size="sm"
                variant={authMode === "REGISTER" ? "primary" : "secondary"}
                onClick={() => {
                  setAuthMode("REGISTER");
                  setAuthError(null);
                  setRegSuccess(null);
                }}
              >
                Create User Account
              </Button>
            </div>
          }
        >
          {authMode === "REGISTER" ? (
            <form onSubmit={handleRegister} className="space-y-4 text-xs">
              <div className="grid md:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="reg-label" className="block text-slate-500 mb-1">Full Name</label>
                  <input
                    id="reg-label"
                    type="text"
                    required
                    value={regLabel}
                    onChange={(e) => setRegLabel(e.target.value)}
                    placeholder="Alice Johnson"
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
                  />
                </div>
                <div>
                  <label htmlFor="reg-email" className="block text-slate-500 mb-1">Email Address</label>
                  <input
                    id="reg-email"
                    type="email"
                    required
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="alice@example.com"
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
                  />
                </div>
                <div>
                  <label htmlFor="reg-username" className="block text-slate-500 mb-1">Username</label>
                  <input
                    id="reg-username"
                    type="text"
                    required
                    minLength={2}
                    value={regActorId}
                    onChange={(e) => setRegActorId(e.target.value)}
                    placeholder="alice_user"
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
                  />
                </div>
                <div>
                  <label htmlFor="reg-password" className="block text-slate-500 mb-1">Password (min 8 chars)</label>
                  <input
                    id="reg-password"
                    type="password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
                  />
                </div>
                <div className="md:col-span-2">
                  <label htmlFor="reg-confirm-password" className="block text-slate-500 mb-1">Confirm Password</label>
                  <input
                    id="reg-confirm-password"
                    type="password"
                    required
                    minLength={8}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
                  />
                </div>
              </div>
              {authError && (
                <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-300 font-mono">
                  {authError}
                </div>
              )}
              <div className="flex justify-end">
                <Button type="submit" disabled={submitting}>
                  {submitting ? "Creating..." : "Create User Account"}
                </Button>
              </div>
            </form>
          ) : (
            <form onSubmit={handleLogin} className="space-y-4 text-xs">
              {regSuccess && (
                <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-300 font-mono">
                  {regSuccess}
                </div>
              )}
              <div className="grid md:grid-cols-2 gap-3">
                <div>
                  <label htmlFor="rbac-identifier" className="block text-slate-500 mb-1">
                    Username or Email
                  </label>
                  <input
                    id="rbac-identifier"
                    type="text"
                    required
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="e.g. alice_user or alice@example.com"
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d] text-slate-900 dark:text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="rbac-password" className="block text-slate-500 mb-1">
                    Password
                  </label>
                  <input
                    id="rbac-password"
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter account password"
                    className="w-full rounded px-3 py-2 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d] text-slate-900 dark:text-slate-100"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-500 mb-1">Assigned Account Role</label>
                <div className="grid grid-cols-3 gap-2">
                  {(["User", "Employee", "Admin"] as RoleChoice[]).map((r) => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setSelectedRole(r)}
                      className={`py-2 px-3 rounded border font-mono text-xs transition-colors ${
                        selectedRole === r
                          ? "bg-emerald-600 text-white border-emerald-600"
                          : "bg-slate-50 dark:bg-[#131a21] text-slate-700 dark:text-slate-300 border-slate-300 dark:border-[#26313d]"
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Selecting a higher role than your account&apos;s database role will be rejected (HTTP 403) and logged as a role-spoofing attempt.
                </p>
              </div>

              {authError && (
                <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-300 font-mono">
                  {authError}
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
                  <Lock className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Salted scrypt + 256-bit session secret</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="secondary" disabled={submitting} onClick={handlePasskeyLogin}>
                    <Fingerprint className="w-3.5 h-3.5 mr-1 inline" /> Sign in with Passkey / Windows Hello
                  </Button>
                  <Button type="submit" disabled={submitting}>
                    {submitting ? "Verifying..." : "Login"}
                  </Button>
                </div>
              </div>
              <p className="text-[11px] text-slate-500 border-t border-slate-200 dark:border-[#1c242d] pt-2">
                Your device may verify your identity using Windows Hello Face, PIN, or another supported authenticator method. Biometric verification is handled locally by your device. Q-SHIELD does not receive or store your facial biometric data.
              </p>
            </form>
          )}
        </Card>
      )}

      {step === "VERIFY" && session && (
        <div className="space-y-4">
          <Card
            title="Account & Role Verified"
            action={<StatusBadge label={`ROLE: ${session.role}`} tone="success" />}
          >
            <div className="grid md:grid-cols-3 gap-3 text-xs font-mono">
              <div>Account: {session.actorId}</div>
              <div>Session Secret: {session.sessionSecretBound ? "256-BIT BOUND (HASHED)" : "NONE"}</div>
              <div>Auth Method: PASSWORD</div>
            </div>
          </Card>

          <Card
            title="Additional Verification (WebAuthn Passkey / Optional Camera Preview)"
            subtitle="WebAuthn verifies real platform authenticator assertions. Camera preview is non-biometric (Face Recognition: NOT IMPLEMENTED)."
            action={
              <div className="flex flex-wrap gap-1.5">
                <StatusBadge label={camStatus === "ACTIVE" ? "CAMERA ACTIVE" : "CAMERA PREVIEW: IMPLEMENTED"} tone={camStatus === "ACTIVE" ? "success" : "info"} />
                <StatusBadge label="FACIAL BIOMETRIC MATCHING: NOT IMPLEMENTED" tone="warning" />
                <StatusBadge label="PASSKEY / WEBAUTHN: SUBJECT TO REAL-DEVICE VERIFICATION" tone="violet" />
              </div>
            }
          >
            <div className="space-y-3 text-xs">
              <div className="h-44 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center overflow-hidden relative">
                <video
                  ref={videoRef}
                  autoPlay
                  playsInline
                  muted
                  className={`w-full h-full object-cover ${camStatus === "ACTIVE" ? "block" : "hidden"}`}
                />
                {camStatus !== "ACTIVE" && (
                  <div className="flex flex-col items-center gap-1.5 text-slate-400">
                    <CameraOff className="w-6 h-6" />
                    <span>Camera inactive (requires explicit consent; never auto-starts)</span>
                  </div>
                )}
              </div>

              {(camMessage || verifyMessage) && (
                <div className="p-2 rounded bg-slate-100 dark:bg-[#131a21] text-slate-700 dark:text-slate-300 font-mono text-[11px]">
                  {verifyMessage || camMessage}
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                <Button variant="primary" onClick={() => navigate(roleRoute(session.role))}>
                  <ShieldCheck className="w-3.5 h-3.5 mr-1 inline" /> Continue to {session.role} Dashboard
                </Button>
                <Button variant="secondary" onClick={runRealWebAuthn}>
                  <Fingerprint className="w-3.5 h-3.5 mr-1 inline" /> Verify with WebAuthn / Passkey
                </Button>
                <Button variant="secondary" onClick={requestCameraPermission} disabled={camStatus === "ACTIVE"}>
                  <Camera className="w-3.5 h-3.5 mr-1 inline" /> Allow Camera Preview
                </Button>
                <Button variant="secondary" onClick={stopCameraTracks} disabled={camStatus !== "ACTIVE"}>
                  Stop Camera
                </Button>
                {camStatus === "ACTIVE" && (
                  <Button variant="secondary" onClick={completeCameraPreview}>
                    Close Camera &amp; Continue
                  </Button>
                )}
                <Button
                  variant="ghost"
                  onClick={async () => {
                    stopCameraTracks();
                    await logout();
                    setStep("LOGIN");
                  }}
                >
                  Cancel &amp; Logout
                </Button>
              </div>
            </div>
          </Card>
        </div>
      )}

      {step === "SUCCESS" && session && (
        <Card
          title="WebAuthn Passkey Verification Complete"
          action={<StatusBadge label="WEBAUTHN VERIFIED" tone="success" />}
        >
          <div className="space-y-4 text-xs">
            <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-semibold">
              <CheckCircle2 className="w-5 h-5" />
              <span>
                Authenticated as <code>{session.actorId}</code> ({session.role}) via {session.verificationMethod}
              </span>
            </div>
            <div className="flex gap-2">
              <Button onClick={() => navigate(roleRoute(session.role))}>
                <ShieldCheck className="w-3.5 h-3.5 mr-1 inline" /> Continue to {session.role} Dashboard
              </Button>
              <Button
                variant="secondary"
                onClick={async () => {
                  await logout();
                  setStep("LOGIN");
                }}
              >
                <KeyRound className="w-3.5 h-3.5 mr-1 inline" /> Logout
              </Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
