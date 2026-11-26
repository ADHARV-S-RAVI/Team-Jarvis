import React, { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Download, LogOut, ShieldAlert, ShieldCheck } from "lucide-react";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, DataTable, StatusBadge, useToast } from "../components/ui";

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { session, authLoading } = useAuth();
  if (authLoading) {
    return <div className="p-8 text-center text-xs font-mono text-slate-500">Verifying session...</div>;
  }
  if (!session) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export function RequireRole({
  allowedRoles,
  children,
}: {
  allowedRoles: string[];
  children: React.ReactNode;
}) {
  const { session, authLoading } = useAuth();
  if (authLoading) {
    return <div className="p-8 text-center text-xs font-mono text-slate-500">Verifying session...</div>;
  }
  if (!session) {
    return <Navigate to="/login" replace />;
  }
  if (!session.role || !allowedRoles.includes(session.role)) {
    return <Navigate to="/access-denied" replace />;
  }
  return <>{children}</>;
}

export function AccessDeniedPage() {
  const navigate = useNavigate();
  const { session, logout } = useAuth();
  return (
    <div className="max-w-xl mx-auto py-12">
      <Card
        title="Access Denied (403)"
        action={<StatusBadge label="RBAC ENFORCED" tone="danger" />}
      >
        <div className="space-y-4 text-xs">
          <div className="flex items-center gap-2 text-rose-500 font-semibold">
            <ShieldAlert className="w-5 h-5" />
            <span>Your current role ({session?.role ?? "Unauthenticated"}) is not permitted to access this resource.</span>
          </div>
          <p className="text-slate-500">
            All dashboard routes and protected APIs are independently verified by the Q-SHIELD backend RBAC engine.
          </p>
          <div className="flex gap-2">
            <Button onClick={() => navigate("/auth")}>Go to Login</Button>
            {session && (
              <Button
                variant="secondary"
                onClick={async () => {
                  await logout();
                  navigate("/auth");
                }}
              >
                Logout
              </Button>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}

function SessionStatusBanner() {
  const { session, logout } = useAuth();
  const navigate = useNavigate();
  const { push } = useToast();
  const [secondsRemaining, setSecondsRemaining] = useState<number | null>(null);

  useEffect(() => {
    if (!session) return;
    let active = true;
    const poll = async () => {
      try {
        const st = await api.getSessionStatus(session.sessionId, session.sessionToken);
        if (active) setSecondsRemaining(st.seconds_remaining);
      } catch {
        if (active) {
          push("Session expired or revoked by backend", "error");
          await logout();
          navigate("/auth");
        }
      }
    };
    void poll();
    const id = window.setInterval(poll, 15000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [session, logout, navigate, push]);

  if (!session) return null;
  const expiringSoon = secondsRemaining !== null && secondsRemaining < 300;

  return (
    <div className="space-y-3">
      {expiringSoon && (
        <div className="p-3 rounded-lg bg-amber-500/15 border border-amber-500/40 text-amber-700 dark:text-amber-300 text-xs flex items-center gap-2 font-mono">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>Session Expiration Warning: {secondsRemaining}s remaining before automatic invalidation.</span>
        </div>
      )}
      <Card
        title="Authenticated Session & Security Monitor"
        action={
          <Button
            size="sm"
            variant="danger"
            onClick={async () => {
              await logout();
              navigate("/auth");
            }}
          >
            <LogOut className="w-3.5 h-3.5 mr-1 inline" /> Logout
          </Button>
        }
      >
        <div className="grid md:grid-cols-4 gap-3 text-xs font-mono">
          <div>Account: <strong>{session.actorId}</strong></div>
          <div>Assigned Role: <StatusBadge label={session.role ?? "Unknown"} tone="info" /></div>
          <div>Auth Status: <StatusBadge label={session.identityVerified ? "VERIFIED" : "PASSWORD_OK"} tone="success" /></div>
          <div>Session Secret: <StatusBadge label={session.sessionSecretBound ? "256-BIT BOUND" : "NONE"} tone="violet" /></div>
          <div>Issued: {session.issuedAt?.slice(0, 19).replace("T", " ")}</div>
          <div>Expires: {session.expiresAt?.slice(0, 19).replace("T", " ")}</div>
          <div>Method: {session.verificationMethod ?? "PASSWORD"}</div>
          <div>TTL Left: {secondsRemaining ?? "Checking..."} s</div>
        </div>
      </Card>
    </div>
  );
}

function ProtectedFilesPanel() {
  const { session } = useAuth();
  const { push } = useToast();
  const [downloaded, setDownloaded] = useState<{ name: string; content_text: string } | null>(null);

  const filesQuery = useQuery({
    queryKey: ["rbac-files", session?.sessionId],
    queryFn: () => api.listProtectedFiles(session!.sessionId, session!.sessionToken),
    enabled: Boolean(session),
  });

  const dlMut = useMutation({
    mutationFn: (fileId: string) => api.downloadProtectedFile(session!.sessionId, session!.sessionToken, fileId),
    onSuccess: (res) => {
      setDownloaded({ name: res.name, content_text: res.content_text });
      push(`Authorized download: ${res.name}`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  return (
    <Card title="Authorized Protected Files" subtitle="Filtered and enforced by backend RBAC">
      <DataTable
        rows={(filesQuery.data ?? []) as unknown as Record<string, unknown>[]}
        columns={[
          { key: "id", header: "File ID" },
          { key: "name", header: "Filename" },
          { key: "classification", header: "Classification" },
          { key: "required_role", header: "Required Role" },
          {
            key: "action",
            header: "Action",
            render: (r) => (
              <Button size="sm" variant="secondary" onClick={() => dlMut.mutate(String(r.id))}>
                <Download className="w-3 h-3 mr-1 inline" /> Download
              </Button>
            ),
          },
        ]}
      />
      {downloaded && (
        <pre className="mt-3 p-3 rounded bg-slate-950 text-emerald-300 text-xs font-mono overflow-x-auto">
          {`[${downloaded.name}]\n${downloaded.content_text}`}
        </pre>
      )}
    </Card>
  );
}

export function UserDashboardPage() {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900 dark:text-white">User Dashboard</h1>
        <StatusBadge label="ROLE: USER" tone="success" />
      </div>
      <SessionStatusBanner />
      <ProtectedFilesPanel />
    </div>
  );
}

export function EmployeeDashboardPage() {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900 dark:text-white">Employee Operations Dashboard</h1>
        <StatusBadge label="ROLE: EMPLOYEE" tone="info" />
      </div>
      <SessionStatusBanner />
      <ProtectedFilesPanel />
    </div>
  );
}

export function AdminDashboardPage() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const { push } = useToast();
  const [newActorId, setNewActorId] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newRole, setNewRole] = useState<"User" | "Employee" | "Admin">("Employee");
  const [newPassword, setNewPassword] = useState("");

  const usersQuery = useQuery({
    queryKey: ["admin-users", session?.sessionId],
    queryFn: () => api.adminListUsers(session!.sessionId, session!.sessionToken),
    enabled: Boolean(session),
  });

  const auditQuery = useQuery({
    queryKey: ["admin-audit", session?.sessionId],
    queryFn: () => api.adminAuditEvents(session!.sessionId, session!.sessionToken),
    enabled: Boolean(session),
  });

  const createMut = useMutation({
    mutationFn: () =>
      api.adminCreateUser(session!.sessionId, session!.sessionToken, {
        actor_id: newActorId,
        display_label: newActorId,
        email: newEmail,
        role: newRole,
        password: newPassword,
        device_id: `dev-${newActorId}`,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      setNewActorId("");
      setNewEmail("");
      setNewPassword("");
      push("Account provisioned with salted scrypt password", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const toggleStatusMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.adminUpdateStatus(session!.sessionId, session!.sessionToken, id, enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-users"] });
      push("Account status updated", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900 dark:text-white">Admin Control Dashboard</h1>
        <StatusBadge label="ROLE: ADMIN" tone="violet" />
      </div>
      <SessionStatusBanner />
      <ProtectedFilesPanel />

      <Card title="Provision User / Employee / Admin Account">
        <div className="grid md:grid-cols-5 gap-2 text-xs">
          <input
            placeholder="actor_id"
            value={newActorId}
            onChange={(e) => setNewActorId(e.target.value)}
            className="rounded px-2.5 py-1.5 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
          />
          <input
            placeholder="email"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            className="rounded px-2.5 py-1.5 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
          />
          <select
            value={newRole}
            onChange={(e) => setNewRole(e.target.value as "User" | "Employee" | "Admin")}
            className="rounded px-2.5 py-1.5 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
          >
            <option value="User">User</option>
            <option value="Employee">Employee</option>
            <option value="Admin">Admin</option>
          </select>
          <input
            type="password"
            placeholder="password (min 8)"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="rounded px-2.5 py-1.5 bg-white dark:bg-[#131a21] border border-slate-300 dark:border-[#26313d]"
          />
          <Button onClick={() => createMut.mutate()} disabled={createMut.isPending}>
            <ShieldCheck className="w-3.5 h-3.5 mr-1 inline" /> Provision
          </Button>
        </div>
      </Card>

      <Card title="Managed Accounts">
        <DataTable
          rows={(usersQuery.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "id", header: "Actor ID" },
            { key: "email", header: "Email" },
            { key: "role", header: "Role" },
            {
              key: "enabled",
              header: "Status",
              render: (r) => <StatusBadge label={r.enabled ? "ENABLED" : "DISABLED"} tone={r.enabled ? "success" : "danger"} />,
            },
            {
              key: "toggle",
              header: "Action",
              render: (r) => (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => toggleStatusMut.mutate({ id: String(r.id), enabled: !r.enabled })}
                >
                  {r.enabled ? "Disable" : "Enable"}
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <Card title="Recent Security & Auth Audit Events">
        <DataTable
          rows={(auditQuery.data ?? []) as unknown as Record<string, unknown>[]}
          columns={[
            { key: "seq", header: "Seq" },
            { key: "actor_id", header: "Actor" },
            { key: "action", header: "Action" },
            { key: "decision", header: "Decision" },
            { key: "reason", header: "Reason" },
          ]}
        />
      </Card>
    </div>
  );
}
