import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, DataTable, ErrorBanner, StatusBadge, useToast } from "../components/ui";

export function MessagingPage() {
  const qc = useQueryClient();
  const { session } = useAuth();
  const { push } = useToast();

  const messages = useQuery({ queryKey: ["messages"], queryFn: api.listMessages });
  const secStatus = useQuery({ queryKey: ["msg-sec-status"], queryFn: api.messagingSecurityStatus });

  const [recipientId, setRecipientId] = useState("bob");
  const [plaintext, setPlaintext] = useState("");
  const [pendingMode, setPendingMode] = useState(false);
  const [resumptionToken, setResumptionToken] = useState<Record<string, string> | null>(null);
  const [resumeStatus, setResumeStatus] = useState<string | null>(null);

  const sendMut = useMutation({
    mutationFn: () =>
      api.sendMessage({
        sender_id: session?.actorId ?? "alice",
        recipient_id: recipientId,
        session_id: session?.sessionId ?? "missing",
        plaintext,
        simulate_pending_recovery: pendingMode,
      }),
    onSuccess: (m) => {
      qc.invalidateQueries({ queryKey: ["messages"] });
      setPlaintext("");
      push(`Message seq #${m.sequence} encrypted (${m.status})`, "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const deliverMut = useMutation({
    mutationFn: ({ id, rec }: { id: string; rec: string }) => api.deliverMessage(id, { recipient_id: rec }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["messages"] });
      push(`Delivered #${res.message_id.slice(0, 8)}: "${res.plaintext}"`, "success");
    },
    onError: (e: Error) => push(`Delivery rejected: ${e.message}`, "error"),
  });

  const recoverMut = useMutation({
    mutationFn: () =>
      api.recoverMessages({ session_id: session?.sessionId ?? "missing", recipient_id: recipientId }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["messages"] });
      push(`Recovered ${res.delivered_count} messages (${res.failed_count} failed)`, "info");
    },
  });

  const issueTokenMut = useMutation({
    mutationFn: () =>
      api.issueResumptionToken({
        session_id: session?.sessionId ?? "missing",
        actor_id: session?.actorId ?? "alice",
        peer_id: session?.peerId ?? recipientId,
      }),
    onSuccess: (res) => {
      setResumptionToken({
        nonce_b64: res.nonce_b64,
        ciphertext_b64: res.ciphertext_b64,
        tag_b64: res.tag_b64,
      });
      setResumeStatus(`Issued AEAD token (${res.token_id.slice(0, 8)}...) bound to peer=${session?.peerId ?? recipientId}`);
      push("Peer-bound session resumption token issued", "success");
    },
    onError: (e: Error) => push(e.message, "error"),
  });

  const resumeMut = useMutation({
    mutationFn: (overridePeer?: string) => {
      if (!resumptionToken) throw new Error("Issue a resumption token first");
      return api.resumeSession({
        token_bundle: resumptionToken,
        actor_id: session?.actorId ?? "alice",
        peer_id: overridePeer ?? session?.peerId ?? recipientId,
      });
    },
    onSuccess: () => {
      setResumeStatus("Session resumed cleanly for bound peer");
      push("Session resumed cleanly", "success");
    },
    onError: (e: Error) => {
      setResumeStatus(`Rejected: ${e.message}`);
      push(`Resumption rejected: ${e.message}`, "info");
    },
  });

  const msgList = messages.data ?? [];
  const statusMap = new Map<string, number>();
  for (const m of msgList) {
    statusMap.set(m.status, (statusMap.get(m.status) ?? 0) + 1);
  }
  const msgChart = Array.from(statusMap.entries()).map(([status, count]) => ({ status, count }));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Secure Messaging Lab (AEAD + Replay Ledger)</h1>
        <StatusBadge
          label={`Forward Secrecy: ${secStatus.data?.forward_secrecy ?? "NOT_ESTABLISHED"}`}
          tone="warning"
        />
      </div>

      {secStatus.data && (
        <div className="p-3 rounded-md bg-amber-50 border border-amber-500/30 text-xs text-amber-800">
          {secStatus.data.forward_secrecy_note}
        </div>
      )}

      <div className="grid lg:grid-cols-3 gap-4">
        <Card
          title="Compose Synthetic AEAD Message"
          subtitle="Binds sender, recipient, session, key version, and expiry in AAD"
          className="lg:col-span-2"
        >
          <div className="grid md:grid-cols-3 gap-3">
            <input
              type="text"
              value={recipientId}
              onChange={(e) => setRecipientId(e.target.value)}
              placeholder="Recipient Actor ID"
              className="rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
            />
            <input
              type="text"
              value={plaintext}
              onChange={(e) => setPlaintext(e.target.value)}
              placeholder="Synthetic Message Body"
              className="rounded bg-slate-50 dark:bg-[#131a21] border border-slate-200 dark:border-[#1f2933] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 md:col-span-2"
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-3 pt-3">
            <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">
              <input type="checkbox" checked={pendingMode} onChange={(e) => setPendingMode(e.target.checked)} />
              <span>Simulate out-of-order / pending recovery</span>
            </label>
            <div className="flex gap-2">
              <Button variant="secondary" onClick={() => recoverMut.mutate()}>
                Recover Pending
              </Button>
              <Button onClick={() => sendMut.mutate()} disabled={!plaintext || sendMut.isPending}>
                Encrypt &amp; Send
              </Button>
            </div>
          </div>
          {sendMut.isError && <div className="mt-3"><ErrorBanner message={(sendMut.error as Error).message} /></div>}
        </Card>

        <Card title="Delivery & Replay Status Graph" subtitle="Live message outcomes">
          <div className="h-36">
            {msgChart.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">No messages yet</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={msgChart}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
                  <XAxis dataKey="status" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: "#ffffff", borderColor: "#e2e8f0", fontSize: 11 }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {msgChart.map((m) => (
                      <Cell key={m.status} fill={m.status === "delivered" ? "#10b981" : "#f97316"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <Card
        title="Peer-Bound Session Resumption"
        subtitle="AEAD resumption tokens fail closed on cross-peer misuse or replay"
        action={
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => issueTokenMut.mutate()}>
              Issue Token
            </Button>
            <Button size="sm" disabled={!resumptionToken} onClick={() => resumeMut.mutate(undefined)}>
              Resume (Valid Peer)
            </Button>
            <Button size="sm" variant="danger" disabled={!resumptionToken} onClick={() => resumeMut.mutate("eve")}>
              Test Cross-Peer Reject
            </Button>
          </div>
        }
      >
        <div className="text-xs font-mono text-slate-600 dark:text-slate-300">
          {resumeStatus ?? "Issue a session resumption token from an active session to test peer-binding."}
        </div>
      </Card>

      <Card title="Message Ledger">
        <DataTable
          rows={msgList as unknown as Record<string, unknown>[]}
          columns={[
            { key: "sequence", header: "Seq" },
            { key: "sender_id", header: "Sender" },
            { key: "recipient_id", header: "Recipient" },
            {
              key: "status",
              header: "Status",
              render: (r) => (
                <StatusBadge
                  label={String(r.status)}
                  tone={
                    r.status === "delivered"
                      ? "success"
                      : r.status === "rejected/replayed" || r.status === "failed"
                      ? "danger"
                      : "info"
                  }
                />
              ),
            },
            {
              key: "actions",
              header: "Actions",
              render: (r) => (
                <div className="flex gap-1.5">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => deliverMut.mutate({ id: String(r.id), rec: String(r.recipient_id) })}
                  >
                    Deliver
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    onClick={() => deliverMut.mutate({ id: String(r.id), rec: "eve" })}
                  >
                    Test Wrong Recipient
                  </Button>
                </div>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
