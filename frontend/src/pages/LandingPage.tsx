import { Link } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  Fingerprint,
  KeyRound,
  Lock,
  Moon,
  Network,
  ShieldCheck,
  Sun,
} from "lucide-react";
import { StatusBadge } from "../components/ui";
import { useTheme } from "../app/ThemeContext";
import AeroShards from "./AeroShards";
import DitherVeil from "./DitherVeil";

export function LandingPage() {
  const { isDark, toggleTheme } = useTheme();
  return (
    <div className="min-h-screen bg-white dark:bg-[#080b0e] text-slate-900 dark:text-slate-100 flex flex-col">
      <header className="border-b border-slate-200 dark:border-[#1c242d] bg-white/95 dark:bg-[#0b0f13]/95 backdrop-blur px-6 py-4 flex items-center justify-between max-w-6xl w-full mx-auto">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
          <span className="font-bold tracking-wider text-base text-slate-900 dark:text-slate-100">Q-SHIELD</span>
          <StatusBadge label="TRACK 4 PROTOTYPE" tone="info" />
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-300 dark:border-[#26313d] text-xs font-mono text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#141b22]"
          >
            {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-violet-600" />}
            <span>{isDark ? "Light" : "Dark"}</span>
          </button>
          <Link to="/login" className="text-xs font-mono text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white">
            Sign In
          </Link>
          <Link
            to="/auth"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-700 text-xs font-medium text-white shadow-sm"
          >
            Role Auth Portal <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 space-y-14 relative">
        {/* AeroShards Interactive Background */}
        <div
          style={{ width: "100%", height: "600px", position: "absolute", top: 0, left: 0, zIndex: 0 }}
          className="pointer-events-none overflow-hidden rounded-xl"
        >
          <div style={{ width: "100%", height: "600px", position: "relative" }}>
            <AeroShards
              shardColor="#896ABD"
              accentColor="#A855F7"
              placement="full"
              material="glass"
              markers="plus"
              count={1300}
              depthOfField={0.75}
              vignette={0.3}
              mouseInteraction
              pulseOnClick
              holdToGather
              lightMode={false}
              shardSize={1}
              spread={1}
              twist={1}
              billow={1}
              speed={1}
              scale={1}
              glow={0.35}
              grain={0.06}
              intro
              mouseStrength={0.6}
              parallax={0.5}
              paused={false}
            />
          </div>
        </div>

        {/* Hero Section with DitherVeil */}
        <section className="grid lg:grid-cols-12 gap-8 items-center relative z-10">
          <div className="lg:col-span-6 space-y-5">
            <div className="flex flex-wrap gap-2">
              <StatusBadge label="PROOF-CARRYING TRUST CHANGES" tone="violet" />
              <StatusBadge label="OFFLINE-FIRST · ZERO AI/ML" tone="success" />
            </div>
            <h1 className="text-4xl md:text-5xl font-bold tracking-tight text-slate-900 dark:text-white leading-tight">
              Trust changes. <span className="text-emerald-600 dark:text-emerald-400">Security follows.</span>
            </h1>
            <p className="text-slate-600 dark:text-slate-300 text-base leading-relaxed">
              Q-SHIELD is an offline-first, CPU-first quantum-ready trust and revocation control plane
              built for Yugaantar DevForge Track 4. Every device revocation, key rotation, and
              replacement enrolment is enforced through a 9-step fail-closed policy gate, verified
              cryptographically, and backed by hash-chained audit receipts.
            </p>
            <div className="flex flex-wrap gap-3 pt-1">
              <Link
                to="/login"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md bg-emerald-600 hover:bg-emerald-700 text-sm font-medium text-white shadow-sm"
              >
                Sign In to Console <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                to="/auth"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md bg-slate-100 dark:bg-[#141b22] hover:bg-slate-200 dark:hover:bg-[#1c242d] text-sm font-medium text-slate-800 dark:text-slate-100 border border-slate-300 dark:border-[#26313d]"
              >
                Role-Based Verification
              </Link>
            </div>
          </div>

          <div className="lg:col-span-6 rounded-xl overflow-hidden border border-slate-200 dark:border-[#1c242d] shadow-sm">
            <div style={{ width: "100%", height: "460px", position: "relative" }}>
              <DitherVeil
                src="https://images.unsplash.com/photo-1737071371043-761e02b1ef95?q=80&w=1400&auto=format&fit=crop"
                pattern="floyd"
                pixelSize={2}
                inkColor="#120f17"
                paperColor="#f4f1ea"
                revealRadius={200}
                softness={0.6}
                linger={1}
                fit="contain"
                rimColor="#a78bfa"
                palette="duotone"
                levels={2}
                contrast={1.15}
                brightness={0}
                rim={0}
                reverse={false}
                wander={false}
                clickBurst
              />
            </div>
          </div>
        </section>

        {/* Verified Track 4 Metrics Strip */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4 relative z-10">
          <div className="p-4 rounded-lg border border-slate-200 dark:border-[#1c242d] bg-slate-50 dark:bg-[#0d1218]">
            <div className="text-[11px] font-mono text-slate-500">SECURITY ASSESSMENT</div>
            <div className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">18 / 18 PASS</div>
            <div className="text-xs text-slate-500 mt-0.5">Salted scrypt, RBAC, AEAD, FIM</div>
          </div>
          <div className="p-4 rounded-lg border border-slate-200 dark:border-[#1c242d] bg-slate-50 dark:bg-[#0d1218]">
            <div className="text-[11px] font-mono text-slate-500">OFFICIAL TRACK 4 VALIDATOR</div>
            <div className="text-2xl font-bold font-mono text-cyan-600 dark:text-cyan-400 mt-1">21 / 21 PASS</div>
            <div className="text-xs text-slate-500 mt-0.5">track4_service.py contract</div>
          </div>
          <div className="p-4 rounded-lg border border-slate-200 dark:border-[#1c242d] bg-slate-50 dark:bg-[#0d1218]">
            <div className="text-[11px] font-mono text-slate-500">BACKEND &amp; ADAPTER TESTS</div>
            <div className="text-2xl font-bold font-mono text-violet-600 dark:text-violet-400 mt-1">53 + 9 PASS</div>
            <div className="text-xs text-slate-500 mt-0.5">Isolated SQLite + Alembic 0010</div>
          </div>
          <div className="p-4 rounded-lg border border-slate-200 dark:border-[#1c242d] bg-slate-50 dark:bg-[#0d1218]">
            <div className="text-[11px] font-mono text-slate-500">AI / ML DEPENDENCIES</div>
            <div className="text-2xl font-bold font-mono text-emerald-600 dark:text-emerald-400 mt-1">0 (ZERO)</div>
            <div className="text-xs text-slate-500 mt-0.5">100% deterministic rules &amp; crypto</div>
          </div>
        </section>

        {/* 6 Core Subsystems */}
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">Core Control Plane Architecture</h2>
            <span className="text-xs font-mono text-slate-500">17 Operator Pages · 14 Scenarios</span>
          </div>
          <div className="grid md:grid-cols-3 gap-5">
            <div className="p-5 rounded-lg bg-slate-50 dark:bg-[#0d1218] border border-slate-200 dark:border-[#1c242d] space-y-2">
              <Lock className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">9-Step Fail-Closed Vault</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Server-side zero-trust authorization + AES-256-GCM envelope encryption + ML-KEM-768
                hybrid key encapsulation with zero plaintext leakage on deny.
              </p>
            </div>
            <div className="p-5 rounded-lg bg-slate-50 dark:bg-[#0d1218] border border-slate-200 dark:border-[#1c242d] space-y-2">
              <Network className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Simulated Node Convergence</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                3&ndash;7 SQLite-backed simulated nodes with monotonic revocation tombstones, partition
                fault injection, honest NOT CONVERGED reporting, and p50/p95/p99 latency tracking.
              </p>
            </div>
            <div className="p-5 rounded-lg bg-slate-50 dark:bg-[#0d1218] border border-slate-200 dark:border-[#1c242d] space-y-2">
              <KeyRound className="w-5 h-5 text-violet-600 dark:text-violet-400" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Crash-Safe Key Rotation</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Integrity-hashed rotation journal across 7 crash injection points plus HMAC-verified
                backup manifests and SHA-256 hash-chained audit evidence.
              </p>
            </div>
            <div className="p-5 rounded-lg bg-slate-50 dark:bg-[#0d1218] border border-slate-200 dark:border-[#1c242d] space-y-2">
              <Activity className="w-5 h-5 text-rose-500" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Lateral Movement Detector</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Deterministic rule engine with clock-offset tolerance, reorder windows, and
                time-aware directed service-hop graphs (no ML/LLM runtime).
              </p>
            </div>
            <div className="p-5 rounded-lg bg-slate-50 dark:bg-[#0d1218] border border-slate-200 dark:border-[#1c242d] space-y-2">
              <Fingerprint className="w-5 h-5 text-amber-500" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Identity Assurance &amp; FIM</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                WebAuthn/FIDO2 public-key challenge verification, freshness policies, and SHA-256
                System File Integrity Monitoring with governed baseline updates.
              </p>
            </div>
            <div className="p-5 rounded-lg bg-slate-50 dark:bg-[#0d1218] border border-slate-200 dark:border-[#1c242d] space-y-2">
              <Database className="w-5 h-5 text-sky-500" />
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">GB-Scale Data Lab &amp; Worker</h3>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Resumable chunked uploads, streaming SHA-256, Merkle tree verification, safe archive
                inspection, X.509 parsing, and 24/7 SQLite job recovery.
              </p>
            </div>
          </div>
        </section>

        {/* Honest Threat Model Disclosures */}
        <section className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5 space-y-2">
          <div className="flex items-center gap-2 text-xs font-mono font-semibold text-amber-700 dark:text-amber-300">
            <Cpu className="w-4 h-4" />
            <span>HONEST THREAT MODEL &amp; SANDBOX DISCLOSURES</span>
          </div>
          <div className="grid md:grid-cols-2 gap-2 text-xs text-slate-600 dark:text-slate-300">
            <div className="flex items-start gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" />
              <span><strong>Nodes:</strong> Simulated in-process SQLite logical nodes (`sim-node-1..7`), not physical Raft/Paxos.</span>
            </div>
            <div className="flex items-start gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" />
              <span><strong>Forward Secrecy:</strong> `NOT_ESTABLISHED` (no per-message ephemeral DH/KEM ratchet).</span>
            </div>
            <div className="flex items-start gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" />
              <span><strong>Post-Quantum Signatures:</strong> `ML-DSA` is `NOT IMPLEMENTED`; integrity uses HMAC-SHA-256.</span>
            </div>
            <div className="flex items-start gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 mt-0.5 shrink-0" />
              <span><strong>Key Store &amp; Biometrics:</strong> Local dev KeyMaterialStore (not HSM); camera demo is non-authenticating.</span>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
