import { API_BASE_URL } from "../services/api";
import { useAuth } from "../app/AuthContext";
import { Button, Card, StatusBadge } from "../components/ui";

export function SettingsPage() {
  const { theme, toggleTheme, reducedMotion, toggleReducedMotion } = useAuth();

  return (
    <div className="space-y-5">
      <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 dark:text-white">Settings, Accessibility & Documentation</h1>

      <Card title="Display & Accessibility Preferences">
        <div className="flex flex-wrap gap-4 items-center text-xs">
          <Button variant="secondary" onClick={toggleTheme}>
            Theme: {theme === "dark" ? "Dark (Default)" : "Light"}
          </Button>
          <Button variant="secondary" onClick={toggleReducedMotion}>
            Reduced Motion: {reducedMotion ? "ON" : "OFF"}
          </Button>
        </div>
      </Card>

      <Card title="Backend Connection & Security Disclosures">
        <div className="space-y-2 text-xs text-slate-600 dark:text-slate-300">
          <div>
            Backend API Base URL: <code className="font-mono text-teal-300">{API_BASE_URL}</code>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            <StatusBadge label="OFFLINE-FIRST" tone="success" />
            <StatusBadge label="ZERO AI/ML" tone="info" />
            <StatusBadge label="NODES: SIMULATED" tone="violet" />
            <StatusBadge label="FORWARD SECRECY: NOT_ESTABLISHED" tone="warning" />
          </div>
          <ul className="list-disc pl-5 pt-2 space-y-1 text-slate-500">
            <li>Simulated nodes are local SQLite-backed logical nodes, not physical distributed consensus.</li>
            <li>Local KeyMaterialStore is a development key store, not a hardware HSM.</li>
            <li>No session tokens or secrets are persisted in browser localStorage.</li>
          </ul>
        </div>
      </Card>
    </div>
  );
}
