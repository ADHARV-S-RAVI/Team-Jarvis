import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./app/AuthContext";
import { ThemeProvider } from "./app/ThemeContext";
import { ConsoleLayout } from "./components/Layout";
import { ToastProvider } from "./components/ui";
import { AuditPage } from "./pages/AuditPage";
import { BenchmarksPage } from "./pages/BenchmarksPage";
import { DataLabPage } from "./pages/DataLabPage";
import { DemoLoginPage } from "./pages/DemoLoginPage";
import { DetectorPage } from "./pages/DetectorPage";
import { DevicesPage } from "./pages/DevicesPage";
import { IdentityAccessPage } from "./pages/IdentityAccessPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { KeysPage } from "./pages/KeysPage";
import { LandingPage } from "./pages/LandingPage";
import { MessagingPage } from "./pages/MessagingPage";
import { NodesPage } from "./pages/NodesPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ScenariosPage } from "./pages/ScenariosPage";
import { ScorecardPage } from "./pages/ScorecardPage";
import { SecurityIntegrityPage } from "./pages/SecurityIntegrityPage";
import { SettingsPage } from "./pages/SettingsPage";
import { VaultPage } from "./pages/VaultPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route element={<ConsoleLayout />}>
        <Route path="/login" element={<DemoLoginPage />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/identities" element={<IdentityAccessPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/vault" element={<VaultPage />} />
        <Route path="/keys" element={<KeysPage />} />
        <Route path="/nodes" element={<NodesPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/detector" element={<DetectorPage />} />
        <Route path="/messaging" element={<MessagingPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/datalab" element={<DataLabPage />} />
        <Route path="/security-integrity" element={<SecurityIntegrityPage />} />
        <Route path="/benchmarks" element={<BenchmarksPage />} />
        <Route path="/scenarios" element={<ScenariosPage />} />
        <Route path="/scorecard" element={<ScorecardPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <ToastProvider>
            <BrowserRouter>
              <AppRoutes />
            </BrowserRouter>
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
