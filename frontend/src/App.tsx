import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./app/AuthContext";
import { ThemeProvider } from "./app/ThemeContext";
import { ConsoleLayout } from "./components/Layout";
import { ToastProvider } from "./components/ui";
import { AuditPage } from "./pages/AuditPage";
import { AuthPortalPage } from "./pages/AuthPortalPage";
import { BenchmarksPage } from "./pages/BenchmarksPage";
import { DataLabPage } from "./pages/DataLabPage";
import { DetectorPage } from "./pages/DetectorPage";
import { DevicesPage } from "./pages/DevicesPage";
import { IdentityAccessPage } from "./pages/IdentityAccessPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { KeysPage } from "./pages/KeysPage";
import { LandingPage } from "./pages/LandingPage";
import { MessagingPage } from "./pages/MessagingPage";
import { NodesPage } from "./pages/NodesPage";
import { OverviewPage } from "./pages/OverviewPage";
import {
  AccessDeniedPage,
  AdminDashboardPage,
  EmployeeDashboardPage,
  RequireAuth,
  RequireRole,
  UserDashboardPage,
} from "./pages/RoleDashboards";
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
        <Route path="/login" element={<AuthPortalPage />} />
        <Route path="/auth" element={<AuthPortalPage />} />
        <Route path="/access-denied" element={<AccessDeniedPage />} />
        <Route
          path="/dashboard/user"
          element={
            <RequireRole allowedRoles={["User", "Employee", "Admin"]}>
              <UserDashboardPage />
            </RequireRole>
          }
        />
        <Route
          path="/dashboard/employee"
          element={
            <RequireRole allowedRoles={["Employee", "Admin"]}>
              <EmployeeDashboardPage />
            </RequireRole>
          }
        />
        <Route
          path="/dashboard/admin"
          element={
            <RequireRole allowedRoles={["Admin"]}>
              <AdminDashboardPage />
            </RequireRole>
          }
        />
        <Route path="/overview" element={<RequireAuth><OverviewPage /></RequireAuth>} />
        <Route path="/identities" element={<RequireAuth><IdentityAccessPage /></RequireAuth>} />
        <Route path="/devices" element={<RequireAuth><DevicesPage /></RequireAuth>} />
        <Route path="/vault" element={<RequireAuth><VaultPage /></RequireAuth>} />
        <Route path="/keys" element={<RequireAuth><KeysPage /></RequireAuth>} />
        <Route path="/nodes" element={<RequireAuth><NodesPage /></RequireAuth>} />
        <Route path="/incidents" element={<RequireAuth><IncidentsPage /></RequireAuth>} />
        <Route path="/detector" element={<RequireAuth><DetectorPage /></RequireAuth>} />
        <Route path="/messaging" element={<RequireAuth><MessagingPage /></RequireAuth>} />
        <Route path="/audit" element={<RequireAuth><AuditPage /></RequireAuth>} />
        <Route path="/datalab" element={<RequireAuth><DataLabPage /></RequireAuth>} />
        <Route path="/security-integrity" element={<RequireAuth><SecurityIntegrityPage /></RequireAuth>} />
        <Route path="/benchmarks" element={<RequireAuth><BenchmarksPage /></RequireAuth>} />
        <Route path="/scenarios" element={<RequireAuth><ScenariosPage /></RequireAuth>} />
        <Route path="/scorecard" element={<RequireAuth><ScorecardPage /></RequireAuth>} />
        <Route path="/settings" element={<RequireAuth><SettingsPage /></RequireAuth>} />
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
