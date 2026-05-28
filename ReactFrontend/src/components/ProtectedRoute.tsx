import { Navigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { getGuestToken } from "../lib/api";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireAdmin?: boolean;
  allowGuest?: boolean; // if true, unauthenticated users with a guest token can access
}

export default function ProtectedRoute({
  children,
  requireAdmin = false,
  allowGuest = false,
}: ProtectedRouteProps) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="text-slate-500 text-lg">Loading...</div>
      </div>
    );
  }

  // Guest access: route allows it and the browser has a guest token
  if (!user && allowGuest && getGuestToken()) {
    return <>{children}</>;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (requireAdmin && user.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}
