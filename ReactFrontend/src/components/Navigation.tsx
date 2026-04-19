import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import {
  Upload,
  FileText,
  LayoutDashboard,
  Settings,
  Activity,
  LogOut,
} from "lucide-react";

export default function Navigation() {
  const { user, role, signOut } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await signOut();
    navigate("/login");
  };

  const isActive = (path: string) =>
    location.pathname === path
      ? "bg-teal-50 text-teal-700 border-teal-200"
      : "text-slate-600 hover:bg-slate-50 hover:text-slate-900 border-transparent";

  const analystLinks = [
    { path: "/dashboard", label: "Upload", icon: Upload },
    { path: "/reports", label: "Reports", icon: FileText },
  ];

  const adminLinks = [
    { path: "/admin/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { path: "/admin/settings", label: "Settings", icon: Settings },
    { path: "/admin/activity-log", label: "Activity Log", icon: Activity },
  ];

  const links = role === "admin" ? adminLinks : analystLinks;

  return (
    <nav className="bg-white border-b border-slate-200 shadow-sm">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-2">
            <div className="w-9 h-9 rounded-full bg-gradient-to-br from-teal-600 to-teal-700 flex items-center justify-center">
              <span className="text-white font-bold text-sm">DS</span>
            </div>
            <span className="text-lg font-semibold text-slate-900">
              MalDoc Detector
            </span>
          </div>

          <div className="flex items-center gap-1">
            {links.map((link) => (
              <Link
                key={link.path}
                to={link.path}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${isActive(link.path)}`}
              >
                <link.icon className="w-4 h-4" />
                {link.label}
              </Link>
            ))}
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm font-medium text-slate-700">
                {user?.email}
              </p>
              <p className="text-xs text-slate-500 capitalize">{role}</p>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-1 text-sm text-slate-500 hover:text-red-600 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}
