import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Menu, X, LogOut } from 'lucide-react';

export default function Navigation() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { signOut, role, switchRole, authDisabled } = useAuth();
  const navigate = useNavigate();

  const handleRoleChange = (nextRole: 'analyst' | 'admin', closeMenu?: boolean) => {
    if (!authDisabled || role === nextRole) {
      if (closeMenu) {
        setMobileMenuOpen(false);
      }
      if (authDisabled && role === nextRole) {
        navigate(nextRole === 'admin' ? '/admin/dashboard' : '/dashboard');
      }
      return;
    }

    switchRole(nextRole);
    if (closeMenu) {
      setMobileMenuOpen(false);
    }
    navigate(nextRole === 'admin' ? '/admin/dashboard' : '/dashboard');
  };

  const handleSignOut = async () => {
    await signOut();
    navigate('/login');
  };

  return (
    <nav className="bg-white border-b border-slate-200 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 hover:bg-slate-100 rounded-lg transition"
            >
              {mobileMenuOpen ? (
                <X className="w-6 h-6 text-slate-700" />
              ) : (
                <Menu className="w-6 h-6 text-slate-700" />
              )}
            </button>
            <div className="flex items-center gap-2">
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-teal-600 to-teal-700 flex items-center justify-center">
                <span className="text-white font-bold text-sm">DS</span>
              </div>
              <span className="font-semibold text-slate-900 hidden sm:inline">
                Document Scanner
              </span>
            </div>
          </div>

          <div className="hidden md:flex items-center gap-8">
            {authDisabled && (
              <div className="hidden md:flex items-center gap-2 text-xs uppercase tracking-wide text-slate-500">
                <span>Mock role:</span>
                <button
                  onClick={() => handleRoleChange('analyst')}
                  className={`px-3 py-1 rounded-lg font-semibold transition ${
                    role === 'analyst'
                      ? 'bg-teal-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  Analyst
                </button>
                <button
                  onClick={() => handleRoleChange('admin')}
                  className={`px-3 py-1 rounded-lg font-semibold transition ${
                    role === 'admin'
                      ? 'bg-teal-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  Admin
                </button>
              </div>
            )}

            {role === 'admin' ? (
              <>
                <a href="/admin/dashboard" className="text-slate-600 hover:text-teal-600 font-medium">
                  Dashboard
                </a>
                <a href="/admin/settings" className="text-slate-600 hover:text-teal-600 font-medium">
                  Settings
                </a>
              </>
            ) : (
              <>
                <a href="/dashboard" className="text-slate-600 hover:text-teal-600 font-medium">
                  Upload
                </a>
                <a href="/reports" className="text-slate-600 hover:text-teal-600 font-medium">
                  Reports
                </a>
              </>
            )}
          </div>

          <div className="flex items-center gap-4">
            <span className="text-sm text-slate-600 hidden sm:inline capitalize">{role}</span>
            <button
              onClick={handleSignOut}
              className="p-2 hover:bg-slate-100 rounded-lg transition text-slate-600 hover:text-red-600"
              title="Sign out"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
        </div>

        {mobileMenuOpen && (
          <div className="md:hidden border-t border-slate-200 py-4 space-y-3">
            {authDisabled && (
              <div className="flex items-center gap-3 px-4">
                <button
                  onClick={() => handleRoleChange('analyst', true)}
                  className={`flex-1 px-4 py-2 rounded-lg font-semibold transition ${
                    role === 'analyst'
                      ? 'bg-teal-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  Analyst
                </button>
                <button
                  onClick={() => handleRoleChange('admin', true)}
                  className={`flex-1 px-4 py-2 rounded-lg font-semibold transition ${
                    role === 'admin'
                      ? 'bg-teal-600 text-white'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  Admin
                </button>
              </div>
            )}

            {role === 'admin' ? (
              <>
                <a
                  href="/admin/dashboard"
                  className="block px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Dashboard
                </a>
                <a
                  href="/admin/settings"
                  className="block px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Settings
                </a>
              </>
            ) : (
              <>
                <a
                  href="/dashboard"
                  className="block px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Upload
                </a>
                <a
                  href="/reports"
                  className="block px-4 py-2 text-slate-600 hover:bg-slate-100 rounded-lg"
                >
                  Reports
                </a>
              </>
            )}
          </div>
        )}
      </div>
    </nav>
  );
}
