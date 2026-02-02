import React, { useState } from 'react';
import { Filter, Search, Clock, User, Activity } from 'lucide-react';
import Navigation from '../components/Navigation';

interface ActivityLogEntry {
  id: string;
  user: string;
  role: 'admin' | 'analyst';
  action: string;
  target: string;
  createdAt: string;
}

const MOCK_ACTIVITY: ActivityLogEntry[] = [
  {
    id: '1',
    user: 'sara.admin@example.com',
    role: 'admin',
    action: 'Successful login',
    target: 'Signed in from 192.168.1.20',
    createdAt: '2024-11-13 10:32',
  },
  {
    id: '2',
    user: 'sara.admin@example.com',
    role: 'admin',
    action: 'Failed login',
    target: 'Wrong password from 192.168.1.20',
    createdAt: '2024-11-13 10:29',
  },
  {
    id: '3',
    user: 'new.analyst@example.com',
    role: 'analyst',
    action: 'Signup',
    target: 'Created new analyst account',
    createdAt: '2024-11-13 09:15',
  },
  {
    id: '4',
    user: 'ali.analyst@example.com',
    role: 'analyst',
    action: 'Requested password reset',
    target: 'Reset email sent',
    createdAt: '2024-11-13 08:47',
  },
  {
    id: '5',
    user: 'mohammed.analyst@example.com',
    role: 'analyst',
    action: 'Uploaded document',
    target: 'invoice_q4_2024.pdf',
    createdAt: '2024-11-13 08:21',
  },
  {
    id: '6',
    user: 'sara.admin@example.com',
    role: 'admin',
    action: 'Updated YARA rule',
    target: 'SUSP_PDF_Embedded_JS',
    createdAt: '2024-11-12 18:07',
  },
  {
    id: '7',
    user: 'sara.admin@example.com',
    role: 'admin',
    action: 'Rotated API key',
    target: 'VirusTotal',
    createdAt: '2024-11-12 17:55',
  },
];

export default function AdminActivityLog() {
  const [roleFilter, setRoleFilter] = useState<'all' | 'admin' | 'analyst'>('all');
  const [search, setSearch] = useState('');

  const filtered = MOCK_ACTIVITY.filter((entry) => {
    const matchesRole = roleFilter === 'all' || entry.role === roleFilter;
    const matchesSearch =
      !search ||
      entry.user.toLowerCase().includes(search.toLowerCase()) ||
      entry.action.toLowerCase().includes(search.toLowerCase()) ||
      entry.target.toLowerCase().includes(search.toLowerCase());
    return matchesRole && matchesSearch;
  });

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <header className="mb-10 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-4xl font-bold text-slate-900 mb-2">Activity Log</h1>
            <p className="text-lg text-slate-600">
              See who did what and when across the system
            </p>
          </div>
        </header>

        <section className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="flex-1 flex items-center gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by user, action, or resource"
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:border-transparent text-sm bg-white"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">
              Filter by role
            </span>
            <div className="inline-flex rounded-lg border border-slate-200 bg-white overflow-hidden">
              <button
                type="button"
                onClick={() => setRoleFilter('all')}
                className={`px-3 py-1.5 text-xs font-medium flex items-center gap-1 ${
                  roleFilter === 'all'
                    ? 'bg-teal-600 text-white'
                    : 'text-slate-600 hover:bg-slate-50'
                }`}
              >
                <Filter className="w-3 h-3" />
                All
              </button>
              <button
                type="button"
                onClick={() => setRoleFilter('admin')}
                className={`px-3 py-1.5 text-xs font-medium ${
                  roleFilter === 'admin'
                    ? 'bg-teal-600 text-white'
                    : 'text-slate-600 hover:bg-slate-50'
                }`}
              >
                Admin
              </button>
              <button
                type="button"
                onClick={() => setRoleFilter('analyst')}
                className={`px-3 py-1.5 text-xs font-medium ${
                  roleFilter === 'analyst'
                    ? 'bg-teal-600 text-white'
                    : 'text-slate-600 hover:bg-slate-50'
                }`}
              >
                Analyst
              </button>
            </div>
          </div>
        </section>

        <section className="bg-white rounded-xl shadow-lg border border-slate-200 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-teal-600" />
              <h2 className="text-sm font-semibold text-slate-900 uppercase tracking-wide">
                Recent Activity
              </h2>
            </div>
            <p className="text-xs text-slate-500">
              Showing {filtered.length} of {MOCK_ACTIVITY.length} events
            </p>
          </div>

          {filtered.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-slate-500">
              No activity found for the selected filters.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-slate-200 text-sm">
                <thead className="bg-slate-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                      User
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                      Action
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                      Resource
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wide">
                      When
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filtered.map((entry) => (
                    <tr key={entry.id} className="hover:bg-slate-50">
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-full bg-teal-100 flex items-center justify-center">
                            <User className="w-4 h-4 text-teal-700" />
                          </div>
                          <div>
                            <p className="font-medium text-slate-900">{entry.user}</p>
                            <p className="text-xs text-slate-500 capitalize">{entry.role}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <p className="font-medium text-slate-900">{entry.action}</p>
                      </td>
                      <td className="px-6 py-4">
                        <p className="text-slate-800">{entry.target}</p>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2 text-slate-600">
                          <Clock className="w-4 h-4" />
                          <span className="text-xs">{entry.createdAt}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

