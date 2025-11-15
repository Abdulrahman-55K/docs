import React from 'react';
import { BarChart, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react';
import Navigation from '../components/Navigation';

export default function AdminDashboard() {
  const stats = {
    todayScans: 156,
    errors: 3,
    mlSuccessRate: '94.2%',
    mlFallback: '5.8%',
    vtSuccess: '99.1%',
  };

  const recentReports = [
    {
      id: 1,
      filename: 'report_q4.pdf',
      timestamp: '2 hours ago',
      status: 'benign',
    },
    {
      id: 2,
      filename: 'analysis_v2.docx',
      timestamp: '5 hours ago',
      status: 'suspicious',
    },
    {
      id: 3,
      filename: 'document_x.xlsx',
      timestamp: '1 day ago',
      status: 'benign',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-12">
          <h1 className="text-4xl font-bold text-slate-900 mb-2">Admin Dashboard</h1>
          <p className="text-lg text-slate-600">System monitoring and performance metrics</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-12">
          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 hover:shadow-xl transition">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">Today's Scans</p>
              <BarChart className="w-5 h-5 text-teal-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">{stats.todayScans}</p>
            <p className="text-xs text-slate-500 mt-2">Last 24 hours</p>
          </div>

          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 hover:shadow-xl transition">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">Errors</p>
              <AlertTriangle className="w-5 h-5 text-red-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">{stats.errors}</p>
            <p className="text-xs text-slate-500 mt-2">Requires attention</p>
          </div>

          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 hover:shadow-xl transition">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">ML Success</p>
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">{stats.mlSuccessRate}</p>
            <p className="text-xs text-slate-500 mt-2">Classification rate</p>
          </div>

          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 hover:shadow-xl transition">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">ML Fallback</p>
              <TrendingUp className="w-5 h-5 text-amber-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">{stats.mlFallback}</p>
            <p className="text-xs text-slate-500 mt-2">Need Review</p>
          </div>

          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 hover:shadow-xl transition">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">VT Success</p>
              <CheckCircle className="w-5 h-5 text-teal-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">{stats.vtSuccess}</p>
            <p className="text-xs text-slate-500 mt-2">API success rate</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 bg-white rounded-xl shadow-lg border border-slate-200 p-8">
            <h2 className="text-2xl font-bold text-slate-900 mb-6">Recent Scan Reports</h2>
            <div className="space-y-4">
              {recentReports.map((report) => (
                <div
                  key={report.id}
                  className="flex items-center justify-between p-4 border border-slate-200 rounded-lg hover:bg-slate-50 transition"
                >
                  <div>
                    <p className="font-medium text-slate-900">{report.filename}</p>
                    <p className="text-sm text-slate-600">{report.timestamp}</p>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-sm font-semibold ${
                      report.status === 'benign'
                        ? 'bg-green-100 text-green-800'
                        : 'bg-amber-100 text-amber-800'
                    }`}
                  >
                    {report.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-gradient-to-br from-teal-50 to-teal-100 rounded-xl p-6 border border-teal-200">
              <h3 className="font-semibold text-slate-900 mb-3">Quick Actions</h3>
              <div className="space-y-2">
                <a
                  href="/admin/settings"
                  className="block px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition text-center"
                >
                  Manage Rules
                </a>
                <a
                  href="/admin/settings"
                  className="block px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition text-center"
                >
                  Settings
                </a>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6">
              <h3 className="font-semibold text-slate-900 mb-3">System Status</h3>
              <div className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">Database</span>
                  <span className="text-green-600 font-medium">Healthy</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">ML Service</span>
                  <span className="text-green-600 font-medium">Online</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-600">VirusTotal API</span>
                  <span className="text-green-600 font-medium">Connected</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
