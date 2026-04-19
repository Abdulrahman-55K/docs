import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { BarChart, TrendingUp, AlertTriangle, CheckCircle, Shield, FileText } from "lucide-react";
import Navigation from "../components/Navigation";
import { apiGet } from "../lib/api";

export default function AdminDashboard() {
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchMetrics = async () => {
      const { data } = await apiGet("/admin-panel/dashboard/");
      if (data) setMetrics(data);
      setLoading(false);
    };
    fetchMetrics();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Navigation />
        <div className="flex items-center justify-center py-20">
          <p className="text-slate-500">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  const stats = metrics || {};

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">
            Admin Dashboard
          </h1>
          <p className="text-slate-600">
            System monitoring and performance metrics
          </p>
        </div>

        {/* Metric cards */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-8">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">Today's Scans</p>
              <BarChart className="w-5 h-5 text-teal-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">
              {stats.today_scans || 0}
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">Total Scans</p>
              <TrendingUp className="w-5 h-5 text-blue-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">
              {stats.total_scans || 0}
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">Errors Today</p>
              <AlertTriangle className="w-5 h-5 text-red-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">
              {stats.errors_today || 0}
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">ML Success</p>
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">
              {stats.ml_success_rate || 0}%
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
            <div className="flex items-start justify-between mb-3">
              <p className="text-sm font-medium text-slate-600">VT Success</p>
              <Shield className="w-5 h-5 text-purple-600" />
            </div>
            <p className="text-3xl font-bold text-slate-900">
              {stats.vt_success_rate || 0}%
            </p>
          </div>
        </div>

        {/* Recent reports */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">
            Recent Reports
          </h2>
          {stats.recent_reports && stats.recent_reports.length > 0 ? (
            <div className="space-y-3">
              {stats.recent_reports.map((report: any) => (
                <div
                  key={report.id}
                  onClick={() => navigate(`/reports/${report.id}`)}
                  className="flex items-center justify-between p-3 bg-slate-50 rounded-lg hover:bg-slate-100 cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <FileText className="w-5 h-5 text-slate-400" />
                    <div>
                      <p className="font-medium text-sm text-slate-900">
                        {report.filename}
                      </p>
                      <p className="text-xs text-slate-500">
                        {new Date(report.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <span
                    className={`text-xs px-2 py-1 rounded font-medium ${
                      report.banner === "clean"
                        ? "bg-green-100 text-green-700"
                        : report.banner === "suspicious"
                        ? "bg-amber-100 text-amber-700"
                        : report.banner === "malicious"
                        ? "bg-red-100 text-red-700"
                        : "bg-blue-100 text-blue-700"
                    }`}
                  >
                    {report.banner?.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No reports yet.</p>
          )}
        </div>
      </div>
    </div>
  );
}
