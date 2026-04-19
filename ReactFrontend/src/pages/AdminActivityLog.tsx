import React, { useState, useEffect } from "react";
import { Filter, Search, Clock, User, Activity } from "lucide-react";
import Navigation from "../components/Navigation";
import { apiGet } from "../lib/api";

export default function AdminActivityLog() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [categoryFilter, setCategoryFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const fetchLogs = async () => {
    setLoading(true);
    let endpoint = "/admin-panel/audit-logs/";
    const params = new URLSearchParams();
    if (categoryFilter) params.set("category", categoryFilter);
    if (searchQuery) params.set("action", searchQuery);
    if (params.toString()) endpoint += `?${params.toString()}`;

    const { data } = await apiGet<{ results: any[] }>(endpoint);
    if (data) {
      setLogs(data.results || []);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchLogs();
  }, [categoryFilter]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchLogs();
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "auth":
        return "bg-blue-100 text-blue-700";
      case "upload":
        return "bg-teal-100 text-teal-700";
      case "analysis":
        return "bg-purple-100 text-purple-700";
      case "config":
        return "bg-amber-100 text-amber-700";
      case "admin":
        return "bg-red-100 text-red-700";
      default:
        return "bg-slate-100 text-slate-700";
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">
            Activity Log
          </h1>
          <p className="text-slate-600">System audit trail</p>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-4 mb-6 flex flex-wrap gap-4 items-center">
          <form onSubmit={handleSearch} className="flex-1 flex gap-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by action..."
                className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-teal-500 outline-none"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 bg-teal-600 text-white rounded-lg text-sm hover:bg-teal-700"
            >
              Search
            </button>
          </form>

          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-teal-500 outline-none"
          >
            <option value="">All categories</option>
            <option value="auth">Authentication</option>
            <option value="upload">Upload</option>
            <option value="analysis">Analysis</option>
            <option value="config">Configuration</option>
            <option value="admin">Admin</option>
          </select>
        </div>

        {/* Log entries */}
        {loading ? (
          <div className="text-center py-12 text-slate-500">Loading logs...</div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12">
            <Activity className="w-12 h-12 text-slate-300 mx-auto mb-4" />
            <p className="text-slate-500">No log entries found.</p>
          </div>
        ) : (
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="divide-y divide-slate-100">
              {logs.map((log) => (
                <div
                  key={log.id}
                  className="p-4 hover:bg-slate-50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">
                        <User className="w-4 h-4 text-slate-400" />
                      </div>
                      <div>
                        <p className="font-medium text-sm text-slate-900">
                          {log.action}
                        </p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-xs text-slate-500">
                            {log.user_email}
                          </span>
                          <span
                            className={`text-xs px-2 py-0.5 rounded font-medium ${getCategoryColor(
                              log.category
                            )}`}
                          >
                            {log.category}
                          </span>
                          {log.ip_address && (
                            <span className="text-xs text-slate-400">
                              IP: {log.ip_address}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <span className="text-xs text-slate-500 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(log.occurred_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
