import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { FileText, Calendar, Shield, AlertTriangle, CheckCircle, Search } from "lucide-react";
import Navigation from "../components/Navigation";
import { apiGet } from "../lib/api";

interface ReportSummary {
  id: string;
  filename: string;
  upload_date: string;
  file_hash: string;
  status: string;
  score: number;
  yara_matches: number;
  vt_detections: number;
}

export default function Reports() {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    fetchReports();
  }, [statusFilter]);

  const fetchReports = async () => {
    setLoading(true);
    let endpoint = "/analysis/reports/";
    const params = new URLSearchParams();
    if (statusFilter) params.set("status", statusFilter);
    if (searchQuery) params.set("filename", searchQuery);
    if (params.toString()) endpoint += `?${params.toString()}`;

    const { data, error } = await apiGet<{ results: ReportSummary[] }>(endpoint);
    if (data) {
      setReports(data.results || []);
    }
    setLoading(false);
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchReports();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "clean":
        return "text-green-600 bg-green-50 border-green-200";
      case "suspicious":
        return "text-amber-600 bg-amber-50 border-amber-200";
      case "malicious":
        return "text-red-600 bg-red-50 border-red-200";
      case "needs_review":
        return "text-blue-600 bg-blue-50 border-blue-200";
      default:
        return "text-slate-600 bg-slate-50 border-slate-200";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "clean":
        return <CheckCircle className="w-4 h-4" />;
      case "suspicious":
        return <AlertTriangle className="w-4 h-4" />;
      case "malicious":
        return <Shield className="w-4 h-4" />;
      default:
        return <FileText className="w-4 h-4" />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">Reports</h1>
          <p className="text-slate-600">Analysis history and results</p>
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
                placeholder="Search by filename..."
                className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-teal-500 focus:border-teal-500 outline-none"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 bg-teal-600 text-white rounded-lg text-sm hover:bg-teal-700 transition-colors"
            >
              Search
            </button>
          </form>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-teal-500 outline-none"
          >
            <option value="">All statuses</option>
            <option value="clean">Clean</option>
            <option value="suspicious">Suspicious</option>
            <option value="malicious">Malicious</option>
            <option value="needs_review">Needs Review</option>
          </select>
        </div>

        {/* Reports list */}
        {loading ? (
          <div className="text-center py-12 text-slate-500">Loading reports...</div>
        ) : reports.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-slate-300 mx-auto mb-4" />
            <p className="text-slate-500">No reports found.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {reports.map((report) => (
              <div
                key={report.id}
                onClick={() => navigate(`/reports/${report.id}`)}
                className="bg-white rounded-xl shadow-sm border border-slate-200 p-5 hover:shadow-md hover:border-slate-300 transition-all cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <FileText className="w-8 h-8 text-slate-400" />
                    <div>
                      <p className="font-medium text-slate-900">
                        {report.filename}
                      </p>
                      <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {new Date(report.upload_date).toLocaleDateString()}
                        </span>
                        <span>SHA: {report.file_hash?.slice(0, 12)}...</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right text-xs text-slate-500">
                      <p>YARA: {report.yara_matches} matches</p>
                      <p>VT: {report.vt_detections} detections</p>
                    </div>
                    <div className="text-right">
                      <span
                        className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium border ${getStatusColor(report.status)}`}
                      >
                        {getStatusIcon(report.status)}
                        {report.status?.replace("_", " ").toUpperCase()}
                      </span>
                      <p className="text-xs text-slate-500 mt-1">
                        Score: {(report.score * 100).toFixed(0)}%
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
