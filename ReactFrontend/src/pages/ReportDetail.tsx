import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  FileText, Calendar, Shield, Download, ArrowLeft,
  CheckCircle, AlertTriangle, TrendingUp, Zap,
} from "lucide-react";
import Navigation from "../components/Navigation";
import { apiGet } from "../lib/api";

interface ReportData {
  id: string;
  file: {
    id: string;
    sha256: string;
    original_name: string;
    mime: string;
    file_size: number;
    status: string;
    created_at: string;
  };
  ml_label: string;
  ml_score: number;
  vt_summary_json: any;
  banner: string;
  top_features: any[];
  yara_hits: any[];
  cluster: any;
  created_at: string;
}

export default function ReportDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchReport = async () => {
      const { data, error: fetchError } = await apiGet<ReportData>(
        `/analysis/reports/${id}/`
      );
      if (data) {
        setReport(data);
      } else {
        setError(fetchError || "Report not found");
      }
      setLoading(false);
    };
    fetchReport();
  }, [id]);

  const handleExport = (format: string) => {
    const token = localStorage.getItem("access_token");
    if (!token) return;

    fetch(`http://127.0.0.1:8000/api/v1/analysis/reports/${id}/export/?format=${format}`, {
      headers: { "Authorization": `Bearer ${token}` },
    })
      .then(res => res.blob())
      .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `report_${report?.file.sha256?.slice(0, 12)}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      })
      .catch(err => console.error("Export error:", err));
  };

  const getBannerStyle = (banner: string) => {
    switch (banner) {
      case "clean":
        return "bg-green-100 text-green-800 border-green-300";
      case "suspicious":
        return "bg-amber-100 text-amber-800 border-amber-300";
      case "malicious":
        return "bg-red-100 text-red-800 border-red-300";
      default:
        return "bg-blue-100 text-blue-800 border-blue-300";
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Navigation />
        <div className="flex items-center justify-center py-20">
          <p className="text-slate-500">Loading report...</p>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Navigation />
        <div className="max-w-4xl mx-auto px-4 py-12">
          <p className="text-red-600">{error || "Report not found"}</p>
          <button
            onClick={() => navigate("/reports")}
            className="mt-4 text-teal-600 hover:text-teal-700"
          >
            ← Back to reports
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate("/reports")}
              className="p-2 hover:bg-slate-200 rounded-lg transition-colors"
            >
              <ArrowLeft className="w-5 h-5 text-slate-600" />
            </button>
            <div>
              <h1 className="text-2xl font-bold text-slate-900">
                {report.file.original_name}
              </h1>
              <p className="text-sm text-slate-500 flex items-center gap-2 mt-1">
                <Calendar className="w-4 h-4" />
                {new Date(report.file.created_at).toLocaleString()}
              </p>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => handleExport("json")}
              className="flex items-center gap-2 px-4 py-2 border border-slate-300 rounded-lg text-sm hover:bg-slate-50 transition-colors"
            >
              <Download className="w-4 h-4" />
              JSON
            </button>
            <button
              onClick={() => handleExport("pdf")}
              className="flex items-center gap-2 px-4 py-2 bg-teal-600 text-white rounded-lg text-sm hover:bg-teal-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              PDF
            </button>
          </div>
        </div>

        {/* Verdict Banner */}
        <div
          className={`rounded-xl border-2 p-6 mb-8 ${getBannerStyle(report.banner)}`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8" />
              <div>
                <p className="text-2xl font-bold">
                  {report.banner.toUpperCase()}
                </p>
                <p className="text-sm opacity-75">Analysis verdict</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-3xl font-bold">
                {(report.ml_score * 100).toFixed(0)}%
              </p>
              <p className="text-sm opacity-75">Risk score</p>
            </div>
          </div>
        </div>

        {/* File Info */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">
            File Information
          </h2>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-slate-500">Filename</p>
              <p className="font-medium text-slate-900">
                {report.file.original_name}
              </p>
            </div>
            <div>
              <p className="text-slate-500">Type</p>
              <p className="font-medium text-slate-900">{report.file.mime}</p>
            </div>
            <div>
              <p className="text-slate-500">Size</p>
              <p className="font-medium text-slate-900">
                {(report.file.file_size / 1024 / 1024).toFixed(2)} MB
              </p>
            </div>
            <div>
              <p className="text-slate-500">SHA-256</p>
              <p className="font-mono text-xs text-slate-700 break-all">
                {report.file.sha256}
              </p>
            </div>
          </div>
        </div>

        {/* Detection Evidence */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-teal-600" />
            Detection Evidence
          </h2>
          {report.top_features && report.top_features.length > 0 ? (
            <div className="space-y-3">
              {report.top_features.map((feat: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-3 bg-slate-50 rounded-lg"
                >
                  <Zap className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-sm text-slate-900">
                      {feat.feature?.replace(/_/g, " ")}
                    </p>
                    <p className="text-sm text-slate-600">{feat.detail}</p>
                    {feat.weight && (
                      <span
                        className={`inline-block mt-1 text-xs px-2 py-0.5 rounded ${
                          feat.weight === "high"
                            ? "bg-red-100 text-red-700"
                            : feat.weight === "medium"
                            ? "bg-amber-100 text-amber-700"
                            : "bg-slate-100 text-slate-600"
                        }`}
                      >
                        {feat.weight} weight
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">
              No specific indicators detected.
            </p>
          )}
        </div>

        {/* YARA Matches */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">
            YARA Matches
          </h2>
          {report.yara_hits && report.yara_hits.length > 0 ? (
            <div className="space-y-2">
              {report.yara_hits.map((hit: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 bg-slate-50 rounded-lg"
                >
                  <div>
                    <p className="font-medium text-sm text-slate-900">
                      {hit.rule_name}
                    </p>
                    {hit.details?.tags?.length > 0 && (
                      <p className="text-xs text-slate-500">
                        Tags: {hit.details.tags.join(", ")}
                      </p>
                    )}
                  </div>
                  <span
                    className={`text-xs px-2 py-1 rounded font-medium ${
                      hit.details?.severity === "high"
                        ? "bg-red-100 text-red-700"
                        : hit.details?.severity === "medium"
                        ? "bg-amber-100 text-amber-700"
                        : "bg-green-100 text-green-700"
                    }`}
                  >
                    {hit.details?.severity || "medium"}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-slate-500 text-sm">No YARA rules matched.</p>
          )}
        </div>

        {/* VirusTotal */}
        <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-4">
            VirusTotal Enrichment
          </h2>
          {report.vt_summary_json ? (
            <div>
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="bg-red-50 rounded-lg p-4 text-center">
                  <p className="text-2xl font-bold text-red-600">
                    {report.vt_summary_json.malicious || 0}
                  </p>
                  <p className="text-xs text-red-600">Malicious</p>
                </div>
                <div className="bg-amber-50 rounded-lg p-4 text-center">
                  <p className="text-2xl font-bold text-amber-600">
                    {report.vt_summary_json.suspicious || 0}
                  </p>
                  <p className="text-xs text-amber-600">Suspicious</p>
                </div>
                <div className="bg-green-50 rounded-lg p-4 text-center">
                  <p className="text-2xl font-bold text-green-600">
                    {report.vt_summary_json.harmless || 0}
                  </p>
                  <p className="text-xs text-green-600">Harmless</p>
                </div>
              </div>
              <p className="text-xs text-slate-500">
                Total engines: {report.vt_summary_json.total_engines || 0} |
                Status: {report.vt_summary_json.enrichment_status}
              </p>
            </div>
          ) : (
            <p className="text-slate-500 text-sm">VT enrichment unavailable.</p>
          )}
        </div>

        {/* Cluster Info */}
        {report.cluster && (
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 mb-6">
            <h2 className="text-lg font-semibold text-slate-900 mb-4">
              Campaign Cluster
            </h2>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-slate-500">Cluster name</p>
                <p className="font-medium text-slate-900">
                  {report.cluster.name}
                </p>
              </div>
              <div>
                <p className="text-slate-500">Cluster size</p>
                <p className="font-medium text-slate-900">
                  {report.cluster.size} files
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
