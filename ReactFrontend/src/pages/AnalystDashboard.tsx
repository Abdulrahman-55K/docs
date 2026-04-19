import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Upload, FileText, CheckCircle, AlertCircle, Clock, Shield } from "lucide-react";
import Navigation from "../components/Navigation";
import { apiUpload } from "../lib/api";

export default function AnalystDashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [uploadError, setUploadError] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const acceptedFormats = [
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ];

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!acceptedFormats.includes(selectedFile.type)) {
        setUploadError("Only PDF and Office documents are accepted.");
        setFile(null);
        return;
      }
      if (selectedFile.size > 25 * 1024 * 1024) {
        setUploadError("File size must be less than 25MB.");
        setFile(null);
        return;
      }
      setFile(selectedFile);
      setUploadError("");
      setResult(null);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setUploadError("");
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    const { data, error } = await apiUpload("/analysis/upload/", formData);

    if (error) {
      setUploadError(error);
    } else if (data) {
      setResult(data);
    }

    setUploading(false);
  };

  const getBannerStyle = (banner: string) => {
    switch (banner) {
      case "clean":
        return "bg-green-50 border-green-200 text-green-800";
      case "suspicious":
        return "bg-amber-50 border-amber-200 text-amber-800";
      case "malicious":
        return "bg-red-50 border-red-200 text-red-800";
      default:
        return "bg-blue-50 border-blue-200 text-blue-800";
    }
  };

  const getBannerIcon = (banner: string) => {
    switch (banner) {
      case "clean":
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      case "suspicious":
        return <AlertCircle className="w-5 h-5 text-amber-600" />;
      case "malicious":
        return <Shield className="w-5 h-5 text-red-600" />;
      default:
        return <Clock className="w-5 h-5 text-blue-600" />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">
            Upload Document
          </h1>
          <p className="text-slate-600">
            Upload Office or PDF documents for malicious content analysis
          </p>
        </div>

        <div className="bg-white rounded-2xl shadow-lg border border-slate-200 p-8">
          <form onSubmit={handleUpload}>
            <div
              className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
                file
                  ? "border-teal-300 bg-teal-50"
                  : "border-slate-300 hover:border-teal-400 hover:bg-slate-50"
              }`}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                className="hidden"
                accept=".pdf,.docx,.xlsx,.pptx"
              />

              {file ? (
                <div className="flex flex-col items-center gap-3">
                  <FileText className="w-12 h-12 text-teal-600" />
                  <div>
                    <p className="text-lg font-medium text-slate-900">
                      {file.name}
                    </p>
                    <p className="text-sm text-slate-500">
                      {(file.size / 1024 / 1024).toFixed(1)} MB
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3">
                  <Upload className="w-12 h-12 text-slate-400" />
                  <div>
                    <p className="text-lg font-medium text-slate-700">
                      Click to select a file
                    </p>
                    <p className="text-sm text-slate-500">
                      PDF, DOCX, XLSX, PPTX — up to 25MB
                    </p>
                  </div>
                </div>
              )}
            </div>

            {uploadError && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-red-800">{uploadError}</p>
              </div>
            )}

            {result && (
              <div
                className={`mt-4 p-4 border rounded-lg flex items-start gap-3 ${getBannerStyle(
                  result.banner || "needs_review"
                )}`}
              >
                {getBannerIcon(result.banner || "needs_review")}
                <div className="flex-1">
                  <p className="font-medium">
                    {result.banner
                      ? `Verdict: ${result.banner.toUpperCase()}`
                      : result.message}
                  </p>
                  {result.report_id && (
                    <button
                      type="button"
                      onClick={() =>
                        navigate(`/reports/${result.report_id}`)
                      }
                      className="mt-2 text-sm underline hover:no-underline"
                    >
                      View full report →
                    </button>
                  )}
                  {result.is_duplicate && (
                    <p className="text-sm mt-1 opacity-75">
                      This file was already analyzed.
                    </p>
                  )}
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={!file || uploading}
              className="mt-6 w-full bg-teal-600 text-white py-3 rounded-lg hover:bg-teal-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {uploading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Upload className="w-5 h-5" />
                  Upload & Analyze
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
