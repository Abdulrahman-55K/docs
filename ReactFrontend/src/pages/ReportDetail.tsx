import React from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  FileText,
  Calendar,
  Shield,
  Download,
  ArrowLeft,
  CheckCircle,
  AlertTriangle,
  TrendingUp,
  Zap,
} from 'lucide-react';
import Navigation from '../components/Navigation';

interface ReportDetailData {
  id: string;
  filename: string;
  uploadDate: string;
  fileSize: string;
  fileHash: string;
  status: 'benign' | 'suspicious' | 'malicious' | 'need_review';
  score: number;
  yaraMatches: Array<{ rule: string; severity: 'low' | 'medium' | 'high'; offset: string }>;
  vtDetections: { detections: number; total: number; engines: string[] };
  mlClassification: { label: string; score: number; entropy: number; macroCount: number };
  relatedCluster: { count: number; samples: string[] };
  notes: string;
}

const mockReports: Record<string, ReportDetailData> = {
  '1': {
    id: '1',
    filename: 'document_v2.pdf',
    uploadDate: '2024-11-13',
    fileSize: '1.8 MB',
    fileHash: '5f2c1a7b4d9e8c3f6a1b2c3d4e5f6789abcdef0123456789abcdef0123456789',
    status: 'benign',
    score: 15,
    yaraMatches: [
      { rule: 'CLEAN_PDF_Metadata', severity: 'low', offset: '0x0120' },
    ],
    vtDetections: {
      detections: 0,
      total: 71,
      engines: [],
    },
    mlClassification: {
      label: 'benign',
      score: 0.11,
      entropy: 4.2,
      macroCount: 0,
    },
    relatedCluster: {
      count: 4,
      samples: ['09adf...', '127bae...', '99d10f...', '54ca2b...'],
    },
    notes: 'No suspicious indicators were observed. Metadata and embedded objects appeared clean.',
  },
  '2': {
    id: '2',
    filename: 'invoice_template.docx',
    uploadDate: '2024-11-12',
    fileSize: '3.2 MB',
    fileHash: 'd4c3b2a1f6789e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a697887766554433221',
    status: 'suspicious',
    score: 62,
    yaraMatches: [
      { rule: 'SUSP_Macro_Presence', severity: 'medium', offset: '0x5680' },
      { rule: 'MALDOC_RTF_Embedded_Object', severity: 'high', offset: '0x89d0' },
    ],
    vtDetections: {
      detections: 3,
      total: 71,
      engines: ['TrendMicro', 'Kaspersky', 'ESET'],
    },
    mlClassification: {
      label: 'suspicious',
      score: 0.62,
      entropy: 7.8,
      macroCount: 5,
    },
    relatedCluster: {
      count: 12,
      samples: ['f92ab...', '0f1c2...', 'adbe11...'],
    },
    notes:
      'Macros found with obfuscated strings. Recommend sandbox execution before releasing to end users.',
  },
};

export default function ReportDetail() {
  const { id: paramId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const requestedId = (location.state as { reportId?: string } | null)?.reportId ?? paramId ?? '1';
  const report = mockReports[requestedId] ?? mockReports['1'];

  const handleExport = () => {
    console.log(`Exporting report ${report.id}...`);
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <button
          onClick={() => navigate('/reports')}
          className="flex items-center gap-2 text-teal-600 hover:text-teal-700 font-medium mb-6"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Reports
        </button>

        <div className="mb-8">
          <div className="flex items-start justify-between gap-4 flex-wrap mb-6">
            <div>
              <h1 className="text-3xl font-bold text-slate-900 mb-2">{report.filename}</h1>
              <p className="text-slate-600">
                Uploaded on {report.uploadDate} • {report.fileSize}
              </p>
            </div>
            <div className="flex gap-3">
              <button
                onClick={handleExport}
                className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition"
              >
                <Download className="w-4 h-4" />
                Export Report
              </button>
            </div>
          </div>

          <div className="bg-gradient-to-r from-teal-50 to-teal-100 rounded-xl p-6 border border-teal-200">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div>
                <p className="text-sm text-slate-600 mb-1">Status</p>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-600" />
                  <span className="font-semibold text-slate-900 capitalize">
                    {report.status}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-sm text-slate-600 mb-1">Risk Score</p>
                <p className="text-3xl font-bold text-slate-900">{report.score}</p>
              </div>
              <div>
                <p className="text-sm text-slate-600 mb-1">YARA Matches</p>
                <p className="text-3xl font-bold text-slate-900">{report.yaraMatches.length}</p>
              </div>
              <div>
                <p className="text-sm text-slate-600 mb-1">VT Detections</p>
                <p className="text-3xl font-bold text-slate-900">
                  {report.vtDetections.detections}/{report.vtDetections.total}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-8">
            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h2 className="text-2xl font-bold text-slate-900 mb-6">File Information</h2>
              <dl className="space-y-4">
                <div className="flex justify-between items-start">
                  <dt className="font-medium text-slate-700">SHA256</dt>
                  <dd className="text-sm text-slate-600 font-mono">{report.fileHash}</dd>
                </div>
                <div className="flex justify-between items-start">
                  <dt className="font-medium text-slate-700">File Size</dt>
                  <dd className="text-sm text-slate-600">{report.fileSize}</dd>
                </div>
                <div className="flex justify-between items-start">
                  <dt className="font-medium text-slate-700">Upload Date</dt>
                  <dd className="text-sm text-slate-600">{report.uploadDate}</dd>
                </div>
              </dl>
            </div>

            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <Zap className="w-6 h-6 text-amber-600" />
                YARA Rule Matches
              </h2>
              {report.yaraMatches.length > 0 ? (
                <div className="space-y-4">
                  {report.yaraMatches.map((match, idx) => (
                    <div
                      key={idx}
                      className="border border-slate-200 rounded-lg p-4 hover:bg-slate-50 transition"
                    >
                      <div className="flex items-start justify-between mb-2">
                        <span className="font-semibold text-slate-900">{match.rule}</span>
                        <span
                          className={`text-xs font-bold px-3 py-1 rounded-full ${
                            match.severity === 'high'
                              ? 'bg-red-100 text-red-800'
                              : 'bg-yellow-100 text-yellow-800'
                          }`}
                        >
                          {match.severity}
                        </span>
                      </div>
                      <p className="text-sm text-slate-600 font-mono">Offset: {match.offset}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-600">No YARA rule matches found.</p>
              )}
            </div>

            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <Shield className="w-6 h-6 text-teal-600" />
                VirusTotal Analysis
              </h2>
              <div className="bg-gradient-to-r from-teal-50 to-cyan-50 rounded-lg p-6 border border-teal-200 mb-4">
                <p className="text-sm text-slate-600 mb-1">Detection Ratio</p>
                <p className="text-3xl font-bold text-slate-900">
                  {report.vtDetections.detections}/{report.vtDetections.total}
                </p>
              </div>
              <p className="text-sm text-slate-600 mb-3">Detected by:</p>
              <div className="flex flex-wrap gap-2">
                {report.vtDetections.engines.map((engine, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 bg-slate-100 text-slate-700 rounded-full text-sm"
                  >
                    {engine}
                  </span>
                ))}
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <TrendingUp className="w-6 h-6 text-teal-600" />
                ML Classification
              </h2>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 rounded-lg p-4">
                  <p className="text-sm text-slate-600 mb-1">Label</p>
                  <p className="font-semibold text-slate-900 capitalize">
                    {report.mlClassification.label}
                  </p>
                </div>
                <div className="bg-slate-50 rounded-lg p-4">
                  <p className="text-sm text-slate-600 mb-1">Confidence</p>
                  <p className="font-semibold text-slate-900">
                    {(report.mlClassification.score * 100).toFixed(1)}%
                  </p>
                </div>
                <div className="bg-slate-50 rounded-lg p-4">
                  <p className="text-sm text-slate-600 mb-1">Entropy</p>
                  <p className="font-semibold text-slate-900">{report.mlClassification.entropy}</p>
                </div>
                <div className="bg-slate-50 rounded-lg p-4">
                  <p className="text-sm text-slate-600 mb-1">Macro Count</p>
                  <p className="font-semibold text-slate-900">
                    {report.mlClassification.macroCount}
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6">
              <h3 className="font-semibold text-slate-900 mb-4">Related Cluster</h3>
              <p className="text-2xl font-bold text-teal-600 mb-3">{report.relatedCluster.count}</p>
              <p className="text-sm text-slate-600 mb-4">
                Similar samples found in the detection database
              </p>
              <button className="w-full px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition">
                View Cluster
              </button>
            </div>

            <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl p-6 border border-blue-200">
              <p className="text-sm text-slate-700">
                <span className="font-semibold">Note:</span> This report is automatically generated
                based on multiple detection engines. Review results carefully before taking action.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
