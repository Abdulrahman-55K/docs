import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText, Calendar, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import Navigation from '../components/Navigation';

export interface ReportSummary {
  id: string;
  filename: string;
  uploadDate: string;
  status: 'benign' | 'suspicious' | 'malicious' | 'need_review';
  score: number;
  yaraMatches: number;
  vtDetections: number;
}

export default function Reports() {
  const [reports] = useState<ReportSummary[]>([
    {
      id: '1',
      filename: 'document_v2.pdf',
      uploadDate: '2024-11-13',
      status: 'benign',
      score: 15,
      yaraMatches: 0,
      vtDetections: 0,
    },
    {
      id: '2',
      filename: 'invoice_template.docx',
      uploadDate: '2024-11-12',
      status: 'suspicious',
      score: 62,
      yaraMatches: 2,
      vtDetections: 3,
    },
  ]);
  const navigate = useNavigate();

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'benign':
        return 'text-green-600 bg-green-50';
      case 'suspicious':
        return 'text-amber-600 bg-amber-50';
      case 'malicious':
        return 'text-red-600 bg-red-50';
      case 'need_review':
        return 'text-blue-600 bg-blue-50';
      default:
        return 'text-slate-600 bg-slate-50';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'benign':
        return <CheckCircle className="w-5 h-5" />;
      case 'malicious':
        return <AlertTriangle className="w-5 h-5" />;
      case 'suspicious':
        return <AlertTriangle className="w-5 h-5" />;
      default:
        return <Shield className="w-5 h-5" />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-12">
          <h1 className="text-4xl font-bold text-slate-900 mb-2">Scan Reports</h1>
          <p className="text-lg text-slate-600">View and manage all your document scan reports</p>
        </div>

        {reports.length === 0 ? (
          <div className="bg-white rounded-2xl shadow-lg border border-slate-200 p-12 text-center">
            <FileText className="w-16 h-16 text-slate-300 mx-auto mb-4" />
            <p className="text-slate-600">No reports yet. Upload a document to get started.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {reports.map((report) => (
              <div
                key={report.id}
                className="bg-white rounded-xl shadow-md hover:shadow-lg border border-slate-200 transition overflow-hidden"
              >
                <div className="p-6">
                  <div className="flex items-start justify-between gap-4 flex-wrap">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <FileText className="w-5 h-5 text-slate-400 flex-shrink-0" />
                        <h3 className="text-lg font-semibold text-slate-900 truncate">
                          {report.filename}
                        </h3>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-slate-600">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-4 h-4" />
                          {report.uploadDate}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div
                        className={`flex items-center gap-2 px-4 py-2 rounded-lg font-semibold ${getStatusColor(
                          report.status
                        )}`}
                      >
                        {getStatusIcon(report.status)}
                        <span className="capitalize">
                          {report.status.replace('_', ' ')}
                        </span>
                      </div>
                      <button
                        onClick={() =>
                          navigate(`/reports/${report.id}`, {
                            state: { reportId: report.id },
                          })
                        }
                        className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition"
                      >
                        View Details
                      </button>
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-3 gap-4 pt-4 border-t border-slate-200">
                    <div className="text-center">
                      <p className="text-sm text-slate-600 mb-1">Risk Score</p>
                      <p className="text-2xl font-bold text-slate-900">{report.score}</p>
                    </div>
                    <div className="text-center">
                      <p className="text-sm text-slate-600 mb-1">YARA Matches</p>
                      <p className="text-2xl font-bold text-slate-900">{report.yaraMatches}</p>
                    </div>
                    <div className="text-center">
                      <p className="text-sm text-slate-600 mb-1">VT Detections</p>
                      <p className="text-2xl font-bold text-slate-900">{report.vtDetections}</p>
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
