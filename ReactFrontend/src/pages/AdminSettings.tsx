import React, { useState } from 'react';
import {
  Plus,
  Edit2,
  Trash2,
  Eye,
  EyeOff,
  Upload,
  CheckCircle,
  AlertCircle,
} from 'lucide-react';
import Navigation from '../components/Navigation';

interface YaraRule {
  id: string;
  name: string;
  version: string;
  status: 'active' | 'inactive';
  updatedAt: string;
}

interface ApiKey {
  id: string;
  service: string;
  status: 'active' | 'test';
  lastUsed: string;
}

export default function AdminSettings() {
  const [activeTab, setActiveTab] = useState<'yara' | 'api' | 'models'>('yara');
  const [showApiKey, setShowApiKey] = useState(false);
  const [editingRule, setEditingRule] = useState<YaraRule | null>(null);
  const [newRuleName, setNewRuleName] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const yaraRules: YaraRule[] = [
    {
      id: '1',
      name: 'SUSP_PDF_Embedded_JS',
      version: '2.1',
      status: 'active',
      updatedAt: '2024-11-10',
    },
    {
      id: '2',
      name: 'MALWARE_Macro_Obfuscation',
      version: '1.8',
      status: 'active',
      updatedAt: '2024-11-08',
    },
    {
      id: '3',
      name: 'SUSP_Macro_Presence',
      version: '1.5',
      status: 'inactive',
      updatedAt: '2024-11-01',
    },
  ];

  const apiKeys: ApiKey[] = [
    {
      id: '1',
      service: 'VirusTotal',
      status: 'active',
      lastUsed: '2 hours ago',
    },
    {
      id: '2',
      service: 'VirusTotal (Test)',
      status: 'test',
      lastUsed: '1 day ago',
    },
  ];

  const handleSaveRule = () => {
    setSuccessMessage('YARA rule updated successfully');
    setEditingRule(null);
    setTimeout(() => setSuccessMessage(''), 3000);
  };

  const handleAddRule = () => {
    if (newRuleName.trim()) {
      setSuccessMessage('YARA rule added successfully');
      setNewRuleName('');
      setTimeout(() => setSuccessMessage(''), 3000);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-12">
          <h1 className="text-4xl font-bold text-slate-900 mb-2">System Settings</h1>
          <p className="text-lg text-slate-600">
            Manage detection rules, API keys, and ML models
          </p>
        </div>

        {successMessage && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" />
            <p className="text-sm text-green-800">{successMessage}</p>
          </div>
        )}

        <div className="flex gap-0 mb-8 border-b border-slate-200">
          <button
            onClick={() => setActiveTab('yara')}
            className={`px-6 py-3 font-medium border-b-2 transition ${
              activeTab === 'yara'
                ? 'border-teal-600 text-teal-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            YARA Rules
          </button>
          <button
            onClick={() => setActiveTab('api')}
            className={`px-6 py-3 font-medium border-b-2 transition ${
              activeTab === 'api'
                ? 'border-teal-600 text-teal-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            API Keys
          </button>
          <button
            onClick={() => setActiveTab('models')}
            className={`px-6 py-3 font-medium border-b-2 transition ${
              activeTab === 'models'
                ? 'border-teal-600 text-teal-600'
                : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
          >
            ML Models
          </button>
        </div>

        {activeTab === 'yara' && (
          <div className="space-y-8">
            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-slate-900">YARA Detection Rules</h2>
                <button className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition">
                  <Plus className="w-4 h-4" />
                  Add Rule
                </button>
              </div>

              <div className="space-y-3">
                {yaraRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="flex items-center justify-between p-4 border border-slate-200 rounded-lg hover:bg-slate-50 transition"
                  >
                    <div className="flex-1">
                      <p className="font-semibold text-slate-900">{rule.name}</p>
                      <p className="text-sm text-slate-600">
                        Version {rule.version} • Updated {rule.updatedAt}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span
                        className={`px-3 py-1 rounded-full text-sm font-medium ${
                          rule.status === 'active'
                            ? 'bg-green-100 text-green-800'
                            : 'bg-slate-100 text-slate-800'
                        }`}
                      >
                        {rule.status}
                      </span>
                      <button className="p-2 hover:bg-slate-200 rounded-lg transition">
                        <Edit2 className="w-4 h-4 text-slate-600" />
                      </button>
                      <button className="p-2 hover:bg-red-50 rounded-lg transition">
                        <Trash2 className="w-4 h-4 text-red-600" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h3 className="text-xl font-bold text-slate-900 mb-4">Upload New Rules</h3>
              <div className="border-2 border-dashed border-slate-300 rounded-lg p-8 text-center hover:border-teal-500 transition cursor-pointer">
                <Upload className="w-12 h-12 text-slate-400 mx-auto mb-3" />
                <p className="font-medium text-slate-900 mb-1">Drop YARA rule files here</p>
                <p className="text-sm text-slate-600">or click to browse</p>
                <input type="file" className="hidden" accept=".yar,.yara" />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'api' && (
          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
            <h2 className="text-2xl font-bold text-slate-900 mb-6">API Key Management</h2>

            <div className="space-y-6">
              {apiKeys.map((key) => (
                <div
                  key={key.id}
                  className="border border-slate-200 rounded-lg p-6 hover:bg-slate-50 transition"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <p className="font-semibold text-slate-900">{key.service}</p>
                      <p className="text-sm text-slate-600">Last used: {key.lastUsed}</p>
                    </div>
                    <span
                      className={`px-3 py-1 rounded-full text-sm font-medium ${
                        key.status === 'active'
                          ? 'bg-green-100 text-green-800'
                          : 'bg-blue-100 text-blue-800'
                      }`}
                    >
                      {key.status}
                    </span>
                  </div>

                  <div className="bg-slate-50 rounded-lg p-4 mb-4">
                    <div className="flex items-center justify-between">
                      <input
                        type={showApiKey ? 'text' : 'password'}
                        value="sk_live_•••••••••••••••••••••••••"
                        readOnly
                        className="flex-1 bg-transparent text-slate-900 font-mono text-sm outline-none"
                      />
                      <button
                        onClick={() => setShowApiKey(!showApiKey)}
                        className="ml-2 p-2 hover:bg-slate-200 rounded transition"
                      >
                        {showApiKey ? (
                          <EyeOff className="w-4 h-4 text-slate-600" />
                        ) : (
                          <Eye className="w-4 h-4 text-slate-600" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="flex gap-3">
                    <button className="px-4 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition">
                      Rotate Key
                    </button>
                    <button className="px-4 py-2 border border-slate-300 hover:bg-slate-50 text-slate-700 font-medium rounded-lg transition">
                      Test Connection
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-8 border-t border-slate-200 pt-8">
              <h3 className="font-semibold text-slate-900 mb-4">Add New API Key</h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Service
                  </label>
                  <select className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-transparent outline-none">
                    <option>Select a service</option>
                    <option>VirusTotal</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    API Key
                  </label>
                  <input
                    type="password"
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-teal-500 focus:border-transparent outline-none"
                    placeholder="Enter API key"
                  />
                </div>
                <button className="px-6 py-2 bg-teal-600 hover:bg-teal-700 text-white font-medium rounded-lg transition">
                  Save API Key
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'models' && (
          <div className="space-y-8">
            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h2 className="text-2xl font-bold text-slate-900 mb-6">ML Model Management</h2>

              <div className="bg-gradient-to-r from-teal-50 to-teal-100 rounded-lg p-6 border border-teal-200 mb-8">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-semibold text-slate-900">Current Model</p>
                    <p className="text-slate-700 mt-1">v3.2 • Updated Nov 10, 2024</p>
                  </div>
                  <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
                    Active
                  </span>
                </div>
              </div>

              <div className="border-t border-slate-200 pt-6">
                <h3 className="font-semibold text-slate-900 mb-4">Previous Versions</h3>
                <div className="space-y-3">
                  {['v3.1', 'v3.0', 'v2.9'].map((version) => (
                    <div
                      key={version}
                      className="flex items-center justify-between p-4 border border-slate-200 rounded-lg"
                    >
                      <p className="font-medium text-slate-900">{version}</p>
                      <button className="px-4 py-2 border border-slate-300 hover:bg-slate-50 text-slate-700 font-medium rounded-lg transition">
                        Rollback
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8">
              <h3 className="font-semibold text-slate-900 mb-4">Upload New Model</h3>
              <div className="border-2 border-dashed border-slate-300 rounded-lg p-8 text-center hover:border-teal-500 transition cursor-pointer">
                <Upload className="w-12 h-12 text-slate-400 mx-auto mb-3" />
                <p className="font-medium text-slate-900 mb-1">Drop model file here</p>
                <p className="text-sm text-slate-600 mb-4">or click to browse (.pkl, .h5, .pth)</p>
                <input type="file" className="hidden" accept=".pkl,.h5,.pth" />
                <p className="text-xs text-slate-500 mt-4">
                  Recommended: Validate model before deploying to production
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
