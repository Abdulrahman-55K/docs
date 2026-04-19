import React, { useState, useEffect, useRef } from "react";
import { Plus, Trash2, Eye, EyeOff, Upload, CheckCircle, AlertCircle } from "lucide-react";
import Navigation from "../components/Navigation";
import { apiGet, apiPost, apiPatch, apiDelete, apiUpload } from "../lib/api";

export default function AdminSettings() {
  const [activeTab, setActiveTab] = useState<"yara" | "api" | "models">("yara");
  const [message, setMessage] = useState({ type: "", text: "" });

  return (
    <div className="min-h-screen bg-slate-50">
      <Navigation />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2">
            System Configuration
          </h1>
          <p className="text-slate-600">Manage YARA rules, ML models, and API keys</p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-slate-100 rounded-lg p-1 w-fit">
          {(["yara", "models", "api"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => { setActiveTab(tab); setMessage({ type: "", text: "" }); }}
              className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab
                  ? "bg-white text-slate-900 shadow-sm"
                  : "text-slate-600 hover:text-slate-900"
              }`}
            >
              {tab === "yara" ? "YARA Rules" : tab === "models" ? "ML Models" : "API Keys"}
            </button>
          ))}
        </div>

        {message.text && (
          <div className={`mb-4 p-4 rounded-lg flex items-start gap-3 ${
            message.type === "success" ? "bg-green-50 border border-green-200" : "bg-red-50 border border-red-200"
          }`}>
            {message.type === "success" ? (
              <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
            ) : (
              <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0" />
            )}
            <p className={`text-sm ${message.type === "success" ? "text-green-800" : "text-red-800"}`}>
              {message.text}
            </p>
          </div>
        )}

        {activeTab === "yara" && <YaraTab onMessage={setMessage} />}
        {activeTab === "models" && <ModelsTab onMessage={setMessage} />}
        {activeTab === "api" && <ApiKeysTab onMessage={setMessage} />}
      </div>
    </div>
  );
}

// --- YARA Rules Tab ---
function YaraTab({ onMessage }: { onMessage: (m: { type: string; text: string }) => void }) {
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("1.0");
  const fileRef = useRef<HTMLInputElement>(null);

  const fetchRules = async () => {
    const { data } = await apiGet("/admin-panel/yara-rules/");
    if (data) setRules(data);
    setLoading(false);
  };

  useEffect(() => { fetchRules(); }, []);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file || !name) return;

    const formData = new FormData();
    formData.append("name", name);
    formData.append("version", version);
    formData.append("rule_file", file);
    formData.append("status", "active");

    const { data, error } = await apiUpload("/admin-panel/yara-rules/", formData);
    if (error) {
      onMessage({ type: "error", text: error });
    } else {
      onMessage({ type: "success", text: `YARA rule "${name}" uploaded.` });
      setName("");
      setVersion("1.0");
      fetchRules();
    }
  };

  const toggleStatus = async (id: string, currentStatus: string) => {
    const newStatus = currentStatus === "active" ? "inactive" : "active";
    await apiPatch(`/admin-panel/yara-rules/${id}/`, { status: newStatus });
    fetchRules();
  };

  const deleteRule = async (id: string, ruleName: string) => {
    if (!confirm(`Delete YARA rule "${ruleName}"?`)) return;
    await apiDelete(`/admin-panel/yara-rules/${id}/`);
    onMessage({ type: "success", text: `Rule "${ruleName}" deleted.` });
    fetchRules();
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleUpload} className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Upload new rule set</h3>
        <div className="grid grid-cols-3 gap-4">
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Rule name" required
            className="px-3 py-2 border border-slate-300 rounded-lg text-sm" />
          <input type="text" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Version"
            className="px-3 py-2 border border-slate-300 rounded-lg text-sm" />
          <input type="file" ref={fileRef} accept=".yar,.yara" required className="text-sm" />
        </div>
        <button type="submit" className="mt-4 px-4 py-2 bg-teal-600 text-white rounded-lg text-sm hover:bg-teal-700 flex items-center gap-2">
          <Upload className="w-4 h-4" /> Upload Rule
        </button>
      </form>

      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Active rules</h3>
        {loading ? <p className="text-slate-500 text-sm">Loading...</p> : rules.length === 0 ? (
          <p className="text-slate-500 text-sm">No YARA rules configured.</p>
        ) : (
          <div className="space-y-2">
            {rules.map((rule) => (
              <div key={rule.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                <div>
                  <p className="font-medium text-sm">{rule.name} <span className="text-slate-400">v{rule.version}</span></p>
                  <p className="text-xs text-slate-500">Updated: {new Date(rule.updated_at).toLocaleDateString()}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => toggleStatus(rule.id, rule.status)}
                    className={`text-xs px-3 py-1 rounded font-medium ${
                      rule.status === "active" ? "bg-green-100 text-green-700" : "bg-slate-200 text-slate-600"
                    }`}>
                    {rule.status}
                  </button>
                  <button onClick={() => deleteRule(rule.id, rule.name)}
                    className="p-1 text-slate-400 hover:text-red-600">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// --- ML Models Tab ---
function ModelsTab({ onMessage }: { onMessage: (m: { type: string; text: string }) => void }) {
  const [models, setModels] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [version, setVersion] = useState("");
  const [description, setDescription] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const fetchModels = async () => {
    const { data } = await apiGet("/admin-panel/ml-models/");
    if (data) setModels(data);
    setLoading(false);
  };

  useEffect(() => { fetchModels(); }, []);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file || !version) return;

    const formData = new FormData();
    formData.append("version", version);
    formData.append("description", description);
    formData.append("model_file", file);

    const { data, error } = await apiUpload("/admin-panel/ml-models/", formData);
    if (error) {
      onMessage({ type: "error", text: error });
    } else {
      onMessage({ type: "success", text: `Model v${version} uploaded.` });
      setVersion("");
      setDescription("");
      fetchModels();
    }
  };

  const promoteModel = async (id: string, ver: string) => {
    const { error } = await apiPost(`/admin-panel/ml-models/${id}/promote/`);
    if (error) {
      onMessage({ type: "error", text: error });
    } else {
      onMessage({ type: "success", text: `Model v${ver} is now active.` });
      fetchModels();
    }
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleUpload} className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Upload new model</h3>
        <div className="grid grid-cols-2 gap-4">
          <input type="text" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="Version (e.g. 1.0)" required
            className="px-3 py-2 border border-slate-300 rounded-lg text-sm" />
          <input type="file" ref={fileRef} accept=".pkl,.joblib,.h5,.onnx" required className="text-sm" />
        </div>
        <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description (optional)"
          className="mt-3 w-full px-3 py-2 border border-slate-300 rounded-lg text-sm" />
        <button type="submit" className="mt-4 px-4 py-2 bg-teal-600 text-white rounded-lg text-sm hover:bg-teal-700 flex items-center gap-2">
          <Upload className="w-4 h-4" /> Upload Model
        </button>
      </form>

      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Model versions</h3>
        {loading ? <p className="text-slate-500 text-sm">Loading...</p> : models.length === 0 ? (
          <p className="text-slate-500 text-sm">No models uploaded.</p>
        ) : (
          <div className="space-y-2">
            {models.map((model) => (
              <div key={model.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                <div>
                  <p className="font-medium text-sm">v{model.version} {model.is_active && <span className="text-green-600">[ACTIVE]</span>}</p>
                  <p className="text-xs text-slate-500">{model.description || "No description"} — {new Date(model.created_at).toLocaleDateString()}</p>
                </div>
                {!model.is_active && (
                  <button onClick={() => promoteModel(model.id, model.version)}
                    className="text-xs px-3 py-1 bg-teal-100 text-teal-700 rounded font-medium hover:bg-teal-200">
                    Promote
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// --- API Keys Tab ---
function ApiKeysTab({ onMessage }: { onMessage: (m: { type: string; text: string }) => void }) {
  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [service, setService] = useState("virustotal");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);

  const fetchKeys = async () => {
    const { data } = await apiGet("/admin-panel/api-keys/");
    if (data) setKeys(data);
    setLoading(false);
  };

  useEffect(() => { fetchKeys(); }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey) return;

    const { error } = await apiPost("/admin-panel/api-keys/", { service, api_key: apiKey });
    if (error) {
      onMessage({ type: "error", text: error });
    } else {
      onMessage({ type: "success", text: `API key for "${service}" saved.` });
      setApiKey("");
      fetchKeys();
    }
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleSave} className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Add / rotate API key</h3>
        <div className="grid grid-cols-2 gap-4">
          <select value={service} onChange={(e) => setService(e.target.value)}
            className="px-3 py-2 border border-slate-300 rounded-lg text-sm">
            <option value="virustotal">VirusTotal</option>
          </select>
          <div className="relative">
            <input type={showKey ? "text" : "password"} value={apiKey} onChange={(e) => setApiKey(e.target.value)}
              placeholder="Paste API key" required
              className="w-full px-3 py-2 pr-10 border border-slate-300 rounded-lg text-sm" />
            <button type="button" onClick={() => setShowKey(!showKey)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400">
              {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>
        <button type="submit" className="mt-4 px-4 py-2 bg-teal-600 text-white rounded-lg text-sm hover:bg-teal-700">
          Save Key
        </button>
      </form>

      <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
        <h3 className="font-semibold text-slate-900 mb-4">Configured keys</h3>
        {loading ? <p className="text-slate-500 text-sm">Loading...</p> : keys.length === 0 ? (
          <p className="text-slate-500 text-sm">No API keys configured.</p>
        ) : (
          <div className="space-y-2">
            {keys.map((key) => (
              <div key={key.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                <div>
                  <p className="font-medium text-sm capitalize">{key.service}</p>
                  <p className="text-xs text-slate-500">Key: {key.key_preview} — Rotated: {new Date(key.last_rotated).toLocaleDateString()}</p>
                </div>
                <span className={`text-xs px-2 py-1 rounded font-medium ${
                  key.status === "active" ? "bg-green-100 text-green-700" : "bg-slate-200 text-slate-600"
                }`}>{key.status}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
