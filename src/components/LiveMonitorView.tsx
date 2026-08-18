import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Radio,
  Play,
  Pause,
  Upload,
  FileText,
  Search,
  Filter,
  Download,
  Trash2,
  Sliders,
  AlertTriangle,
  CheckCircle,
  Zap,
  Sparkles,
  RefreshCw,
  Terminal,
  X,
  Copy,
  Check,
  Eye,
} from 'lucide-react';
import { SecurityEvent } from '../types/security';

export const LiveMonitorView: React.FC = () => {
  const {
    events,
    isLiveStreaming,
    setIsLiveStreaming,
    streamSpeed,
    setStreamSpeed,
    ingestRawLogs,
    isAnalyzing,
    triggerAttackScenario,
    setActiveTab,
    clearEvents,
  } = useSecurity();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [onlyAnomalies, setOnlyAnomalies] = useState<boolean>(false);
  const [rawTextInput, setRawTextInput] = useState<string>('');
  const [ingestStatus, setIngestStatus] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [copiedEventId, setCopiedEventId] = useState<string | null>(null);

  // Filtered Events
  const filteredEvents = events.filter(evt => {
    if (selectedCategory !== 'ALL' && evt.eventCategory !== selectedCategory) return false;
    if (selectedSeverity !== 'ALL' && evt.severity !== selectedSeverity) return false;
    if (onlyAnomalies && !evt.isAnomaly) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        evt.rawMessage.toLowerCase().includes(q) ||
        evt.sourceIp.includes(q) ||
        evt.destIp.includes(q) ||
        evt.user.toLowerCase().includes(q) ||
        evt.assetName.toLowerCase().includes(q) ||
        evt.action.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async event => {
      const content = event.target?.result as string;
      if (content) {
        setRawTextInput(content);
        const res = await ingestRawLogs(content);
        setIngestStatus(`Successfully ingested ${res.parsedCount} events (${res.newThreatsCount} new threats detected).`);
      }
    };
    reader.readAsText(file);
  };

  const handlePasteIngest = async () => {
    if (!rawTextInput.trim()) return;
    const res = await ingestRawLogs(rawTextInput);
    setIngestStatus(`Successfully parsed ${res.parsedCount} security events (${res.newThreatsCount} new threats identified).`);
  };

  const loadPresetLogs = (type: 'brute' | 'ransomware' | 'cloud') => {
    if (type === 'brute') {
      const bruteLogs = `timestamp,source_ip,user,action,dest_ip,asset,status
2026-08-17T02:13:01Z,185.220.101.5,admin,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:03Z,185.220.101.5,admin,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:05Z,185.220.101.5,root,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:07Z,185.220.101.5,svc_backup,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:09Z,185.220.101.5,admin,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:12Z,185.220.101.5,administrator,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:15Z,185.220.101.5,cfo,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:18Z,185.220.101.5,manager,LOGIN_FAILED,10.0.1.5,Active-Directory-DC01,FAIL
2026-08-17T02:13:21Z,185.220.101.5,admin,LOGIN_SUCCESS,10.0.1.5,Active-Directory-DC01,SUCCESS`;
      setRawTextInput(bruteLogs);
    } else if (type === 'ransomware') {
      const ransomLogs = `[
  {"timestamp": "2026-08-17T01:45:00Z", "source_ip": "10.0.3.44", "user": "SYSTEM", "action": "PROCESS_SPAWN_VSSADMIN", "asset": "Finance-DB-Server", "message": "CommandLine: vssadmin.exe delete shadows /all /quiet"},
  {"timestamp": "2026-08-17T01:45:15Z", "source_ip": "10.0.3.44", "user": "SYSTEM", "action": "FILE_MODIFICATION_BULK", "asset": "Finance-DB-Server", "message": "Modified 1420 files with extension .lockbit"},
  {"timestamp": "2026-08-17T01:45:30Z", "source_ip": "10.0.3.44", "user": "SYSTEM", "action": "OUTBOUND_C2_BEACON", "dest_ip": "91.240.118.172", "asset": "Finance-DB-Server", "message": "POST /api/v1/keys HTTP/1.1 to Russian IP"}
]`;
      setRawTextInput(ransomLogs);
    } else {
      const cloudLogs = `{"timestamp":"2026-08-17T02:10:00Z","eventName":"GetObject","userIdentity":{"type":"IAMUser","userName":"dev_contractor"},"sourceIPAddress":"103.145.74.22","eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"prod-customer-pii-vault","key":"customers_ssn_export_2026.csv.gz"}}
{"timestamp":"2026-08-17T02:10:14Z","eventName":"CreateAccessKey","userIdentity":{"type":"Root"},"sourceIPAddress":"103.145.74.22","eventSource":"iam.amazonaws.com","responseElements":{"accessKey":{"status":"Active"}}}`;
      setRawTextInput(cloudLogs);
    }
  };

  const exportEventsJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredEvents, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `cybershield_events_${Date.now()}.json`;
    a.click();
  };

  const handleCopyEvent = (evt: SecurityEvent) => {
    navigator.clipboard.writeText(JSON.stringify(evt, null, 2));
    setCopiedEventId(evt.id);
    setTimeout(() => setCopiedEventId(null), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* 1. Ingestion Control & Upload Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Radio className="w-5 h-5 text-emerald-600 animate-pulse" />
              <h1 className="text-base font-bold text-slate-900">Live Security Telemetry & Ingestion Core</h1>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Ingest raw `.log`, CSV, syslog, JSON events or stream live enterprise network traffic directly to the AI reasoning engine.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Speed Control */}
            <div className="flex items-center gap-1.5 bg-slate-50 px-2.5 py-1 rounded-lg border border-slate-200 text-xs">
              <Sliders className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-slate-600 font-medium">Rate:</span>
              <select
                value={streamSpeed}
                onChange={e => setStreamSpeed(Number(e.target.value))}
                className="bg-white border border-slate-200 rounded text-slate-800 text-xs px-1.5 py-0.5 focus:outline-none"
              >
                <option value={1000}>1.0s (Fast)</option>
                <option value={2000}>2.0s (Normal)</option>
                <option value={4000}>4.0s (Relaxed)</option>
              </select>
            </div>

            {/* Stream Toggle */}
            <button
              onClick={() => setIsLiveStreaming(!isLiveStreaming)}
              className={`flex items-center gap-1.5 text-xs font-semibold px-3.5 py-1.5 rounded-lg border transition-all cursor-pointer ${
                isLiveStreaming
                  ? 'bg-emerald-50 border-emerald-300 text-emerald-700 hover:bg-emerald-100'
                  : 'bg-slate-100 border-slate-300 text-slate-700 hover:bg-slate-200'
              }`}
            >
              {isLiveStreaming ? <Pause className="w-3.5 h-3.5 text-emerald-600" /> : <Play className="w-3.5 h-3.5 text-slate-700" />}
              <span>{isLiveStreaming ? 'Streaming Live' : 'Resume Stream'}</span>
            </button>

            {/* Export JSON */}
            <button
              onClick={exportEventsJson}
              className="flex items-center gap-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs px-3 py-1.5 rounded-lg border border-slate-200 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-slate-500" />
              <span>Export Events</span>
            </button>
          </div>
        </div>

        {/* Ingest Raw Data Box (Collapsible / expandable) */}
        <div className="mt-4 pt-4 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-500" />
              <span className="text-xs font-bold text-slate-800">Direct File & Raw Log Ingestion</span>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-500">Load sample attack log:</span>
              <button
                onClick={() => loadPresetLogs('brute')}
                className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 font-medium text-[11px] cursor-pointer"
              >
                Kerberos Spray (CSV)
              </button>
              <button
                onClick={() => loadPresetLogs('ransomware')}
                className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 font-medium text-[11px] cursor-pointer"
              >
                LockBit Ransomware (JSON)
              </button>
              <button
                onClick={() => loadPresetLogs('cloud')}
                className="px-2 py-0.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 font-medium text-[11px] cursor-pointer"
              >
                AWS CloudTrail PII Leak
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="md:col-span-3">
              <textarea
                value={rawTextInput}
                onChange={e => setRawTextInput(e.target.value)}
                placeholder="Paste raw log lines, CSV security records, JSON CloudTrail / Zeek events, or syslog stream..."
                rows={3}
                className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono text-xs text-slate-800 focus:outline-none focus:border-slate-400 focus:bg-white resize-y"
              />
            </div>

            <div className="flex flex-col gap-2 justify-between">
              <label className="flex-1 border-2 border-dashed border-slate-200 hover:border-slate-300 bg-slate-50 hover:bg-slate-100/80 rounded-lg flex flex-col items-center justify-center p-3 cursor-pointer text-center transition-colors">
                <Upload className="w-4 h-4 text-slate-500 mb-1" />
                <span className="text-xs font-semibold text-slate-700">Upload File</span>
                <span className="text-[10px] text-slate-500">.log, .csv, .json, .txt</span>
                <input
                  type="file"
                  accept=".log,.csv,.json,.txt"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>

              <button
                onClick={handlePasteIngest}
                disabled={!rawTextInput.trim() || isAnalyzing}
                className="w-full bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white text-xs font-semibold py-2 px-3 rounded-lg shadow-xs transition-all flex items-center justify-center gap-1.5 cursor-pointer"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Parse & Detect Threats</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {ingestStatus && (
            <div className="mt-2 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 p-2 rounded-lg flex items-center justify-between">
              <span>{ingestStatus}</span>
              <button onClick={() => setIngestStatus(null)} className="text-emerald-700 hover:text-emerald-900">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* 2. Filter & Search Controls */}
      <div className="bg-white border border-slate-200 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shadow-xs">
        <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter by IP, user, action, host, or payload..."
              className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-slate-400 focus:bg-white"
            />
          </div>

          <select
            value={selectedCategory}
            onChange={e => setSelectedCategory(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none font-medium"
          >
            <option value="ALL">All Categories</option>
            <option value="AUTH">AUTH (Kerberos/SSH)</option>
            <option value="FIREWALL">FIREWALL / Perimeter</option>
            <option value="ENDPOINT">ENDPOINT / EDR</option>
            <option value="NETWORK">NETWORK / NetFlow</option>
            <option value="CLOUD">CLOUD / AWS / GCP</option>
            <option value="EMAIL">EMAIL / Exchange</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none font-medium"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <label className="flex items-center gap-1.5 text-xs text-slate-700 cursor-pointer select-none bg-slate-50 px-2.5 py-1.5 rounded-lg border border-slate-200">
            <input
              type="checkbox"
              checked={onlyAnomalies}
              onChange={e => setOnlyAnomalies(e.target.checked)}
              className="rounded text-slate-900 focus:ring-0"
            />
            <span className="font-semibold text-rose-700">Anomalies Only</span>
          </label>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-500 font-mono">
          <span>Showing <b className="text-slate-900">{filteredEvents.length}</b> of {events.length}</span>
        </div>
      </div>

      {/* 3. Live Telemetry Stream Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto max-h-[540px]">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-50 text-slate-600 sticky top-0 z-10 border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-3 font-semibold">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-semibold">Category</th>
                <th className="py-2.5 px-3 font-semibold">Source IP / Geo</th>
                <th className="py-2.5 px-3 font-semibold">Destination / Asset</th>
                <th className="py-2.5 px-3 font-semibold">User Identity</th>
                <th className="py-2.5 px-3 font-semibold">Action / Event</th>
                <th className="py-2.5 px-3 font-semibold">Severity</th>
                <th className="py-2.5 px-3 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
              {filteredEvents.map(evt => {
                const isAnomaly = evt.isAnomaly;
                return (
                  <tr
                    key={evt.id}
                    className={`transition-colors cursor-pointer ${
                      isAnomaly
                        ? 'bg-rose-50/50 hover:bg-rose-50'
                        : 'hover:bg-slate-50/80'
                    }`}
                    onClick={() => setSelectedEvent(evt)}
                  >
                    <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                      {evt.timestamp.replace('T', ' ').replace('Z', '')}
                    </td>

                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="font-sans font-bold text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        {evt.eventCategory}
                      </span>
                    </td>

                    <td className="py-2 px-3 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className={`font-semibold ${isAnomaly ? 'text-rose-700' : 'text-slate-800'}`}>
                          {evt.sourceIp}
                        </span>
                        <span className="text-[10px] text-slate-400 font-sans">({evt.sourceCountry})</span>
                      </div>
                    </td>

                    <td className="py-2 px-3 text-slate-700 whitespace-nowrap">
                      <div>{evt.assetName}</div>
                      <div className="text-[10px] text-slate-400">{evt.destIp}:{evt.port}</div>
                    </td>

                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className="text-slate-800 font-medium">{evt.user}</span>
                    </td>

                    <td className="py-2 px-3">
                      <div className="font-semibold text-slate-900 max-w-xs truncate">{evt.action}</div>
                      <div className="text-[10px] text-slate-500 truncate max-w-sm">{evt.rawMessage}</div>
                    </td>

                    <td className="py-2 px-3 whitespace-nowrap">
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase font-sans ${
                          evt.severity === 'critical'
                            ? 'bg-rose-100 text-rose-700 border border-rose-200'
                            : evt.severity === 'high'
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : evt.severity === 'medium'
                            ? 'bg-blue-100 text-blue-800 border border-blue-200'
                            : 'bg-slate-100 text-slate-600 border border-slate-200'
                        }`}
                      >
                        {evt.severity}
                      </span>
                    </td>

                    <td className="py-2 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          setSelectedEvent(evt);
                        }}
                        className="text-slate-500 hover:text-slate-900 p-1 rounded hover:bg-slate-100"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Event Inspection Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-2xl w-full p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-slate-700" />
                <h3 className="text-sm font-bold text-slate-900">Security Telemetry Event Inspector</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-700 p-1 rounded-lg hover:bg-slate-100"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-500 text-[10px] block">Event ID</span>
                <span className="font-mono font-bold text-slate-800">{selectedEvent.id}</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-500 text-[10px] block">Source Entity</span>
                <span className="font-mono font-bold text-slate-800">{selectedEvent.sourceIp} ({selectedEvent.sourceCountry})</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-500 text-[10px] block">Destination Asset</span>
                <span className="font-mono font-bold text-slate-800">{selectedEvent.assetName}</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-500 text-[10px] block">User Identity</span>
                <span className="font-mono font-bold text-slate-800">{selectedEvent.user}</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-500 text-[10px] block">Action</span>
                <span className="font-mono font-bold text-slate-800">{selectedEvent.action}</span>
              </div>
              <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                <span className="text-slate-500 text-[10px] block">Severity</span>
                <span className="font-bold text-rose-700 uppercase">{selectedEvent.severity}</span>
              </div>
            </div>

            <div>
              <span className="text-xs font-bold text-slate-700 block mb-1">Raw Payload & Message:</span>
              <pre className="bg-slate-900 text-slate-100 p-3 rounded-lg font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                {selectedEvent.rawMessage}
              </pre>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                onClick={() => handleCopyEvent(selectedEvent)}
                className="flex items-center gap-1 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1.5 rounded-lg border border-slate-200 font-medium"
              >
                {copiedEventId === selectedEvent.id ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copiedEventId === selectedEvent.id ? 'Copied' : 'Copy JSON'}</span>
              </button>

              <button
                onClick={() => setSelectedEvent(null)}
                className="bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold px-4 py-1.5 rounded-lg shadow-xs"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
