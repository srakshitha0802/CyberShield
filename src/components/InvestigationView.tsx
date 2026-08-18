import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  ShieldAlert,
  Search,
  CheckCircle,
  AlertTriangle,
  Flame,
  FileText,
  Copy,
  Download,
  Terminal,
  Server,
  Activity,
  Layers,
  ChevronRight,
  ExternalLink,
  Sparkles,
  RefreshCw,
  Lock,
  Zap,
  Globe,
  Radio,
  Check,
  Play,
  Clock,
  FileDown,
} from 'lucide-react';
import { ThreatAlert, IoCRecord } from '../types/security';
import { exportThreatInvestigationPDF } from '../utils/pdfExport';

interface InvestigationViewProps {
  onOpenReportModal: (threat: ThreatAlert) => void;
}

export const InvestigationView: React.FC<InvestigationViewProps> = ({ onOpenReportModal }) => {
  const {
    threats,
    selectedThreatId,
    setSelectedThreatId,
    executePlaybookAction,
    updateThreatStatus,
    analyzeThreatWithAI,
    isAnalyzing,
    events,
    setActiveTab,
  } = useSecurity();

  const [activeTabSub, setActiveTabSub] = useState<'overview' | 'pattern' | 'mitre' | 'iocs' | 'assets' | 'logs' | 'playbook'>('overview');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);
  const [logFilterQuery, setLogFilterQuery] = useState<string>('');

  const currentThreat = threats.find(t => t.id === selectedThreatId) || threats[0];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(text);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  // Correlated logs
  const correlatedLogs = events.filter(e =>
    currentThreat.sourceIps.includes(e.sourceIp) ||
    currentThreat.targetAccounts.includes(e.user) ||
    currentThreat.affectedAssets.some(a => a.name === e.assetName || a.ip === e.destIp) ||
    (e.threatCode && e.threatCode === currentThreat.threatCode)
  );

  const filteredLogs = correlatedLogs.filter(l =>
    logFilterQuery ? l.rawMessage.toLowerCase().includes(logFilterQuery.toLowerCase()) || l.sourceIp.includes(logFilterQuery) : true
  );

  const isContained = currentThreat.status === 'contained' || currentThreat.status === 'remediated';

  return (
    <div className="space-y-6 pb-12">
      {/* 1. Top Threat Selector & Actions Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Select Incident:</span>
            <select
              value={currentThreat.id}
              onChange={e => setSelectedThreatId(e.target.value)}
              className="bg-slate-50 border border-slate-200 text-slate-900 font-mono font-bold text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-slate-400"
            >
              {threats.map(t => (
                <option key={t.id} value={t.id}>
                  [{t.threatCode}] {t.title.substring(0, 40)}... ({t.severity})
                </option>
              ))}
            </select>
          </div>

          <span
            className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
              currentThreat.severity === 'critical'
                ? 'bg-rose-100 text-rose-700 border border-rose-200'
                : 'bg-amber-100 text-amber-800 border border-amber-200'
            }`}
          >
            {currentThreat.severity}
          </span>

          <span
            className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
              isContained
                ? 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                : 'bg-indigo-100 text-indigo-700 border border-indigo-200'
            }`}
          >
            Status: {currentThreat.status}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => analyzeThreatWithAI(currentThreat.id)}
            disabled={isAnalyzing}
            className="flex items-center gap-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs px-3 py-1.5 rounded-lg border border-slate-200 transition-colors font-semibold cursor-pointer"
          >
            {isAnalyzing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5 text-indigo-600" />}
            <span>Re-Analyze with AI</span>
          </button>

          <button
            id="btn-export-pdf-dossier"
            onClick={() => exportThreatInvestigationPDF(currentThreat)}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg shadow-xs transition-all cursor-pointer"
          >
            <FileDown className="w-3.5 h-3.5 text-indigo-200" />
            <span>Export Investigation PDF</span>
          </button>

          <button
            id="btn-generate-report"
            onClick={() => onOpenReportModal(currentThreat)}
            className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg shadow-xs transition-all cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>NIST Dossier</span>
          </button>
        </div>
      </div>

      {/* 2. Main Threat Headline Card */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs relative overflow-hidden space-y-4">
        <div className="flex flex-col lg:flex-row items-start justify-between gap-4">
          <div className="space-y-2 max-w-4xl">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold text-slate-900 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded">
                {currentThreat.threatCode}
              </span>
              <span className="text-xs text-slate-500 font-medium">Incident Investigation Dossier</span>
            </div>

            <h1 className="text-xl font-bold text-slate-900">{currentThreat.title}</h1>
            <p className="text-xs text-slate-600 leading-relaxed">{currentThreat.aiSummary}</p>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-3 shrink-0">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 text-center min-w-[110px]">
              <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wider">AI Confidence</div>
              <div className="text-xl font-bold font-mono text-indigo-600 mt-0.5">{currentThreat.confidence}%</div>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 text-center min-w-[110px]">
              <div className="text-[10px] text-slate-500 font-medium uppercase tracking-wider">Risk Index</div>
              <div className={`text-xl font-bold font-mono mt-0.5 ${currentThreat.riskScore > 80 ? 'text-rose-600' : 'text-amber-600'}`}>
                {currentThreat.riskScore}/100
              </div>
            </div>
          </div>
        </div>

        {/* Quick Metadata Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-100 text-xs">
          <div>
            <span className="text-slate-400 text-[11px] block">Attacking Source:</span>
            <span className="font-mono font-bold text-rose-700">{currentThreat.sourceIps[0] || 'Unknown'}</span>
          </div>
          <div>
            <span className="text-slate-400 text-[11px] block">Target Account:</span>
            <span className="font-mono font-bold text-slate-800">{currentThreat.targetAccounts[0] || 'System'}</span>
          </div>
          <div>
            <span className="text-slate-400 text-[11px] block">Compromised Host:</span>
            <span className="font-mono font-bold text-slate-800">{currentThreat.affectedAssets[0]?.name || 'N/A'}</span>
          </div>
          <div>
            <span className="text-slate-400 text-[11px] block">First Detected:</span>
            <span className="font-mono text-slate-600">{currentThreat.firstDetected}</span>
          </div>
        </div>
      </div>

      {/* 3. Sub-Navigation Tabs */}
      <div className="flex border-b border-slate-200 bg-white rounded-t-xl px-4 overflow-x-auto scrollbar-none shadow-xs">
        {[
          { id: 'overview', label: 'Executive & Root Cause' },
          { id: 'pattern', label: 'Kill Chain Timeline', count: currentThreat.attackPattern.length },
          { id: 'mitre', label: 'MITRE ATT&CK Matrix', count: currentThreat.mitreAttack.length },
          { id: 'iocs', label: 'Extracted IoCs', count: currentThreat.iocs.length },
          { id: 'assets', label: 'Blast Radius & Assets', count: currentThreat.affectedAssets.length },
          { id: 'playbook', label: 'Containment Playbook', count: currentThreat.recommendedActions.length },
          { id: 'logs', label: 'Correlated Logs', count: correlatedLogs.length },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTabSub(tab.id as any)}
            className={`py-3 px-4 text-xs font-medium border-b-2 transition-colors whitespace-nowrap cursor-pointer flex items-center gap-1.5 ${
              activeTabSub === tab.id
                ? 'border-slate-900 text-slate-900 font-bold bg-slate-50/50'
                : 'border-transparent text-slate-500 hover:text-slate-800 hover:bg-slate-50/30'
            }`}
          >
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span className="bg-slate-100 text-slate-600 text-[10px] font-mono font-bold px-1.5 py-0.2 rounded-full border border-slate-200">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* 4. Tab Contents */}

      {/* Overview / Deep Reasoning Tab */}
      {activeTabSub === 'overview' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-6">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-indigo-600" />
              Detailed AI Forensic Reasoning & Root Cause Analysis
            </h2>
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mt-3 text-xs text-slate-700 leading-relaxed font-sans whitespace-pre-wrap">
              {currentThreat.detailedReasoning}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-50/80 border border-slate-200 rounded-xl p-4">
              <h3 className="text-xs font-bold text-slate-900 mb-2 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-600" />
                Key Threat Indicators
              </h3>
              <ul className="space-y-1.5 text-xs text-slate-600">
                {currentThreat.iocs.map(ioc => (
                  <li key={ioc.id} className="flex items-center justify-between font-mono bg-white p-2 rounded border border-slate-200">
                    <span className="font-semibold text-slate-900">{ioc.value}</span>
                    <span className="text-[10px] text-rose-700 bg-rose-50 px-1.5 py-0.2 rounded font-sans uppercase font-bold">
                      {ioc.reputation}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-slate-50/80 border border-slate-200 rounded-xl p-4">
              <h3 className="text-xs font-bold text-slate-900 mb-2 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4 text-indigo-600" />
                Target Blast Radius
              </h3>
              <ul className="space-y-1.5 text-xs text-slate-600">
                {currentThreat.affectedAssets.map(asset => (
                  <li key={asset.id} className="flex items-center justify-between font-mono bg-white p-2 rounded border border-slate-200">
                    <div>
                      <span className="font-semibold text-slate-900 block">{asset.name}</span>
                      <span className="text-[10px] text-slate-400">{asset.ip} • {asset.role}</span>
                    </div>
                    <span className="text-[10px] bg-indigo-50 text-indigo-700 px-1.5 py-0.2 rounded font-sans font-bold">
                      {asset.criticality}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Kill Chain Timeline */}
      {activeTabSub === 'pattern' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-bold text-slate-900">Chronological Adversary Attack Pattern & Kill Chain</h2>
            <span className="text-xs font-mono text-slate-500">NIST SP 800-61 Timeline</span>
          </div>

          <div className="relative border-l-2 border-slate-200 ml-4 space-y-6 py-2">
            {currentThreat.attackPattern.map(step => (
              <div key={step.step} className="relative pl-6">
                <div className="absolute -left-[9px] top-1 w-4 h-4 rounded-full bg-slate-900 border-2 border-white flex items-center justify-center text-[9px] font-bold text-white">
                  {step.step}
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-slate-900">{step.phase}</span>
                      <span className="bg-slate-200 text-slate-800 text-[10px] font-mono px-2 py-0.5 rounded font-semibold">
                        {step.technique}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">{step.timestamp}</span>
                  </div>

                  <p className="text-xs text-slate-600 leading-relaxed">{step.description}</p>

                  <div className="pt-2 border-t border-slate-200/80 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-500">Indicator: <b className="text-slate-900">{step.indicator}</b></span>
                    <span className="text-rose-700 bg-rose-50 px-2 py-0.5 rounded text-[10px] font-sans uppercase font-bold">
                      {step.status}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK Matrix Tab */}
      {activeTabSub === 'mitre' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900">Mapped MITRE ATT&CK Framework Techniques</h2>
            <span className="text-xs font-mono text-slate-500">v14 Enterprise Matrix</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {currentThreat.mitreAttack.map(m => (
              <div key={m.id} className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold bg-slate-900 text-white px-2 py-0.5 rounded">
                      {m.id}
                    </span>
                    <span className="text-xs font-bold text-slate-900">{m.name}</span>
                  </div>
                  <span className="text-[10px] bg-slate-200 text-slate-700 px-2 py-0.5 rounded font-medium">
                    {m.tactic}
                  </span>
                </div>

                <p className="text-xs text-slate-600 leading-relaxed">{m.description}</p>

                <div className="pt-2">
                  <a
                    href={m.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[11px] text-slate-700 hover:text-slate-900 font-semibold flex items-center gap-1"
                  >
                    <span>View in Official MITRE ATT&CK Knowledge Base</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Extracted IoCs Tab */}
      {activeTabSub === 'iocs' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900">Extracted Threat Artifacts & Indicators of Compromise</h2>
            <button
              onClick={() => setActiveTab('iocs')}
              className="text-xs text-slate-700 hover:text-slate-900 font-semibold flex items-center gap-1"
            >
              <span>Explore All Global IoCs</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
                <tr>
                  <th className="py-2.5 px-3 font-semibold">Artifact Type</th>
                  <th className="py-2.5 px-3 font-semibold">Indicator Value</th>
                  <th className="py-2.5 px-3 font-semibold">Risk Level</th>
                  <th className="py-2.5 px-3 font-semibold">Threat Intel Reputation</th>
                  <th className="py-2.5 px-3 font-semibold">Context Notes</th>
                  <th className="py-2.5 px-3 font-semibold text-right">Copy</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                {currentThreat.iocs.map(ioc => (
                  <tr key={ioc.id} className="hover:bg-slate-50">
                    <td className="py-2.5 px-3 font-sans uppercase font-bold text-slate-700">
                      {ioc.type}
                    </td>
                    <td className="py-2.5 px-3 font-bold text-slate-900 select-all">
                      {ioc.value}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase bg-rose-100 text-rose-700 font-sans">
                        {ioc.risk}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-600 font-sans">
                      {ioc.reputation}
                    </td>
                    <td className="py-2.5 px-3 text-slate-500 font-sans">
                      {ioc.notes}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => handleCopy(ioc.value)}
                        className="p-1 text-slate-400 hover:text-slate-800 rounded"
                      >
                        {copiedValue === ioc.value ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Affected Assets Tab */}
      {activeTabSub === 'assets' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-4">
          <h2 className="text-sm font-bold text-slate-900">Targeted Assets & Host Posture Assessment</h2>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {currentThreat.affectedAssets.map(asset => (
              <div key={asset.id} className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-slate-700" />
                    <span className="font-bold text-slate-900 text-xs">{asset.name}</span>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-100 text-indigo-700 font-mono">
                    {asset.criticality}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-white p-2.5 rounded border border-slate-200">
                  <div>
                    <span className="text-[10px] text-slate-400 block font-sans">IP Address:</span>
                    <span className="text-slate-800 font-bold">{asset.ip}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-slate-400 block font-sans">OS / Environment:</span>
                    <span className="text-slate-800">{asset.os}</span>
                  </div>
                </div>

                <div className="text-xs">
                  <span className="text-slate-500 font-medium block mb-1">Identified Weaknesses:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {asset.vulnerabilities.map((v, i) => (
                      <span key={i} className="text-[10px] bg-rose-50 text-rose-700 border border-rose-200 px-2 py-0.5 rounded font-mono">
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Containment Playbook Tab */}
      {activeTabSub === 'playbook' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Incident Containment & Remediation Playbook</h2>
              <p className="text-xs text-slate-500 mt-0.5">Automated mitigation commands ready for live execution</p>
            </div>
          </div>

          <div className="space-y-4">
            {currentThreat.recommendedActions.map(action => (
              <div
                key={action.id}
                className={`p-4 rounded-xl border transition-all ${
                  action.executed
                    ? 'bg-emerald-50/60 border-emerald-200'
                    : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-200 text-slate-800 font-mono">
                      {action.priority}
                    </span>
                    <span className="text-xs font-bold text-slate-900">{action.title}</span>
                  </div>

                  <button
                    onClick={() => executePlaybookAction(currentThreat.id, action.id)}
                    disabled={action.executed}
                    className={`text-xs font-semibold px-4 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                      action.executed
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-200 cursor-default'
                        : 'bg-slate-900 hover:bg-slate-800 text-white shadow-xs'
                    }`}
                  >
                    {action.executed ? (
                      <>
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                        <span>Action Executed</span>
                      </>
                    ) : (
                      <>
                        <Zap className="w-3.5 h-3.5 text-amber-300" />
                        <span>Execute Containment</span>
                      </>
                    )}
                  </button>
                </div>

                <p className="text-xs text-slate-600 mt-2 leading-relaxed">{action.action}</p>

                {action.commandSnippet && (
                  <div className="mt-3">
                    <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
                      <span>Synthesized Command:</span>
                      <button
                        onClick={() => handleCopy(action.commandSnippet!)}
                        className="text-slate-600 hover:text-slate-900 flex items-center gap-1"
                      >
                        {copiedValue === action.commandSnippet ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>Copy Script</span>
                      </button>
                    </div>
                    <pre className="bg-slate-900 text-slate-100 p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto">
                      {action.commandSnippet}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Correlated Logs Tab */}
      {activeTabSub === 'logs' && (
        <div className="bg-white border border-slate-200 rounded-b-xl p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-bold text-slate-900">Correlated Raw Telemetry ({filteredLogs.length} Events)</h2>
            <input
              type="text"
              value={logFilterQuery}
              onChange={e => setLogFilterQuery(e.target.value)}
              placeholder="Search correlated logs..."
              className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-1 text-xs text-slate-800 w-64 focus:outline-none"
            />
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto font-mono text-[11px]">
            {filteredLogs.map(log => (
              <div key={log.id} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 hover:bg-slate-100/60">
                <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                  <span>{log.timestamp} • {log.eventCategory}</span>
                  <span className="text-rose-700 font-bold">{log.sourceIp} → {log.destIp}</span>
                </div>
                <div className="text-slate-800 whitespace-pre-wrap">{log.rawMessage}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
