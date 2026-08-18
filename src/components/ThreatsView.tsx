import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowUpRight,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Sparkles,
  Zap,
  Sliders,
  ExternalLink,
  Lock,
  Server,
  Activity,
  FileDown,
} from 'lucide-react';
import { ThreatAlert, Severity, ThreatStatus } from '../types/security';
import { exportThreatInvestigationPDF } from '../utils/pdfExport';

export const ThreatsView: React.FC = () => {
  const {
    threats,
    setSelectedThreatId,
    setActiveTab,
    executePlaybookAction,
    updateThreatStatus,
    analyzeThreatWithAI,
    isAnalyzing,
  } = useSecurity();

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredThreats = threats.filter(t => {
    if (severityFilter !== 'ALL' && t.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && t.status !== statusFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        t.threatCode.toLowerCase().includes(q) ||
        t.title.toLowerCase().includes(q) ||
        t.threatType.toLowerCase().includes(q) ||
        t.sourceIps.some(ip => ip.includes(q)) ||
        t.affectedAssets.some(a => a.name.toLowerCase().includes(q)) ||
        t.targetAccounts.some(u => u.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleInvestigate = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab('investigation');
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
            <h1 className="text-base font-bold text-slate-900">Threat Detection & Incident Queue</h1>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Correlated multi-source security incidents classified with AI confidence, IoCs, and containment playbooks.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              if (threats[0]) analyzeThreatWithAI(threats[0].id);
            }}
            disabled={isAnalyzing}
            className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs transition-all cursor-pointer"
          >
            {isAnalyzing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5 text-indigo-400" />}
            <span>Run Deep AI Triage</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 shadow-xs">
        <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
          <div className="relative flex-1 min-w-[220px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by Threat ID (TH-1042), IP, asset, or title..."
              className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-slate-400 focus:bg-white"
            />
          </div>

          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none font-medium"
          >
            <option value="ALL">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none font-medium"
          >
            <option value="ALL">All Statuses</option>
            <option value="investigating">Investigating</option>
            <option value="open">Open</option>
            <option value="contained">Contained</option>
            <option value="remediated">Remediated</option>
          </select>
        </div>

        <span className="text-xs text-slate-500 font-mono">
          Showing <b className="text-slate-900">{filteredThreats.length}</b> Incidents
        </span>
      </div>

      {/* Threats Grid / List */}
      <div className="grid grid-cols-1 gap-4">
        {filteredThreats.map(threat => {
          const isContained = threat.status === 'contained' || threat.status === 'remediated';

          return (
            <div
              key={threat.id}
              className="bg-white border border-slate-200 hover:border-slate-300 rounded-xl p-5 shadow-xs transition-all space-y-4"
            >
              {/* Card Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-200">
                    {threat.threatCode}
                  </span>

                  <span
                    className={`text-[10px] font-bold px-2.5 py-0.5 rounded uppercase ${
                      threat.severity === 'critical'
                        ? 'bg-rose-100 text-rose-700 border border-rose-200'
                        : threat.severity === 'high'
                        ? 'bg-amber-100 text-amber-800 border border-amber-200'
                        : 'bg-blue-100 text-blue-800 border border-blue-200'
                    }`}
                  >
                    {threat.severity}
                  </span>

                  <span
                    className={`text-[10px] font-bold px-2.5 py-0.5 rounded uppercase ${
                      isContained
                        ? 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                        : 'bg-indigo-100 text-indigo-700 border border-indigo-200'
                    }`}
                  >
                    {threat.status}
                  </span>

                  <span className="text-xs text-slate-500 font-medium">
                    Category: <b className="text-slate-800">{threat.threatType}</b>
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => exportThreatInvestigationPDF(threat)}
                    title="Export Threat Forensic Report to PDF"
                    className="flex items-center gap-1 text-xs bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-200 px-2.5 py-1.5 rounded-lg font-medium shadow-2xs transition-colors cursor-pointer"
                  >
                    <FileDown className="w-3.5 h-3.5" />
                    <span>PDF</span>
                  </button>

                  <button
                    onClick={() => handleInvestigate(threat.id)}
                    className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg shadow-xs transition-all cursor-pointer"
                  >
                    <span>Investigate</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </button>

                  <select
                    value={threat.status}
                    onChange={e => updateThreatStatus(threat.id, e.target.value as ThreatStatus)}
                    className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2 py-1.5 focus:outline-none font-medium cursor-pointer"
                  >
                    <option value="investigating">Status: Investigating</option>
                    <option value="open">Status: Open</option>
                    <option value="contained">Status: Contained</option>
                    <option value="remediated">Status: Remediated</option>
                    <option value="false_positive">Status: False Positive</option>
                  </select>
                </div>
              </div>

              {/* Title & AI Summary */}
              <div>
                <h2 className="text-base font-bold text-slate-900">{threat.title}</h2>
                <p className="text-xs text-slate-600 mt-1 leading-relaxed">{threat.aiSummary}</p>
              </div>

              {/* Badges / Assets / Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 bg-slate-50/80 p-3 rounded-lg border border-slate-100 text-xs">
                <div>
                  <span className="text-slate-500 text-[10px] block font-medium">Attacker Origin</span>
                  <span className="font-mono font-bold text-rose-700">{threat.sourceIps[0] || 'Unknown'}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block font-medium">Primary Asset</span>
                  <span className="font-mono font-bold text-slate-800">{threat.affectedAssets[0]?.name || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block font-medium">Risk Index & Confidence</span>
                  <span className="font-mono font-bold text-slate-800">{threat.riskScore}/100 • {threat.confidence}% Conf</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block font-medium">Extracted IoCs</span>
                  <span className="font-mono font-bold text-indigo-700">{threat.iocs.length} Artifacts</span>
                </div>
              </div>

              {/* Containment Playbook Quick Actions */}
              <div className="pt-2 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-slate-500 font-medium">Quick Playbooks:</span>
                  {threat.recommendedActions.slice(0, 2).map(action => (
                    <button
                      key={action.id}
                      onClick={() => executePlaybookAction(threat.id, action.id)}
                      disabled={action.executed}
                      className={`px-2.5 py-1 rounded text-xs font-semibold transition-colors flex items-center gap-1 cursor-pointer ${
                        action.executed
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 cursor-default'
                          : 'bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-200'
                      }`}
                    >
                      {action.executed ? <CheckCircle className="w-3 h-3 text-emerald-600" /> : <Zap className="w-3 h-3 text-amber-500" />}
                      <span>{action.executed ? 'Executed' : action.title}</span>
                    </button>
                  ))}
                </div>

                <span className="text-[11px] text-slate-400 font-mono">First seen: {threat.firstDetected}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
