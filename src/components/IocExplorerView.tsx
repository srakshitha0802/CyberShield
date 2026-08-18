import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Radar,
  Search,
  Filter,
  Download,
  Copy,
  Globe,
  Check,
  ShieldAlert,
  ExternalLink,
  Tag,
  Layers,
  Sparkles,
  RefreshCw,
  Plus,
  X,
  Radio,
} from 'lucide-react';
import { IoCRecord, Severity } from '../types/security';

export const IocExplorerView: React.FC = () => {
  const { getAllIocs, setSelectedThreatId, setActiveTab, threats } = useSecurity();

  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Live Threat Intel Lookup state
  const [lookupInput, setLookupInput] = useState('185.220.101.5');
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [lookupResult, setLookupResult] = useState<any | null>(null);

  const iocs = getAllIocs();

  const filteredIocs = iocs.filter(ioc => {
    if (typeFilter !== 'ALL' && ioc.type !== typeFilter) return false;
    if (riskFilter !== 'ALL' && ioc.risk !== riskFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        ioc.value.toLowerCase().includes(q) ||
        ioc.reputation.toLowerCase().includes(q) ||
        ioc.notes.toLowerCase().includes(q) ||
        ioc.associatedThreats.some(t => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(text);
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleRunLookup = async (customQuery?: string) => {
    const target = customQuery || lookupInput;
    if (!target.trim()) return;

    setIsLookingUp(true);
    try {
      const res = await fetch('/api/lookup-ioc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: target }),
      });
      if (res.ok) {
        const data = await res.json();
        setLookupResult(data.data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsLookingUp(false);
    }
  };

  const exportIocsAsJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredIocs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `cybershield_iocs_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportIocsAsCsv = () => {
    const headers = ['Type', 'Value', 'Risk', 'AssociatedThreats', 'Occurrences', 'Reputation', 'Notes'];
    const rows = filteredIocs.map(ioc => [
      ioc.type,
      `"${ioc.value}"`,
      ioc.risk,
      `"${ioc.associatedThreats.join(';')}"`,
      ioc.occurrences,
      `"${ioc.reputation}"`,
      `"${ioc.notes}"`,
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `cybershield_iocs_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Radar className="w-5 h-5 text-indigo-600" />
            <h1 className="text-base font-bold text-slate-900">Global Indicators of Compromise (IoC) Explorer</h1>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time extracted threat artifacts correlated across enterprise telemetry with live reputation intelligence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportIocsAsJson}
            className="flex items-center gap-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs px-3.5 py-1.5 rounded-lg border border-slate-200 transition-colors font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={exportIocsAsCsv}
            className="flex items-center gap-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs px-3.5 py-1.5 rounded-lg border border-slate-200 transition-colors font-medium cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-slate-500" />
            <span>Export CSV / STIX</span>
          </button>
        </div>
      </div>

      {/* Live Threat Intel Intelligence Lookup Tool */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-indigo-600" />
              Live Threat Intel & Reputation Lookup
            </h2>
            <p className="text-xs text-slate-500">
              Query any IP address, domain, file hash, or URL for instant WHOIS, ASN, abuse score, and threat actor attribution.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Quick tests:</span>
            <button
              onClick={() => { setLookupInput('185.220.101.5'); handleRunLookup('185.220.101.5'); }}
              className="text-[11px] bg-slate-100 hover:bg-slate-200 text-slate-700 px-2 py-0.5 rounded border border-slate-200 font-mono"
            >
              185.220.101.5
            </button>
            <button
              onClick={() => { setLookupInput('micosoft-verify-auth.com'); handleRunLookup('micosoft-verify-auth.com'); }}
              className="text-[11px] bg-slate-100 hover:bg-slate-200 text-slate-700 px-2 py-0.5 rounded border border-slate-200 font-mono"
            >
              micosoft-verify-auth.com
            </button>
            <button
              onClick={() => { setLookupInput('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); handleRunLookup('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); }}
              className="text-[11px] bg-slate-100 hover:bg-slate-200 text-slate-700 px-2 py-0.5 rounded border border-slate-200 font-mono"
            >
              LockBit Hash
            </button>
          </div>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={lookupInput}
            onChange={e => setLookupInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleRunLookup()}
            placeholder="Enter IP address (e.g. 185.220.101.5), domain name, or SHA256 file hash..."
            className="flex-1 bg-slate-50 border border-slate-200 rounded-lg px-3.5 py-2 text-xs font-mono text-slate-900 focus:outline-none focus:border-slate-400 focus:bg-white"
          />
          <button
            onClick={() => handleRunLookup()}
            disabled={isLookingUp}
            className="bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs flex items-center gap-1.5 cursor-pointer"
          >
            {isLookingUp ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>Lookup Intel</span>
          </button>
        </div>

        {/* Lookup Result Box */}
        {lookupResult && (
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3 mt-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 pb-3">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-slate-900 bg-white border border-slate-200 px-2 py-0.5 rounded">
                  {lookupResult.indicator}
                </span>
                <span className="text-xs font-bold text-rose-700 bg-rose-50 px-2 py-0.5 rounded uppercase">
                  Risk: {lookupResult.risk} ({lookupResult.reputationScore}% Malicious)
                </span>
              </div>
              <span className="text-xs text-slate-500 font-mono">Actor: <b className="text-slate-800">{lookupResult.threatActorAttribution}</b></span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-slate-400 text-[10px] block">Classification</span>
                <span className="font-semibold text-slate-800">{lookupResult.threatClassification}</span>
              </div>
              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-slate-400 text-[10px] block">Country & ASN</span>
                <span className="font-semibold text-slate-800">{lookupResult.country} ({lookupResult.asn})</span>
              </div>
              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-slate-400 text-[10px] block">Community Abuse Score</span>
                <span className="font-semibold text-rose-700">{lookupResult.abuseConfidence}</span>
              </div>
              <div className="bg-white p-2.5 rounded border border-slate-200">
                <span className="text-slate-400 text-[10px] block">Associated Malware</span>
                <span className="font-semibold text-slate-800">{lookupResult.associatedMalware?.join(', ') || 'Various'}</span>
              </div>
            </div>

            <div className="bg-white p-3 rounded border border-slate-200 text-xs">
              <span className="text-slate-500 font-bold block mb-1">Recommended Containment Action:</span>
              <p className="text-slate-700 font-medium">{lookupResult.recommendedAction}</p>
            </div>
          </div>
        )}
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
              placeholder="Search artifacts, IP, domain, hash, or CVE..."
              className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-slate-400 focus:bg-white"
            />
          </div>

          <select
            value={typeFilter}
            onChange={e => setTypeFilter(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none font-medium"
          >
            <option value="ALL">All Types</option>
            <option value="ip">IP Addresses</option>
            <option value="domain">Domains</option>
            <option value="url">URLs</option>
            <option value="hash">Hashes</option>
            <option value="email">Emails</option>
            <option value="user">Users</option>
          </select>

          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
            className="bg-slate-50 border border-slate-200 text-slate-700 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none font-medium"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <span className="text-xs text-slate-500 font-mono">
          Showing <b className="text-slate-900">{filteredIocs.length}</b> Artifacts
        </span>
      </div>

      {/* IoCs Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-slate-50 text-slate-600 border-b border-slate-200">
              <tr>
                <th className="py-3 px-4 font-semibold">Artifact Type</th>
                <th className="py-3 px-4 font-semibold">Indicator Value</th>
                <th className="py-3 px-4 font-semibold">Risk Rating</th>
                <th className="py-3 px-4 font-semibold">Associated Incidents</th>
                <th className="py-3 px-4 font-semibold">Occurrences</th>
                <th className="py-3 px-4 font-semibold">Threat Intel Reputation</th>
                <th className="py-3 px-4 font-semibold">Notes</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
              {filteredIocs.map(ioc => (
                <tr key={ioc.id} className="hover:bg-slate-50/80 transition-colors">
                  <td className="py-2.5 px-4 font-sans font-bold text-slate-700 uppercase">
                    <span className="bg-slate-100 px-2 py-0.5 rounded border border-slate-200 text-[10px]">
                      {ioc.type}
                    </span>
                  </td>

                  <td className="py-2.5 px-4 font-bold text-slate-900 select-all">
                    {ioc.value}
                  </td>

                  <td className="py-2.5 px-4">
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase font-sans ${
                        ioc.risk === 'critical'
                          ? 'bg-rose-100 text-rose-700 border border-rose-200'
                          : ioc.risk === 'high'
                          ? 'bg-amber-100 text-amber-800 border border-amber-200'
                          : 'bg-blue-100 text-blue-800 border border-blue-200'
                      }`}
                    >
                      {ioc.risk}
                    </span>
                  </td>

                  <td className="py-2.5 px-4">
                    <div className="flex flex-wrap gap-1">
                      {ioc.associatedThreats.map((code, idx) => (
                        <span key={idx} className="bg-slate-100 text-slate-700 px-1.5 py-0.2 rounded text-[10px] border border-slate-200">
                          {code}
                        </span>
                      ))}
                    </div>
                  </td>

                  <td className="py-2.5 px-4 text-slate-700">
                    {ioc.occurrences} hits
                  </td>

                  <td className="py-2.5 px-4 text-slate-700 font-sans">
                    {ioc.reputation}
                  </td>

                  <td className="py-2.5 px-4 text-slate-500 font-sans truncate max-w-xs">
                    {ioc.notes}
                  </td>

                  <td className="py-2.5 px-4 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => {
                          setLookupInput(ioc.value);
                          handleRunLookup(ioc.value);
                        }}
                        title="Lookup Live Intelligence"
                        className="p-1 text-slate-500 hover:text-indigo-600 rounded hover:bg-slate-100 cursor-pointer"
                      >
                        <Search className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => handleCopy(ioc.value)}
                        title="Copy Indicator Value"
                        className="p-1 text-slate-500 hover:text-slate-900 rounded hover:bg-slate-100 cursor-pointer"
                      >
                        {copiedValue === ioc.value ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
