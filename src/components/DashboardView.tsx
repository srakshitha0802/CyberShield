import React from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Activity,
  ArrowUpRight,
  Server,
  Lock,
  Radio,
  Zap,
  TrendingUp,
  Cpu,
  Clock,
  ChevronRight,
  Sparkles,
  ExternalLink,
  Layers,
  FileDown,
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, BarChart, Bar, Cell, PieChart, Pie } from 'recharts';
import { exportDashboardExecutiveReportPDF } from '../utils/pdfExport';

interface DashboardViewProps {
  onOpenSimulateModal: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ onOpenSimulateModal }) => {
  const {
    threats,
    events,
    campaigns,
    setSelectedThreatId,
    setActiveTab,
    executePlaybookAction,
  } = useSecurity();

  const totalThreats = threats.length;
  const criticalThreats = threats.filter(t => t.severity === 'critical');
  const highThreats = threats.filter(t => t.severity === 'high');
  const mediumThreats = threats.filter(t => t.severity === 'medium');
  const lowThreats = threats.filter(t => t.severity === 'low');
  const activeUncontained = threats.filter(t => t.status !== 'contained' && t.status !== 'remediated');

  const overallRiskScore = Math.max(...threats.map(t => t.riskScore), 65);
  const isCritical = criticalThreats.some(t => t.status !== 'contained' && t.status !== 'remediated');

  // Category counts
  const categoryCounts: Record<string, number> = {};
  threats.forEach(t => {
    categoryCounts[t.threatType] = (categoryCounts[t.threatType] || 0) + 1;
  });

  const categoryChartData = Object.entries(categoryCounts).map(([name, value]) => ({
    name: name.replace(' Attack', '').replace(' Outbreak', ''),
    count: value,
  }));

  // Timeline data for 24h attack volume
  const timelineData = [
    { time: '00:00', totalEvents: 1420, threats: 1 },
    { time: '00:30', totalEvents: 1890, threats: 2 },
    { time: '01:00', totalEvents: 3400, threats: 5 },
    { time: '01:30', totalEvents: 5200, threats: 8 },
    { time: '02:00', totalEvents: 7800, threats: 14 },
    { time: '02:30', totalEvents: 4100, threats: 6 },
  ];

  const severityPieData = [
    { name: 'Critical', value: criticalThreats.length, color: '#e11d48' },
    { name: 'High', value: highThreats.length, color: '#f59e0b' },
    { name: 'Medium', value: mediumThreats.length, color: '#3b82f6' },
    { name: 'Low', value: lowThreats.length, color: '#10b981' },
  ];

  const handleInvestigate = (threatId: string) => {
    setSelectedThreatId(threatId);
    setActiveTab('investigation');
  };

  return (
    <div className="space-y-6 pb-12">
      {/* 1. Top Threat Alert Banner */}
      <div
        id="dashboard-posture-banner"
        className={`p-5 rounded-2xl border transition-all ${
          isCritical
            ? 'bg-white border-rose-200 shadow-xs'
            : 'bg-white border-emerald-200 shadow-xs'
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div
              className={`w-11 h-11 rounded-xl flex items-center justify-center border shrink-0 ${
                isCritical
                  ? 'bg-rose-50 border-rose-200 text-rose-600'
                  : 'bg-emerald-50 border-emerald-200 text-emerald-600'
              }`}
            >
              {isCritical ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span
                  className={`text-[11px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                    isCritical ? 'bg-rose-100 text-rose-800 border border-rose-200' : 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                  }`}
                >
                  {isCritical ? 'CRITICAL THREAT ACTIVE' : 'SYSTEM POSTURE SECURE'}
                </span>
                <span className="text-slate-500 text-xs flex items-center gap-1">
                  <Cpu className="w-3.5 h-3.5 text-indigo-600" />
                  Qwen & Gemini 3.7 Flash Intelligence Active
                </span>
              </div>
              <h1 className="text-lg font-bold text-slate-900 mt-1">
                {isCritical
                  ? `${criticalThreats.length} Critical Threat(s) Require Immediate SOC Containment`
                  : 'All Ingress Telemetry Within Normal Baselines'}
              </h1>
              <p className="text-slate-600 text-xs mt-0.5 max-w-3xl">
                CyberShield AI is continuously correlating raw syslog, firewall drops, auth feeds, and CloudTrail events. Real-time reasoning and IoC extraction active.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <button
              id="btn-dash-export-pdf"
              onClick={() => exportDashboardExecutiveReportPDF({ threats, events, campaigns })}
              className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs transition-all cursor-pointer"
            >
              <FileDown className="w-4 h-4 text-indigo-200" />
              <span>Export Executive PDF</span>
            </button>
            <button
              id="btn-dash-simulate"
              onClick={onOpenSimulateModal}
              className="flex items-center gap-1.5 bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs transition-all cursor-pointer"
            >
              <Flame className="w-4 h-4 text-amber-200" />
              <span>Simulate Attack</span>
            </button>
            <button
              onClick={() => setActiveTab('copilot')}
              className="flex items-center gap-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-semibold px-3.5 py-2 rounded-lg border border-slate-200 transition-all cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
              <span>Ask AI Copilot</span>
            </button>
          </div>
        </div>
      </div>

      {/* 2. Key Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Overall Risk Index</span>
            <span className="text-slate-400 font-mono">CVSS 3.1</span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-2xl font-bold font-mono ${overallRiskScore > 80 ? 'text-rose-600' : 'text-amber-600'}`}>
              {overallRiskScore}/100
            </span>
            <span className="text-xs font-semibold text-rose-600 font-mono">HIGH RISK</span>
          </div>
          <div className="w-full bg-slate-100 h-1.5 rounded-full mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full ${overallRiskScore > 80 ? 'bg-rose-500' : 'bg-amber-500'}`}
              style={{ width: `${overallRiskScore}%` }}
            />
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Active Threats</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-slate-900">{totalThreats}</span>
            <span className="text-xs text-rose-600 font-semibold">{activeUncontained.length} uncontained</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-2 flex items-center gap-2">
            <span className="text-rose-600 font-semibold">{criticalThreats.length} Critical</span>
            <span>•</span>
            <span className="text-amber-600 font-semibold">{highThreats.length} High</span>
            <span>•</span>
            <span className="text-blue-600 font-semibold">{mediumThreats.length} Med</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Live Telemetry Events</span>
            <Radio className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-slate-900">{events.length}</span>
            <span className="text-xs text-emerald-600 font-semibold font-mono">LIVE FEED</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-2 flex items-center justify-between">
            <span>Anomalies: <b className="text-rose-600">{events.filter(e => e.isAnomaly).length}</b></span>
            <span>Ingest: <b>1.2k/min</b></span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Targeted Assets</span>
            <Server className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-bold font-mono text-slate-900">
              {Array.from(new Set(threats.flatMap(t => t.affectedAssets.map(a => a.name)))).length}
            </span>
            <span className="text-xs text-indigo-600 font-semibold">Tier-1 Core</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-2 truncate">
            Primary: <span className="font-mono text-slate-700">Active-Directory-DC01</span>
          </div>
        </div>
      </div>

      {/* 3. Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Active Threat Incidents */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Incidents Queue */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-500" />
                  Active Incident Queue & Triage Priority
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Ranked by AI confidence, CVSS risk index, and lateral blast radius
                </p>
              </div>

              <button
                onClick={() => setActiveTab('threats')}
                className="text-xs text-slate-700 hover:text-slate-900 font-semibold flex items-center gap-1"
              >
                <span>View All ({threats.length})</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-3">
              {threats.map(threat => {
                const isContained = threat.status === 'contained' || threat.status === 'remediated';
                return (
                  <div
                    key={threat.id}
                    className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-100/60 hover:border-slate-300 transition-all"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-200 text-slate-800 border border-slate-300">
                          {threat.threatCode}
                        </span>
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
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
                          className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                            isContained
                              ? 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                              : 'bg-indigo-100 text-indigo-700 border border-indigo-200'
                          }`}
                        >
                          {threat.status}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">Risk: {threat.riskScore}/100</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleInvestigate(threat.id)}
                          className="flex items-center gap-1 text-xs bg-slate-900 hover:bg-slate-800 text-white px-3 py-1.5 rounded-lg font-medium shadow-xs transition-colors cursor-pointer"
                        >
                          <span>Investigate</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    <h3 className="text-sm font-bold text-slate-900 mt-2">{threat.title}</h3>
                    <p className="text-xs text-slate-600 mt-1 line-clamp-2">{threat.aiSummary}</p>

                    <div className="mt-3 pt-3 border-t border-slate-200 flex flex-wrap items-center justify-between text-xs text-slate-500 gap-2">
                      <div className="flex flex-wrap items-center gap-3 font-mono text-[11px]">
                        <span>Origin: <b className="text-slate-800">{threat.sourceIps[0]}</b></span>
                        <span>Target: <b className="text-slate-800">{threat.affectedAssets[0]?.name}</b></span>
                      </div>
                      <div className="flex items-center gap-1.5 text-indigo-700 font-medium">
                        <Sparkles className="w-3 h-3 text-indigo-600" />
                        <span>AI Confidence: {threat.confidence}%</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Telemetry Stream Chart */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-blue-600" />
                  24-Hour Telemetry Volume & Threat Spikes
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">Ingested events vs. AI detected malicious anomalies</p>
              </div>
              <span className="text-xs font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                10-second aggregate
              </span>
            </div>

            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="eventGradLight" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.15} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="threatGradLight" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#e11d48" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#e11d48" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                  <YAxis stroke="#94a3b8" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#ffffff',
                      borderColor: '#e2e8f0',
                      borderRadius: '8px',
                      color: '#0f172a',
                      fontSize: '12px',
                      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                    }}
                  />
                  <Area type="monotone" dataKey="totalEvents" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#eventGradLight)" name="Total Ingress" />
                  <Area type="monotone" dataKey="threats" stroke="#e11d48" strokeWidth={2} fillOpacity={1} fill="url(#threatGradLight)" name="Threat Events" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Campaigns & Distribution */}
        <div className="space-y-6">
          {/* Active Campaigns Card */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Layers className="w-4 h-4 text-indigo-600" />
                Correlated Adversary Campaigns
              </h2>
              <span className="text-xs text-slate-500 font-mono">APT Tracking</span>
            </div>

            <div className="space-y-3">
              {campaigns.map(camp => (
                <div key={camp.id} className="p-3 rounded-lg border border-slate-200 bg-slate-50/60 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900">{camp.title}</span>
                    <span
                      className={`text-[9px] font-bold px-1.5 py-0.2 rounded uppercase ${
                        camp.severity === 'critical'
                          ? 'bg-rose-100 text-rose-700 border border-rose-200'
                          : 'bg-amber-100 text-amber-800 border border-amber-200'
                      }`}
                    >
                      {camp.severity}
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-600">{camp.summary}</p>

                  <div>
                    <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                      <span>Kill Chain Progression:</span>
                      <span className="font-mono font-bold text-slate-800">{camp.killChainProgress}%</span>
                    </div>
                    <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${camp.killChainProgress > 70 ? 'bg-rose-500' : 'bg-amber-500'}`}
                        style={{ width: `${camp.killChainProgress}%` }}
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 font-mono">
                    <span>Actor: <b className="text-slate-800">{camp.threatActor}</b></span>
                    <span>Assets: <b className="text-slate-800">{camp.targetedAssetsCount} nodes</b></span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Distribution Pie */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
            <h2 className="text-sm font-bold text-slate-900 mb-3">Severity Breakdown</h2>
            <div className="h-44 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {severityPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#ffffff',
                      borderColor: '#e2e8f0',
                      borderRadius: '8px',
                      color: '#0f172a',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-2 gap-2 mt-2 text-xs">
              {severityPieData.map(item => (
                <div key={item.name} className="flex items-center gap-2 p-1.5 rounded bg-slate-50 border border-slate-100">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-600">{item.name}:</span>
                  <span className="font-bold text-slate-900 ml-auto font-mono">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
