import React from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Activity,
  TrendingUp,
  BarChart3,
  Layers,
  Globe,
  Clock,
  ShieldCheck,
  Server,
  Zap,
  FileDown,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
import { exportDashboardExecutiveReportPDF } from '../utils/pdfExport';

export const AnalyticsView: React.FC = () => {
  const { threats, events, campaigns } = useSecurity();

  // Attack Trend Data
  const trendData = [
    { time: '00:00', bruteForce: 12, ransomware: 2, c2: 8, exfil: 4 },
    { time: '00:30', bruteForce: 18, ransomware: 5, c2: 12, exfil: 6 },
    { time: '01:00', bruteForce: 45, ransomware: 9, c2: 24, exfil: 14 },
    { time: '01:30', bruteForce: 89, ransomware: 18, c2: 42, exfil: 31 },
    { time: '02:00', bruteForce: 142, ransomware: 24, c2: 56, exfil: 48 },
    { time: '02:30', bruteForce: 67, ransomware: 12, c2: 30, exfil: 22 },
  ];

  // Top Attacking ASNs
  const topAsns = [
    { name: 'ASN 44050 (St. Petersburg, RU)', requests: 1240, color: '#e11d48' },
    { name: 'ASN 51167 (Latvia Hosting)', requests: 890, color: '#f59e0b' },
    { name: 'ASN 135905 (Vietnam Cloud)', requests: 640, color: '#3b82f6' },
    { name: 'ASN 206264 (Bulgaria Mirai Node)', requests: 420, color: '#8b5cf6' },
    { name: 'Tor Exit Node Relay', requests: 380, color: '#ec4899' },
  ];

  // Targeted Assets Data
  const assetTargetData = [
    { name: 'Active-Directory-DC01', attacks: 342 },
    { name: 'Finance-DB-Server', attacks: 184 },
    { name: 'Cloud-API-Gateway', attacks: 145 },
    { name: 'HR-Portal-Server', attacks: 98 },
    { name: 'Edge-Ingress-Proxy-01', attacks: 85 },
  ];

  // MITRE Tactics Matrix Heatmap Data
  const mitreTactics = [
    { tactic: 'Reconnaissance', count: 14, color: 'bg-blue-50 text-blue-700 border-blue-200' },
    { tactic: 'Initial Access', count: 48, color: 'bg-rose-50 text-rose-700 border-rose-200 font-bold' },
    { tactic: 'Execution', count: 32, color: 'bg-rose-50 text-rose-700 border-rose-200' },
    { tactic: 'Persistence', count: 18, color: 'bg-amber-50 text-amber-800 border-amber-200' },
    { tactic: 'Privilege Escalation', count: 36, color: 'bg-rose-50 text-rose-700 border-rose-200 font-bold' },
    { tactic: 'Defense Evasion', count: 28, color: 'bg-amber-50 text-amber-800 border-amber-200' },
    { tactic: 'Credential Access', count: 52, color: 'bg-rose-50 text-rose-700 border-rose-200 font-bold' },
    { tactic: 'Lateral Movement', count: 24, color: 'bg-amber-50 text-amber-800 border-amber-200' },
    { tactic: 'Exfiltration', count: 20, color: 'bg-amber-50 text-amber-800 border-amber-200' },
    { tactic: 'Impact / Ransom', count: 16, color: 'bg-rose-50 text-rose-700 border-rose-200 font-bold' },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-indigo-600" />
            <h1 className="text-base font-bold text-slate-900">Security Analytics & Threat Trends</h1>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Statistical anomaly distributions, autonomous resolution metrics, and MITRE ATT&CK coverage.
          </p>
        </div>

        <button
          onClick={() => exportDashboardExecutiveReportPDF({ threats, events, campaigns })}
          className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs transition-all cursor-pointer shrink-0"
        >
          <FileDown className="w-4 h-4 text-indigo-200" />
          <span>Export Analytics PDF Report</span>
        </button>
      </div>

      {/* SLA & MTTR Gauges */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Mean Time to Detect (MTTD)</span>
            <Clock className="w-4 h-4 text-indigo-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-indigo-600 mt-2">1.8 Seconds</div>
          <span className="text-[11px] text-emerald-600 flex items-center gap-1 mt-1 font-mono font-semibold">
            ↓ 92% faster with AI streaming
          </span>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>Mean Time to Contain (MTTC)</span>
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-600 mt-2">4.2 Seconds</div>
          <span className="text-[11px] text-emerald-600 flex items-center gap-1 mt-1 font-mono font-semibold">
            One-click playbook execution
          </span>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>False Positive Reduction</span>
            <TrendingUp className="w-4 h-4 text-blue-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-blue-600 mt-2">94.8%</div>
          <span className="text-[11px] text-slate-500 flex items-center gap-1 mt-1 font-mono">
            Filtered via context reasoning
          </span>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between text-slate-500 text-xs font-medium">
            <span>NIST Compliance Index</span>
            <Zap className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-600 mt-2">98.5%</div>
          <span className="text-[11px] text-slate-500 flex items-center gap-1 mt-1 font-mono">
            SP 800-61 Rev 2 Standard
          </span>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Attack Vector Trend */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Attack Vector Intensity Over Time</h2>
              <p className="text-xs text-slate-500">Volume breakdown by specific cyberattack category</p>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="bruteGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#e11d48" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#e11d48" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="c2Grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="ransomGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
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
                <Area type="monotone" dataKey="bruteForce" stroke="#e11d48" fillOpacity={1} fill="url(#bruteGrad)" name="Password Spray / Auth" />
                <Area type="monotone" dataKey="c2" stroke="#8b5cf6" fillOpacity={1} fill="url(#c2Grad)" name="C2 Beaconing" />
                <Area type="monotone" dataKey="ransomware" stroke="#f59e0b" fillOpacity={1} fill="url(#ransomGrad)" name="Ransomware Staging" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right 1 Col: Top Attacking ASNs */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Globe className="w-4 h-4 text-slate-700" />
              Top Attacking ASNs & Subnets
            </h2>
            <p className="text-xs text-slate-500">Autonomous systems generating malicious ingress</p>
          </div>

          <div className="space-y-3">
            {topAsns.map(asn => (
              <div key={asn.name} className="p-2.5 rounded-lg border border-slate-200 bg-slate-50/60 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-800 truncate">{asn.name}</span>
                  <span className="font-mono font-bold text-slate-900">{asn.requests} reqs</span>
                </div>
                <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${(asn.requests / 1240) * 100}%`, backgroundColor: asn.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Heatmap */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-600" />
              MITRE ATT&CK Enterprise Matrix Coverage & Heatmap
            </h2>
            <p className="text-xs text-slate-500">Detected adversary activities mapped to standard enterprise tactics</p>
          </div>
          <span className="text-xs font-mono text-slate-500">Enterprise Tactics (10)</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {mitreTactics.map(tactic => (
            <div
              key={tactic.tactic}
              className={`p-3 rounded-xl border text-center transition-all ${tactic.color}`}
            >
              <div className="text-[11px] font-semibold">{tactic.tactic}</div>
              <div className="text-xl font-bold font-mono mt-1">{tactic.count}</div>
              <span className="text-[10px] text-slate-500 block">Detections</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
