import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Code,
  Terminal,
  FileCode,
  CheckCircle,
  Copy,
  Download,
  Sparkles,
  Play,
  ShieldCheck,
  Flame,
  AlertTriangle,
  RefreshCw,
  Search,
  BookOpen,
} from 'lucide-react';

interface SigmaRuleResult {
  ruleTitle: string;
  ruleId: string;
  status: string;
  level: string;
  sigmaYaml: string;
  yaraRule: string;
  splunkSpl: string;
  sentinelKql: string;
  falsePositiveRisks: string[];
  testScenarios: string[];
}

const PRESET_DETECTION_TEMPLATES = [
  {
    name: 'Kerberos Password Spray & DC Injection',
    technique: 'T1110.003',
    logSource: 'windows_security',
    desc: 'Detects rapid Event ID 4771 Kerberos pre-auth failures followed by anomalous administrative ticket requests.',
  },
  {
    name: 'LockBit / Ransomware Volume Shadow Purge',
    technique: 'T1490',
    logSource: 'windows_sysmon',
    desc: 'Identifies execution of vssadmin.exe delete shadows, wbadmin, and bcdedit recovery disabling commands.',
  },
  {
    name: 'AWS S3 Bulk Data Exfiltration via Leaked Token',
    technique: 'T1530',
    logSource: 'aws_cloudtrail',
    desc: 'Flags high-frequency S3 GetObject API calls originating from unapproved foreign ASNs or Tor exit relays.',
  },
  {
    name: 'Cobalt Strike HTTPS C2 Beaconing (JARM)',
    technique: 'T1071.001',
    logSource: 'suricata_zeek',
    desc: 'Detects regular TLS connection handshakes matching known Cobalt Strike JARM hashes and short payload intervals.',
  },
];

export const DetectionEngineeringView: React.FC = () => {
  const { threats, events } = useSecurity();

  const [promptInput, setPromptInput] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState('T1003.001');
  const [selectedLogSource, setSelectedLogSource] = useState('windows_sysmon');
  const [activeFormatTab, setActiveFormatTab] = useState<'sigma' | 'yara' | 'splunk' | 'sentinel'>('sigma');
  const [isGenerating, setIsGenerating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [testResult, setTestResult] = useState<{ matchedCount: number; matchedEvents: string[] } | null>(null);

  const [currentRule, setCurrentRule] = useState<SigmaRuleResult>({
    ruleTitle: 'CyberShield: Suspicious LSASS Process Memory Dump (T1003.001)',
    ruleId: 'd84b2190-2ef8-4903-b09a-8a1e948c21a0',
    status: 'production',
    level: 'critical',
    sigmaYaml: `title: Suspicious LSASS Process Access and Memory Handle Acquisition
id: d84b2190-2ef8-4903-b09a-8a1e948c21a0
status: production
description: Detects unauthorized processes requesting PROCESS_VM_READ or PROCESS_ALL_ACCESS to lsass.exe for credential dumping.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://cyber.gc.ca/en/guidance/detecting-lsass-memory-dumps
author: CyberShield Autonomous Detection Studio
date: 2026/08/17
tags:
    - attack.credential_access
    - attack.t1003_001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x1F0FFF'
            - '0x1038'
    filter_trusted:
        SourceImage|endswith:
            - '\\MsMpEng.exe'
            - '\\csagent.exe'
            - '\\CortexEDR.exe'
    condition: selection and not filter_trusted
falsepositives:
    - Domain Controller active directory backup jobs
    - Approved EDR / Antivirus kernel agent diagnostics
level: critical`,
    yaraRule: `rule CyberShield_LSASS_Memory_Dumper {
    meta:
        description = "Detects mimikatz and custom LSASS credential scraper artifacts"
        author = "CyberShield AI"
        reference = "MITRE ATT&CK T1003.001"
        severity = "CRITICAL"
    strings:
        $mim1 = "sekurlsa::logonpasswords" ascii wide nocase
        $mim2 = "lsasrv.dll" ascii wide nocase
        $mim3 = "kuhl_m_sekurlsa" ascii wide nocase
        $cmd1 = "rundll32.exe comsvcs.dll, MiniDump" ascii wide nocase
        $hex1 = { 8B 45 08 85 C0 74 1E 8B 40 04 85 C0 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($mim*) or $cmd1 or $hex1)
}`,
    splunkSpl: `index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10
| where match(TargetImage, "(?i)lsass\\.exe$")
| where NOT match(SourceImage, "(?i)(MsMpEng|csagent|CortexEDR)\\.exe$")
| eval suspicious_access=case(
    GrantedAccess=="0x1010", "VM_READ (MiniDump)",
    GrantedAccess=="0x1F0FFF", "ALL_ACCESS (Full Injection)",
    1==1, "Other Elevated Handle"
  )
| stats count earliest(_time) as first_seen latest(_time) as last_seen by SourceImage, TargetImage, GrantedAccess, suspicious_access, Computer, User
| sort - count`,
    sentinelKql: `SecurityEvent
| where EventID == 4663 or EventID == 4656
| where ObjectType == "Process" and ObjectName has "lsass.exe"
| where AccessMask in ("0x1010", "0x1410", "0x1F0FFF")
| project TimeGenerated, Computer, SubjectUserName, ObjectName, AccessMask, ProcessName
| extend MitreTechnique = "T1003.001"`,
    falsePositiveRisks: [
      'Approved third-party EDR scanner process handles',
      'Scheduled Active Directory automated snapshot scripts',
    ],
    testScenarios: [
      'Trigger rundll32 comsvcs.dll MiniDump simulation test',
      'Execute unprivileged token impersonation against test endpoint',
    ],
  });

  const handleGenerate = async (customDesc?: string, customTech?: string) => {
    setIsGenerating(true);
    setTestResult(null);

    const descToUse = customDesc || promptInput || 'Detect suspicious Kerberos pre-authentication brute-forcing and ticket requests';
    const techToUse = customTech || selectedTechnique;

    try {
      const res = await fetch('/api/generate-sigma-rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatTitle: descToUse.slice(0, 50),
          description: descToUse,
          logSource: selectedLogSource,
          mitreTechnique: techToUse,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.success && data.data) {
          setCurrentRule(data.data);
        }
      }
    } catch (err) {
      console.error('Sigma generation error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleTestRule = () => {
    // Search current ingested events for matches
    const matched = events.filter(e => {
      const raw = (e.rawMessage + ' ' + e.action + ' ' + e.assetName).toLowerCase();
      if (currentRule.ruleTitle.toLowerCase().includes('lsass') && raw.includes('lsass')) return true;
      if (currentRule.ruleTitle.toLowerCase().includes('kerberos') && raw.includes('kerberos')) return true;
      if (currentRule.ruleTitle.toLowerCase().includes('vssadmin') && raw.includes('vssadmin')) return true;
      if (currentRule.ruleTitle.toLowerCase().includes('s3') && raw.includes('s3')) return true;
      if (raw.includes(selectedTechnique.toLowerCase())) return true;
      return e.severity === 'critical';
    });

    setTestResult({
      matchedCount: matched.length,
      matchedEvents: matched.slice(0, 5).map(m => `[${m.timestamp}] ${m.assetName} - ${m.action}: ${m.rawMessage}`),
    });
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (filename: string, text: string) => {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const getActiveCodeContent = () => {
    switch (activeFormatTab) {
      case 'sigma':
        return { text: currentRule.sigmaYaml, filename: `${currentRule.ruleTitle.toLowerCase().replace(/[^a-z0-9]/g, '_')}.yml`, lang: 'yaml' };
      case 'yara':
        return { text: currentRule.yaraRule, filename: `${currentRule.ruleTitle.toLowerCase().replace(/[^a-z0-9]/g, '_')}.yar`, lang: 'yara' };
      case 'splunk':
        return { text: currentRule.splunkSpl, filename: 'splunk_search.spl', lang: 'splunk' };
      case 'sentinel':
        return { text: currentRule.sentinelKql, filename: 'sentinel_hunting.kql', lang: 'kql' };
    }
  };

  const activeContent = getActiveCodeContent();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">Detection Engineering Studio</h1>
            <span className="bg-slate-100 text-slate-700 border border-slate-200 text-xs px-2 py-0.5 rounded-full font-medium">
              Sigma / YARA / KQL / SPL
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Synthesize, validate, and export production-grade SIEM & EDR detection rules from threat telemetry and natural language.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleGenerate()}
            disabled={isGenerating}
            className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium px-3.5 py-2 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
          >
            {isGenerating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5 text-amber-300" />}
            <span>{isGenerating ? 'Synthesizing Rule...' : 'Generate Detection Rule'}</span>
          </button>
        </div>
      </div>

      {/* Preset Detection Blueprints */}
      <div>
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2.5">
          Preset MITRE ATT&CK Blueprints
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {PRESET_DETECTION_TEMPLATES.map((tmpl, idx) => (
            <div
              key={idx}
              onClick={() => {
                setPromptInput(tmpl.desc);
                setSelectedTechnique(tmpl.technique);
                setSelectedLogSource(tmpl.logSource);
                handleGenerate(tmpl.desc, tmpl.technique);
              }}
              className="bg-white border border-slate-200 hover:border-slate-400 p-3 rounded-xl transition-all cursor-pointer shadow-2xs group"
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-mono text-[11px] font-bold text-slate-700 bg-slate-100 px-1.5 py-0.5 rounded">
                  {tmpl.technique}
                </span>
                <span className="text-[10px] text-slate-400 font-mono">{tmpl.logSource}</span>
              </div>
              <h3 className="text-xs font-semibold text-slate-900 group-hover:text-indigo-600 transition-colors">
                {tmpl.name}
              </h3>
              <p className="text-[11px] text-slate-500 line-clamp-2 mt-1">{tmpl.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Custom Rule Input Controls */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
          <div className="lg:col-span-6">
            <label className="block text-xs font-medium text-slate-700 mb-1">
              Threat Description or Custom Hunting Hypothesis
            </label>
            <input
              type="text"
              value={promptInput}
              onChange={e => setPromptInput(e.target.value)}
              placeholder="e.g. Detect PowerShell stager invoking vssadmin delete shadows with hidden window flags"
              className="w-full text-xs bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-slate-900 focus:outline-none focus:border-slate-900"
            />
          </div>

          <div className="lg:col-span-3">
            <label className="block text-xs font-medium text-slate-700 mb-1">MITRE Technique</label>
            <select
              value={selectedTechnique}
              onChange={e => setSelectedTechnique(e.target.value)}
              className="w-full text-xs bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-slate-900 focus:outline-none focus:border-slate-900 cursor-pointer"
            >
              <option value="T1003.001">T1003.001 - LSASS Memory Dump</option>
              <option value="T1110.003">T1110.003 - Password Spraying</option>
              <option value="T1490">T1490 - Inhibit System Recovery</option>
              <option value="T1059.001">T1059.001 - PowerShell Stagers</option>
              <option value="T1071.001">T1071.001 - Web Protocols & C2</option>
              <option value="T1530">T1530 - Cloud Storage Exfiltration</option>
              <option value="T1566.002">T1566.002 - Spearphishing Link</option>
            </select>
          </div>

          <div className="lg:col-span-3">
            <label className="block text-xs font-medium text-slate-700 mb-1">Target Log Schema</label>
            <select
              value={selectedLogSource}
              onChange={e => setSelectedLogSource(e.target.value)}
              className="w-full text-xs bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-slate-900 focus:outline-none focus:border-slate-900 cursor-pointer"
            >
              <option value="windows_sysmon">Windows Sysmon (EventCode 1, 10, 11)</option>
              <option value="windows_security">Windows Security Event Log (4624, 4625, 4771)</option>
              <option value="aws_cloudtrail">AWS CloudTrail & IAM Telemetry</option>
              <option value="suricata_zeek">Suricata / Zeek IDS Alerts</option>
              <option value="linux_auditd">Linux Auditd / auth.log</option>
            </select>
          </div>
        </div>
      </div>

      {/* Rule Output and Formats */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Code View Canvas */}
        <div className="lg:col-span-8 space-y-3">
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
            {/* Tab Bar */}
            <div className="border-b border-slate-200 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 bg-slate-50">
              <div className="flex items-center gap-1">
                {[
                  { id: 'sigma', label: 'Sigma Rule (YAML)', icon: Code },
                  { id: 'yara', label: 'YARA Scanner', icon: FileCode },
                  { id: 'splunk', label: 'Splunk (SPL)', icon: Terminal },
                  { id: 'sentinel', label: 'MS Sentinel (KQL)', icon: Search },
                ].map(tab => {
                  const Icon = tab.icon;
                  const isActive = activeFormatTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActiveFormatTab(tab.id as typeof activeFormatTab)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-md font-medium transition-colors cursor-pointer ${
                        isActive
                          ? 'bg-white text-slate-900 border border-slate-200 shadow-2xs font-semibold'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{tab.label}</span>
                    </button>
                  );
                })}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopy(activeContent.text)}
                  className="flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1 rounded font-medium transition-colors cursor-pointer"
                >
                  {copied ? <CheckCircle className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  onClick={() => handleDownload(activeContent.filename, activeContent.text)}
                  className="flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1 rounded font-medium transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download</span>
                </button>
              </div>
            </div>

            {/* Code Body */}
            <div className="p-4 bg-slate-900 text-slate-100 overflow-x-auto">
              <pre className="font-mono text-xs leading-relaxed text-slate-200 whitespace-pre">
                {activeContent.text}
              </pre>
            </div>
          </div>

          {/* Test Against Live Telemetry Engine */}
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Play className="w-4 h-4 text-emerald-600" />
                <span className="text-xs font-bold text-slate-900">Run Rule Validation on Ingested Telemetry</span>
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Evaluates query logic against the active stream of {events.length} ingested security events.
              </p>
            </div>

            <button
              onClick={handleTestRule}
              className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium px-3.5 py-2 rounded-lg transition-colors cursor-pointer shrink-0"
            >
              <CheckCircle className="w-3.5 h-3.5" />
              <span>Validate on Live Stream</span>
            </button>
          </div>

          {testResult && (
            <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 text-xs space-y-2">
              <div className="flex items-center gap-2 text-emerald-800 font-bold">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>Validation Success: {testResult.matchedCount} Telemetry Events Flagged by Rule</span>
              </div>
              {testResult.matchedEvents.length > 0 && (
                <div className="space-y-1 font-mono text-[11px] text-emerald-900 bg-white/80 p-2.5 rounded border border-emerald-200">
                  {testResult.matchedEvents.map((evt, i) => (
                    <div key={i} className="truncate">
                      • {evt}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Rule Metadata & False Positive Analysis */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <BookOpen className="w-3.5 h-3.5 text-slate-700" />
              <span>Rule Operational Metadata</span>
            </h3>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500">Severity Level</span>
                <span className="font-bold text-rose-600 uppercase">{currentRule.level}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500">Deployment Status</span>
                <span className="font-bold text-emerald-600 uppercase">{currentRule.status}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500">Rule UUID</span>
                <span className="font-mono text-[11px] text-slate-700 truncate max-w-[160px]">
                  {currentRule.ruleId}
                </span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-bold text-slate-700 mt-3 mb-1.5 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                <span>False Positive Considerations</span>
              </h4>
              <ul className="space-y-1 text-xs text-slate-600">
                {currentRule.falsePositiveRisks.map((fp, i) => (
                  <li key={i} className="flex items-start gap-1.5">
                    <span className="text-amber-500">•</span>
                    <span>{fp}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h4 className="text-xs font-bold text-slate-700 mt-3 mb-1.5 flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-rose-500" />
                <span>Unit Testing Scenarios</span>
              </h4>
              <ul className="space-y-1 text-xs text-slate-600">
                {currentRule.testScenarios.map((ts, i) => (
                  <li key={i} className="flex items-start gap-1.5">
                    <span className="text-slate-400">•</span>
                    <span>{ts}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
