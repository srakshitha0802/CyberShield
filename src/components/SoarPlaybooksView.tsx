import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Workflow,
  Play,
  CheckCircle,
  Clock,
  ShieldAlert,
  Server,
  Key,
  Database,
  Radio,
  FileCheck,
  RotateCcw,
  Sparkles,
  Zap,
  ArrowRight,
  CheckCircle2,
  Terminal,
  Lock,
} from 'lucide-react';
import confetti from 'canvas-confetti';

interface PlaybookStep {
  id: string;
  name: string;
  targetSystem: string;
  type: 'firewall' | 'identity' | 'edr' | 'snapshot' | 'notify';
  action: string;
  commandSnippet: string;
  status: 'idle' | 'running' | 'success' | 'failed';
  executionTimeMs?: number;
}

interface SoarPlaybook {
  id: string;
  name: string;
  threatType: string;
  description: string;
  nistPhase: string;
  averageExecutionTime: string;
  steps: PlaybookStep[];
}

const DEFAULT_PLAYBOOKS: SoarPlaybook[] = [
  {
    id: 'soar-1',
    name: 'Critical Active Directory Domain Takeover Containment',
    threatType: 'Brute Force / Kerberos Spray / LSASS Dump',
    description: 'Sequentially drops adversary IP origins, invalidates privileged Kerberos tickets, isolates compromised Domain Controller, and triggers digital forensics snapshot.',
    nistPhase: 'Containment & Eradication (NIST SP 800-61)',
    averageExecutionTime: '380 ms',
    steps: [
      {
        id: 's1-1',
        name: 'Perimeter Firewall Edge Drop',
        targetSystem: 'Edge Border Router / Linux iptables',
        type: 'firewall',
        action: 'Inject DROP rule for all incoming traffic from 185.220.101.5 and 194.26.29.112',
        commandSnippet: 'iptables -I INPUT -s 185.220.101.5 -j DROP\niptables -I INPUT -s 194.26.29.112 -j DROP',
        status: 'idle',
      },
      {
        id: 's1-2',
        name: 'Revoke Identity OAuth & Kerberos Tickets',
        targetSystem: 'Azure AD / Entra ID & On-Prem AD KDC',
        type: 'identity',
        action: 'Invalidate all active Kerberos TGTs and revoke refresh tokens for admin@company.com',
        commandSnippet: 'Revoke-AzureADUserAllRefreshToken -ObjectId "admin@company.com"\nkpurge -f',
        status: 'idle',
      },
      {
        id: 's1-3',
        name: 'EDR Host Network Microsegmentation',
        targetSystem: 'CrowdStrike Falcon / Windows Defender for Endpoint',
        type: 'edr',
        action: 'Quarantine Active-Directory-DC01 from East-West lateral movement routing',
        commandSnippet: 'Set-NetFirewallRule -DisplayName "EDR-Host-Isolation" -Enabled True',
        status: 'idle',
      },
      {
        id: 's1-4',
        name: 'Forensic Live Memory Snapshot',
        targetSystem: 'Forensic Agent / LiME RAM Dump',
        type: 'snapshot',
        action: 'Dump volatile RAM memory and process handle table for root cause analysis',
        commandSnippet: 'winpmem.exe -o C:\\Forensics\\DC01_memdump.raw',
        status: 'idle',
      },
      {
        id: 's1-5',
        name: 'Dispatch P1 SOC War Room & Incident Ticket',
        targetSystem: 'PagerDuty / Jira Service Management / Slack',
        type: 'notify',
        action: 'Create P1 Critical Incident ticket and alert Senior Incident Response Commander',
        commandSnippet: 'curl -X POST https://events.pagerduty.com/v2/enqueue -d \'{"severity":"critical"}\'',
        status: 'idle',
      },
    ],
  },
  {
    id: 'soar-2',
    name: 'Automated LockBit 3.0 Ransomware Kill-Switch',
    threatType: 'Ransomware Outbreak & Backup Purge',
    description: 'Instantly halts volume shadow purges, isolates file storage clusters, kills unauthorized PowerShell stagers, and restores immutable backup snapshot.',
    nistPhase: 'Immediate Blast-Radius Containment',
    averageExecutionTime: '420 ms',
    steps: [
      {
        id: 's2-1',
        name: 'Kill Malicious Scripting & Stager Processes',
        targetSystem: 'Endpoint EDR / Sysinternals',
        type: 'edr',
        action: 'Terminate powershell.exe and vssadmin.exe child processes on Finance-DB-Server',
        commandSnippet: 'Stop-Process -Name "vssadmin", "wbadmin", "powershell" -Force',
        status: 'idle',
      },
      {
        id: 's2-2',
        name: 'VLAN Microsegmentation Isolation',
        targetSystem: 'Finance-DB-Server (10.0.3.44)',
        type: 'edr',
        action: 'Sever network interfaces to protect ERP and Billing databases',
        commandSnippet: 'Disable-NetAdapter -Name "Ethernet0" -Confirm:$false',
        status: 'idle',
      },
      {
        id: 's2-3',
        name: 'Lock Immutable Backup Storage Volume',
        targetSystem: 'AWS S3 Glacier / Cohesity Snapshot',
        type: 'snapshot',
        action: 'Set Object Lock compliance mode on backup storage targets',
        commandSnippet: 'aws s3api put-object-legal-hold --bucket prod-backups --legal-hold Status=ON',
        status: 'idle',
      },
    ],
  },
  {
    id: 'soar-3',
    name: 'Cloud IAM Secret Leak & S3 Exfiltration Containment',
    threatType: 'API Credential Abuse',
    description: 'Deactivates compromised AWS IAM access keys, detaches admin policies, and revokes S3 bucket public access.',
    nistPhase: 'Cloud Identity Containment',
    averageExecutionTime: '290 ms',
    steps: [
      {
        id: 's3-1',
        name: 'Deactivate AWS Access Key Pair',
        targetSystem: 'AWS IAM / Security Token Service',
        type: 'identity',
        action: 'Immediately disable compromised AccessKeyId AKIAIOSFODNN7EXAMPLE',
        commandSnippet: 'aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive',
        status: 'idle',
      },
      {
        id: 's3-2',
        name: 'Attach DenyAll Cloud Perimeter Policy',
        targetSystem: 'AWS IAM Boundary',
        type: 'identity',
        action: 'Enforce explicit Deny policy across all S3 and RDS resources for the principal',
        commandSnippet: 'aws iam attach-user-policy --user-name aws_iam_terraform_deployer --policy-arn arn:aws:iam::aws:policy/AWSDenyAll',
        status: 'idle',
      },
    ],
  },
];

export const SoarPlaybooksView: React.FC = () => {
  const { threats } = useSecurity();
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>(DEFAULT_PLAYBOOKS);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('soar-1');
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [activeRunningStepId, setActiveRunningStepId] = useState<string | null>(null);
  const [executionLogs, setExecutionLogs] = useState<Array<{ time: string; msg: string; type: 'success' | 'info' | 'warn' }>>([
    { time: '02:00:00 UTC', msg: 'SOAR Orchestrator initialized. 3 Automated Response Playbooks armed.', type: 'info' },
  ]);

  const activePlaybook = playbooks.find(p => p.id === selectedPlaybookId) || playbooks[0];

  const handleRunPlaybook = async () => {
    setIsRunningAll(true);

    const logEntry = (msg: string, type: 'success' | 'info' | 'warn' = 'info') => {
      setExecutionLogs(prev => [
        { time: new Date().toISOString().substring(11, 19) + ' UTC', msg, type },
        ...prev,
      ]);
    };

    logEntry(`Starting automated response workflow: ${activePlaybook.name}`, 'info');

    // Run steps sequentially with visual delay
    for (let i = 0; i < activePlaybook.steps.length; i++) {
      const step = activePlaybook.steps[i];
      setActiveRunningStepId(step.id);

      // Set running status
      setPlaybooks(prev =>
        prev.map(p =>
          p.id === activePlaybook.id
            ? {
                ...p,
                steps: p.steps.map(s => (s.id === step.id ? { ...s, status: 'running' as const } : s)),
              }
            : p
        )
      );

      const delay = Math.floor(Math.random() * 400) + 300;
      await new Promise(resolve => setTimeout(resolve, delay));

      // Mark success
      setPlaybooks(prev =>
        prev.map(p =>
          p.id === activePlaybook.id
            ? {
                ...p,
                steps: p.steps.map(s =>
                  s.id === step.id
                    ? { ...s, status: 'success' as const, executionTimeMs: delay }
                    : s
                ),
              }
            : p
        )
      );

      logEntry(`[STEP ${i + 1}/${activePlaybook.steps.length}] Executed ${step.name} on [${step.targetSystem}] in ${delay}ms`, 'success');
    }

    setActiveRunningStepId(null);
    setIsRunningAll(false);
    logEntry(`🎉 Playbook completed successfully! Threat contained across all endpoints.`, 'success');

    confetti({
      particleCount: 50,
      spread: 70,
      origin: { y: 0.7 },
      colors: ['#10b981', '#3b82f6', '#6366f1'],
    });
  };

  const handleResetPlaybook = () => {
    setPlaybooks(prev =>
      prev.map(p =>
        p.id === activePlaybook.id
          ? {
              ...p,
              steps: p.steps.map(s => ({ ...s, status: 'idle' as const, executionTimeMs: undefined })),
            }
          : p
      )
    );
  };

  const getStepIcon = (type: PlaybookStep['type']) => {
    switch (type) {
      case 'firewall':
        return Lock;
      case 'identity':
        return Key;
      case 'edr':
        return Server;
      case 'snapshot':
        return Database;
      case 'notify':
        return Radio;
    }
  };

  const completedStepsCount = activePlaybook.steps.filter(s => s.status === 'success').length;
  const progressPercent = Math.round((completedStepsCount / activePlaybook.steps.length) * 100);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">SOAR Automated Playbook Engine</h1>
            <span className="bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs px-2 py-0.5 rounded-full font-medium">
              Autonomous Orchestration
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Execute orchestrated multi-stage containment pipelines across perimeter firewalls, identity providers, EDR agents, and SIEM queues.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleResetPlaybook}
            disabled={isRunningAll}
            className="flex items-center gap-1.5 text-xs text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-3 py-2 rounded-lg font-medium transition-colors cursor-pointer disabled:opacity-50"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Pipeline</span>
          </button>
          <button
            onClick={handleRunPlaybook}
            disabled={isRunningAll}
            className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium px-4 py-2 rounded-lg transition-colors cursor-pointer shadow-xs disabled:opacity-50"
          >
            {isRunningAll ? <Zap className="w-3.5 h-3.5 animate-bounce" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isRunningAll ? 'Executing Orchestration Pipeline...' : 'Run Automated Playbook'}</span>
          </button>
        </div>
      </div>

      {/* Playbook Selector Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {playbooks.map(pb => {
          const isSelected = pb.id === selectedPlaybookId;
          return (
            <div
              key={pb.id}
              onClick={() => setSelectedPlaybookId(pb.id)}
              className={`p-4 rounded-xl border transition-all cursor-pointer shadow-2xs ${
                isSelected
                  ? 'bg-white border-slate-900 ring-1 ring-slate-900'
                  : 'bg-white border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-mono text-slate-500">{pb.nistPhase}</span>
                <span className="text-[11px] font-mono font-medium text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                  {pb.averageExecutionTime}
                </span>
              </div>
              <h3 className="text-xs font-bold text-slate-900">{pb.name}</h3>
              <p className="text-[11px] text-slate-500 mt-1 line-clamp-2">{pb.description}</p>
              <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-600">
                <span>{pb.steps.length} Orchestrated Steps</span>
                <span className="font-semibold text-slate-800">{pb.threatType}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Playbook Workflow Pipeline Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Step Sequence Canvas */}
        <div className="lg:col-span-8 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-2xs space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h2 className="text-sm font-bold text-slate-900">{activePlaybook.name}</h2>
                <p className="text-xs text-slate-500 mt-0.5">{activePlaybook.description}</p>
              </div>

              <div className="text-right">
                <span className="text-xs font-bold text-slate-800">
                  {completedStepsCount} / {activePlaybook.steps.length} Steps Completed
                </span>
                <div className="w-32 h-1.5 bg-slate-100 rounded-full overflow-hidden mt-1.5">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-300"
                    style={{ width: `${progressPercent}%` }}
                  ></div>
                </div>
              </div>
            </div>

            {/* Sequence Cards */}
            <div className="space-y-3">
              {activePlaybook.steps.map((step, idx) => {
                const Icon = getStepIcon(step.type);
                const isRunning = step.id === activeRunningStepId;
                const isSuccess = step.status === 'success';

                return (
                  <div
                    key={step.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isRunning
                        ? 'bg-indigo-50/50 border-indigo-300 ring-1 ring-indigo-300'
                        : isSuccess
                        ? 'bg-emerald-50/30 border-emerald-200'
                        : 'bg-slate-50/70 border-slate-200'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3">
                        <div
                          className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                            isSuccess
                              ? 'bg-emerald-600 text-white'
                              : isRunning
                              ? 'bg-indigo-600 text-white animate-pulse'
                              : 'bg-white border border-slate-200 text-slate-700'
                          }`}
                        >
                          {isSuccess ? <CheckCircle2 className="w-4 h-4" /> : <Icon className="w-4 h-4" />}
                        </div>

                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[11px] font-bold text-slate-400">0{idx + 1}</span>
                            <h3 className="text-xs font-bold text-slate-900">{step.name}</h3>
                            <span className="text-[10px] font-mono bg-white px-2 py-0.5 rounded border border-slate-200 text-slate-600">
                              {step.targetSystem}
                            </span>
                          </div>
                          <p className="text-xs text-slate-600 mt-1">{step.action}</p>

                          {/* Code Snippet Box */}
                          <div className="mt-2 bg-slate-900 text-slate-200 p-2 rounded-lg font-mono text-[11px] overflow-x-auto flex items-center justify-between gap-2">
                            <code className="text-slate-300">{step.commandSnippet}</code>
                            {step.executionTimeMs && (
                              <span className="text-[10px] text-emerald-400 font-bold shrink-0">
                                {step.executionTimeMs}ms
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="shrink-0">
                        {isSuccess ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-700 bg-emerald-100 border border-emerald-200 px-2 py-0.5 rounded-full">
                            <CheckCircle className="w-3 h-3" /> Executed
                          </span>
                        ) : isRunning ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-bold text-indigo-700 bg-indigo-100 border border-indigo-200 px-2 py-0.5 rounded-full animate-pulse">
                            Running...
                          </span>
                        ) : (
                          <span className="text-[11px] font-medium text-slate-400 bg-white border border-slate-200 px-2 py-0.5 rounded-full">
                            Pending
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Real-time SOAR Execution Audit Log */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-2xs space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-slate-700" />
              <span>SOAR Audit Execution Logs</span>
            </h3>

            <div className="space-y-2 max-h-[380px] overflow-y-auto font-mono text-[11px] scrollbar-thin">
              {executionLogs.map((log, i) => (
                <div
                  key={i}
                  className={`p-2 rounded border leading-relaxed ${
                    log.type === 'success'
                      ? 'bg-emerald-50/80 border-emerald-200 text-emerald-900'
                      : log.type === 'warn'
                      ? 'bg-amber-50/80 border-amber-200 text-amber-900'
                      : 'bg-slate-50 border-slate-200 text-slate-700'
                  }`}
                >
                  <span className="text-slate-400">[{log.time}]</span> {log.msg}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
