import React, { useState, useEffect } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Search,
  ShieldAlert,
  BarChart3,
  Radio,
  Workflow,
  Code,
  ShieldCheck,
  Radar,
  Activity,
  Bot,
  Mail,
  Flame,
  FileDown,
  Lock,
  LogOut,
  UserCheck,
  ChevronRight,
  Sparkles,
} from 'lucide-react';
import { exportExecutiveDashboardPDF } from '../utils/pdfExport';

interface CommandPaletteModalProps {
  isOpen: boolean;
  onClose: () => void;
  onOpenSimulateModal: () => void;
  onOpenUserModal: () => void;
}

export const CommandPaletteModal: React.FC<CommandPaletteModalProps> = ({
  isOpen,
  onClose,
  onOpenSimulateModal,
  onOpenUserModal,
}) => {
  const {
    setActiveTab,
    threats,
    setSelectedThreatId,
    lockSession,
    logout,
    campaigns,
  } = useSecurity();

  const [search, setSearch] = useState('');

  // Close on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const NAV_ITEMS = [
    { id: 'dashboard', label: 'SOC Executive Dashboard', icon: BarChart3, category: 'Navigation' },
    { id: 'monitor', label: 'Live SIEM Telemetry Feed', icon: Radio, category: 'Navigation' },
    { id: 'threats', label: 'Active Threat Incidents Queue', icon: ShieldAlert, category: 'Navigation' },
    { id: 'investigation', label: 'DFIR Investigation & Attack Tree', icon: Search, category: 'Navigation' },
    { id: 'playbooks', label: 'SOAR Automated Containment Playbooks', icon: Workflow, category: 'Navigation' },
    { id: 'detection', label: 'Detection Studio & Sigma Rules', icon: Code, category: 'Navigation' },
    { id: 'vulns', label: 'Vulnerability Matrix & CVEs', icon: ShieldCheck, category: 'Navigation' },
    { id: 'iocs', label: 'IoC Threat Intelligence Explorer', icon: Radar, category: 'Navigation' },
    { id: 'analytics', label: 'MITRE ATT&CK & Trend Analytics', icon: Activity, category: 'Navigation' },
    { id: 'copilot', label: 'CyberShield AI SOC Copilot', icon: Bot, category: 'Navigation' },
    { id: 'phishing', label: 'Phishing Email Analysis Sandbox', icon: Mail, category: 'Navigation' },
  ];

  const THREAT_ITEMS = threats.map(t => ({
    id: t.id,
    label: `[${t.threatCode}] ${t.title}`,
    sub: `${t.threatType} • Severity: ${t.severity.toUpperCase()} • Confidence: ${t.confidence}%`,
    icon: ShieldAlert,
    category: 'Active Incident Dossier',
    action: () => {
      setSelectedThreatId(t.id);
      setActiveTab('investigation');
      onClose();
    },
  }));

  const ACTION_ITEMS = [
    {
      id: 'act-simulate',
      label: 'Simulate Live Adversary Attack',
      sub: 'Inject Kerberos spray, ransomware, or cloud exfiltration scenario',
      icon: Flame,
      category: 'Actions',
      action: () => {
        onClose();
        onOpenSimulateModal();
      },
    },
    {
      id: 'act-export-pdf',
      label: 'Export Executive Posture PDF Report',
      sub: 'Download board-ready executive security status dossier',
      icon: FileDown,
      category: 'Actions',
      action: () => {
        exportExecutiveDashboardPDF(threats, campaigns);
        onClose();
      },
    },
    {
      id: 'act-user-profile',
      label: 'View Analyst Profile & RBAC Permissions',
      sub: 'Inspect credentials, clearance, and security audit trail',
      icon: UserCheck,
      category: 'Actions',
      action: () => {
        onClose();
        onOpenUserModal();
      },
    },
    {
      id: 'act-lock',
      label: 'Lock SOC Terminal Session',
      sub: 'Engage NIST SP 800-53 console screen lock',
      icon: Lock,
      category: 'Security',
      action: () => {
        lockSession();
        onClose();
      },
    },
    {
      id: 'act-logout',
      label: 'Terminate Session & Logout',
      sub: 'Revoke active authentication token',
      icon: LogOut,
      category: 'Security',
      action: () => {
        logout();
        onClose();
      },
    },
  ];

  const searchLower = search.toLowerCase();

  const filteredNav = NAV_ITEMS.filter(item =>
    item.label.toLowerCase().includes(searchLower)
  );

  const filteredThreats = THREAT_ITEMS.filter(
    item =>
      item.label.toLowerCase().includes(searchLower) ||
      item.sub.toLowerCase().includes(searchLower)
  );

  const filteredActions = ACTION_ITEMS.filter(
    item =>
      item.label.toLowerCase().includes(searchLower) ||
      item.sub.toLowerCase().includes(searchLower)
  );

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-start justify-center pt-20 p-4">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-2xl w-full flex flex-col overflow-hidden animate-fadeIn font-sans">
        {/* Search Bar Input */}
        <div className="p-4 border-b border-slate-200 flex items-center gap-3 bg-slate-50">
          <Search className="w-5 h-5 text-slate-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Type a command, incident ID (e.g. TH-1042), or view..."
            className="w-full bg-transparent text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none font-medium"
          />
          <span className="text-[10px] font-mono text-slate-400 bg-slate-200 px-2 py-0.5 rounded">
            ESC to close
          </span>
        </div>

        {/* Results List */}
        <div className="max-h-96 overflow-y-auto p-2 divide-y divide-slate-100">
          {/* Quick Actions */}
          {filteredActions.length > 0 && (
            <div className="py-2">
              <div className="px-3 py-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
                Security Actions
              </div>
              {filteredActions.map(item => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={item.action}
                    className="w-full text-left p-2.5 rounded-xl hover:bg-slate-100/80 flex items-center justify-between group transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-700 flex items-center justify-center group-hover:bg-slate-900 group-hover:text-white transition-colors">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-900">{item.label}</div>
                        <div className="text-[11px] text-slate-500">{item.sub}</div>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-slate-700" />
                  </button>
                );
              })}
            </div>
          )}

          {/* Active Threats */}
          {filteredThreats.length > 0 && (
            <div className="py-2">
              <div className="px-3 py-1 text-[10px] font-bold text-rose-500 uppercase tracking-wider font-mono">
                Active Incidents & Alerts
              </div>
              {filteredThreats.map(item => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={item.action}
                    className="w-full text-left p-2.5 rounded-xl hover:bg-rose-50/60 flex items-center justify-between group transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-rose-100 text-rose-700 flex items-center justify-center">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-900">{item.label}</div>
                        <div className="text-[11px] text-slate-500">{item.sub}</div>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-rose-600" />
                  </button>
                );
              })}
            </div>
          )}

          {/* Navigation Views */}
          {filteredNav.length > 0 && (
            <div className="py-2">
              <div className="px-3 py-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
                SOC Navigation Views
              </div>
              {filteredNav.map(item => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActiveTab(item.id);
                      onClose();
                    }}
                    className="w-full text-left p-2.5 rounded-xl hover:bg-slate-100/80 flex items-center justify-between group transition-colors cursor-pointer"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-600 flex items-center justify-center group-hover:bg-slate-900 group-hover:text-white transition-colors">
                        <Icon className="w-4 h-4" />
                      </div>
                      <div className="text-xs font-semibold text-slate-800">{item.label}</div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-slate-700" />
                  </button>
                );
              })}
            </div>
          )}

          {filteredActions.length === 0 && filteredThreats.length === 0 && filteredNav.length === 0 && (
            <div className="py-8 text-center text-xs text-slate-400 font-medium">
              No SOC commands or incidents matching &ldquo;{search}&rdquo;
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-slate-50 border-t border-slate-200 px-4 py-2 text-[11px] text-slate-500 flex items-center justify-between">
          <span className="font-mono">CyberShield Quick Command Bar</span>
          <div className="flex items-center gap-3">
            <span>Use ↑↓ to navigate</span>
            <span>↵ to select</span>
          </div>
        </div>
      </div>
    </div>
  );
};
