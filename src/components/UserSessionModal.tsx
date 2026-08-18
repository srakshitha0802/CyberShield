import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { ANALYST_PERSONAS } from '../data/analystPersonas';
import { UserRole } from '../types/security';
import {
  X,
  UserCheck,
  ShieldCheck,
  Lock,
  LogOut,
  KeyRound,
  FileText,
  Activity,
  CheckCircle,
  AlertCircle,
  Search,
  Clock,
  Radio,
  Server,
  Layers,
  ArrowRightLeft,
} from 'lucide-react';

interface UserSessionModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const UserSessionModal: React.FC<UserSessionModalProps> = ({ isOpen, onClose }) => {
  const {
    currentUser,
    switchUserRole,
    logout,
    lockSession,
    auditLogs,
    defconLevel,
    setDefconLevel,
  } = useSecurity();

  const [activeTab, setActiveTab] = useState<'profile' | 'permissions' | 'audit' | 'roles'>('profile');
  const [auditFilter, setAuditFilter] = useState<string>('ALL');
  const [auditSearch, setAuditSearch] = useState<string>('');

  if (!isOpen || !currentUser) return null;

  const ALL_SYSTEM_PERMISSIONS = [
    { id: 'ALL_PERMISSIONS', label: 'Root SOC Administrator & Superuser', desc: 'Unrestricted execution on all endpoints and containment gateways' },
    { id: 'EXECUTE_SOAR_PLAYBOOKS', label: 'Execute SOAR Automated Playbooks', desc: 'Trigger automated incident response pipelines and scripts' },
    { id: 'PERIMETER_FIREWALL_CONTROL', label: 'Perimeter Firewall Manipulation', desc: 'Inject iptables drop rules, block source IP subnets' },
    { id: 'HOST_NETWORK_ISOLATION', label: 'EDR Endpoint Host Network Isolation', desc: 'Sever network connectivity for compromised virtual and physical servers' },
    { id: 'TOKEN_REVOCATION', label: 'IAM / Cloud Token Revocation', desc: 'Invalidate active cloud sessions and force credential resets' },
    { id: 'SIGMA_DETECTION_COMMIT', label: 'Sigma Rule & Detection Engineering', desc: 'Deploy new threat hunting rules to live SIEM pipelines' },
    { id: 'EXPORT_DFIR_DOSSIERS', label: 'Export NIST SP 800-61 PDF Reports', desc: 'Generate cryptographic audit reports and executive dashboards' },
    { id: 'OVERRIDE_THREAT_STATUS', label: 'Manual Incident Status Override', desc: 'Mark threats as contained, remediated, or false positive' },
    { id: 'QUERY_IOC_INTELLIGENCE', label: 'Threat Intel & IoC Enrichment', desc: 'Query global threat intelligence telemetry for reputation scores' },
    { id: 'INSPECT_PACKETS', label: 'Deep Packet Inspection (PCAP)', desc: 'Reconstruct raw protocol payloads and JARM TLS signatures' },
  ];

  const filteredLogs = auditLogs.filter(log => {
    const matchesCategory = auditFilter === 'ALL' || log.category === auditFilter;
    const matchesSearch =
      auditSearch === '' ||
      log.action.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.details.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.target.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.userName.toLowerCase().includes(auditSearch.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-3xl w-full max-h-[90vh] flex flex-col overflow-hidden animate-fadeIn font-sans">
        {/* Header */}
        <div className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-800 border border-slate-700 overflow-hidden flex items-center justify-center">
              {currentUser.avatar ? (
                <img
                  src={currentUser.avatar}
                  alt={currentUser.name}
                  referrerPolicy="no-referrer"
                  className="w-full h-full object-cover"
                />
              ) : (
                <UserCheck className="w-5 h-5 text-rose-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-base text-white">{currentUser.name}</h3>
                <span className="bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[10px] font-mono font-semibold px-2 py-0.5 rounded">
                  {currentUser.clearance}
                </span>
              </div>
              <p className="text-xs text-slate-400">{currentUser.roleTitle} • {currentUser.badgeNumber}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="bg-slate-50 border-b border-slate-200 px-6 flex items-center justify-between gap-2 overflow-x-auto">
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab('profile')}
              className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'profile'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              <UserCheck className="w-3.5 h-3.5" />
              <span>Analyst Profile</span>
            </button>

            <button
              onClick={() => setActiveTab('permissions')}
              className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'permissions'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>RBAC Permissions</span>
            </button>

            <button
              onClick={() => setActiveTab('audit')}
              className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'audit'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Security Audit Trail ({auditLogs.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('roles')}
              className={`py-3 px-3 text-xs font-semibold border-b-2 transition-all cursor-pointer flex items-center gap-1.5 ${
                activeTab === 'roles'
                  ? 'border-slate-900 text-slate-900'
                  : 'border-transparent text-slate-500 hover:text-slate-900'
              }`}
            >
              <ArrowRightLeft className="w-3.5 h-3.5" />
              <span>Switch Operational Role</span>
            </button>
          </div>

          <div className="flex items-center gap-1.5 py-2">
            <button
              onClick={() => {
                onClose();
                lockSession();
              }}
              className="p-1.5 rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-200 text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer"
              title="Lock Console"
            >
              <Lock className="w-3.5 h-3.5 text-slate-700" />
              <span className="hidden sm:inline text-[11px]">Lock</span>
            </button>
            <button
              onClick={() => {
                onClose();
                logout();
              }}
              className="p-1.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 hover:bg-rose-100 text-xs font-medium flex items-center gap-1 transition-colors cursor-pointer"
              title="Terminate Session"
            >
              <LogOut className="w-3.5 h-3.5 text-rose-600" />
              <span className="hidden sm:inline text-[11px]">Logout</span>
            </button>
          </div>
        </div>

        {/* Tab Contents */}
        <div className="p-6 flex-1 overflow-y-auto max-h-[calc(90vh-180px)]">
          {/* 1. Profile Tab */}
          {activeTab === 'profile' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                    Department & Unit
                  </div>
                  <div className="text-sm font-bold text-slate-900">{currentUser.department}</div>
                  <div className="text-xs text-slate-600 mt-1">{currentUser.assignedJurisdiction}</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                    Multi-Factor Authentication
                  </div>
                  <div className="text-sm font-bold text-emerald-700 flex items-center gap-1.5">
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                    <span>{currentUser.mfaMethod}</span>
                  </div>
                  <div className="text-xs text-slate-500 mt-1">Cryptographic WebAuthn Attestation Validated</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                    Session Ingestion Time
                  </div>
                  <div className="text-sm font-mono font-semibold text-slate-800">{currentUser.sessionStarted}</div>
                  <div className="text-xs text-slate-500 mt-1">Active Lease Duration: 8h 00m (TLS 1.3)</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4">
                  <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
                    Defense Readiness Condition
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    {[1, 2, 3, 4, 5].map(lvl => (
                      <button
                        key={lvl}
                        onClick={() => setDefconLevel(lvl as 1 | 2 | 3 | 4 | 5)}
                        className={`px-2.5 py-1 rounded text-xs font-mono font-bold transition-all cursor-pointer ${
                          defconLevel === lvl
                            ? lvl === 1
                              ? 'bg-rose-600 text-white shadow-xs'
                              : lvl === 2
                              ? 'bg-amber-600 text-white shadow-xs'
                              : 'bg-emerald-600 text-white shadow-xs'
                            : 'bg-slate-200 text-slate-700 hover:bg-slate-300'
                        }`}
                      >
                        DEFCON {lvl}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Zero-Trust Device & Session Health */}
              <div className="border border-slate-200 rounded-xl p-4 bg-slate-900 text-white">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-emerald-400" />
                    <span className="font-semibold text-xs text-slate-200">Zero-Trust Enclave Identity Verification</span>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 border border-emerald-800 px-2 py-0.5 rounded font-semibold">
                    100% COMPLIANT
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className="bg-slate-800/80 p-2 rounded-lg">
                    <div className="text-[10px] text-slate-400">CIPHER SUITE</div>
                    <div className="text-slate-200 font-semibold truncate">TLS_AES_256_GCM</div>
                  </div>
                  <div className="bg-slate-800/80 p-2 rounded-lg">
                    <div className="text-[10px] text-slate-400">ANALYST IP</div>
                    <div className="text-slate-200 font-semibold">10.0.0.84 (VPN)</div>
                  </div>
                  <div className="bg-slate-800/80 p-2 rounded-lg">
                    <div className="text-[10px] text-slate-400">HARDWARE TPM</div>
                    <div className="text-slate-200 font-semibold">TPM 2.0 Locked</div>
                  </div>
                  <div className="bg-slate-800/80 p-2 rounded-lg">
                    <div className="text-[10px] text-slate-400">SESSION LEASE</div>
                    <div className="text-slate-200 font-semibold">Valid (7h 24m)</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 2. Permissions Tab */}
          {activeTab === 'permissions' && (
            <div className="space-y-3">
              <div className="text-xs text-slate-600 mb-2">
                The role <b className="text-slate-900">{currentUser.roleTitle}</b> is granted the following role-based access control privileges:
              </div>

              <div className="space-y-2">
                {ALL_SYSTEM_PERMISSIONS.map(perm => {
                  const hasPermission =
                    currentUser.permissions.includes('ALL_PERMISSIONS') ||
                    currentUser.permissions.includes(perm.id);

                  return (
                    <div
                      key={perm.id}
                      className={`p-3 rounded-xl border flex items-center justify-between transition-all ${
                        hasPermission
                          ? 'bg-emerald-50/50 border-emerald-200'
                          : 'bg-slate-50 border-slate-200 opacity-60'
                      }`}
                    >
                      <div>
                        <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                          {hasPermission ? (
                            <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                          ) : (
                            <AlertCircle className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          )}
                          <span>{perm.label}</span>
                        </div>
                        <div className="text-[11px] text-slate-500 mt-0.5">{perm.desc}</div>
                      </div>
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${
                          hasPermission
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                            : 'bg-slate-200 text-slate-600'
                        }`}
                      >
                        {hasPermission ? 'GRANTED' : 'DENIED'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* 3. Security Audit Trail Tab */}
          {activeTab === 'audit' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-2 justify-between">
                <div className="relative flex-1">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={auditSearch}
                    onChange={e => setAuditSearch(e.target.value)}
                    placeholder="Search audit actions, analysts, targets..."
                    className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-slate-900"
                  />
                </div>

                <div className="flex gap-1 overflow-x-auto">
                  {['ALL', 'CONTAINMENT', 'AUTH', 'INVESTIGATION', 'EXPORT'].map(cat => (
                    <button
                      key={cat}
                      onClick={() => setAuditFilter(cat)}
                      className={`px-2.5 py-1 rounded text-xs font-semibold whitespace-nowrap cursor-pointer ${
                        auditFilter === cat
                          ? 'bg-slate-900 text-white'
                          : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="overflow-x-auto max-h-72">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-100 text-slate-600 font-semibold border-b border-slate-200 text-[11px]">
                      <tr>
                        <th className="py-2 px-3">Timestamp (UTC)</th>
                        <th className="py-2 px-3">Action</th>
                        <th className="py-2 px-3">Analyst</th>
                        <th className="py-2 px-3">Target Asset</th>
                        <th className="py-2 px-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                      {filteredLogs.map(log => (
                        <tr key={log.id} className="hover:bg-slate-50/80">
                          <td className="py-2 px-3 text-slate-500 whitespace-nowrap">{log.timestamp.substring(11)}</td>
                          <td className="py-2 px-3 font-semibold text-slate-900 whitespace-nowrap">{log.action}</td>
                          <td className="py-2 px-3 text-slate-700 whitespace-nowrap">{log.userName}</td>
                          <td className="py-2 px-3 text-slate-600 max-w-[160px] truncate" title={log.target}>
                            {log.target}
                          </td>
                          <td className="py-2 px-3 whitespace-nowrap">
                            <span className="bg-emerald-100 text-emerald-800 px-1.5 py-0.5 rounded text-[10px] font-bold">
                              {log.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                      {filteredLogs.length === 0 && (
                        <tr>
                          <td colSpan={5} className="py-6 text-center text-slate-400 font-sans text-xs">
                            No audit log entries matching current search filter.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* 4. Switch Operational Role Tab */}
          {activeTab === 'roles' && (
            <div className="space-y-4">
              <div className="text-xs text-slate-600 mb-2">
                Select an operational role to instantly evaluate the CyberShield console from different operational perspectives:
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {ANALYST_PERSONAS.map(persona => {
                  const isCurrent = currentUser.role === persona.role;
                  return (
                    <button
                      key={persona.id}
                      onClick={() => {
                        switchUserRole(persona.role);
                        onClose();
                      }}
                      className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                        isCurrent
                          ? 'bg-slate-900 text-white border-slate-900 shadow-md ring-2 ring-rose-500/50'
                          : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <div className="font-bold text-sm">{persona.name}</div>
                        <span
                          className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                            isCurrent
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : 'bg-slate-100 text-slate-600'
                          }`}
                        >
                          {persona.clearance}
                        </span>
                      </div>
                      <div className={`text-xs font-medium ${isCurrent ? 'text-slate-300' : 'text-slate-700'}`}>
                        {persona.roleTitle}
                      </div>
                      <div className={`text-[11px] mt-1 line-clamp-2 ${isCurrent ? 'text-slate-400' : 'text-slate-500'}`}>
                        {persona.assignedJurisdiction}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-slate-50 border-t border-slate-200 px-6 py-3 flex items-center justify-between text-xs text-slate-500">
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            <Radio className="w-3 h-3 text-emerald-500 animate-pulse" />
            <span>NIST SP 800-61 / ISO 27001 SOC Session</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs transition-colors cursor-pointer"
          >
            Close Dossier
          </button>
        </div>
      </div>
    </div>
  );
};
