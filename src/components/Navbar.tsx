import React, { useState, useEffect } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  Radar,
  Search,
  Mail,
  Play,
  Pause,
  Volume2,
  VolumeX,
  Flame,
  BarChart3,
  Bot,
  AlertTriangle,
  Radio,
  CheckCircle,
  Sparkles,
  Workflow,
  Code,
  Lock,
  LogOut,
  UserCheck,
  Command,
  ChevronDown,
} from 'lucide-react';

interface NavbarProps {
  onOpenSimulateModal: () => void;
  onOpenCommandPalette: () => void;
  onOpenUserModal: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenSimulateModal,
  onOpenCommandPalette,
  onOpenUserModal,
}) => {
  const {
    activeTab,
    setActiveTab,
    threats,
    isLiveStreaming,
    setIsLiveStreaming,
    soundEnabled,
    setSoundEnabled,
    isAnalyzing,
    currentUser,
    defconLevel,
    lockSession,
    logout,
  } = useSecurity();

  const [timeUtc, setTimeUtc] = useState<string>('');
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeUtc(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Global Cmd+K keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onOpenCommandPalette();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onOpenCommandPalette]);

  const criticalCount = threats.filter(t => t.severity === 'critical' && t.status !== 'contained' && t.status !== 'remediated').length;
  const highCount = threats.filter(t => t.severity === 'high' && t.status !== 'contained' && t.status !== 'remediated').length;
  const containedCount = threats.filter(t => t.status === 'contained' || t.status === 'remediated').length;

  const isCriticalState = criticalCount > 0;

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'monitor', label: 'Live Telemetry', icon: Radio, countBadge: isLiveStreaming ? 'LIVE' : undefined },
    { id: 'threats', label: 'Threats & Alerts', icon: ShieldAlert, badge: criticalCount + highCount },
    { id: 'investigation', label: 'DFIR Investigation', icon: Search },
    { id: 'playbooks', label: 'SOAR Playbooks', icon: Workflow },
    { id: 'detection', label: 'Detection Studio', icon: Code },
    { id: 'vulns', label: 'Vulnerability Matrix', icon: ShieldCheck },
    { id: 'iocs', label: 'IoC Intelligence', icon: Radar },
    { id: 'analytics', label: 'MITRE & Trends', icon: Activity },
    { id: 'copilot', label: 'AI Copilot', icon: Bot, isAi: true },
    { id: 'phishing', label: 'Phishing Sandbox', icon: Mail },
  ];

  return (
    <header className="bg-white border-b border-slate-200 sticky top-0 z-40 shadow-xs">
      {/* Top Threat Ticker & Status Bar */}
      <div className="bg-slate-900 text-slate-200 px-4 py-1.5 flex flex-wrap items-center justify-between text-xs border-b border-slate-800">
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 bg-rose-950/80 border border-rose-800 text-rose-300 text-[10px] font-mono font-bold px-2 py-0.5 rounded">
            <Radio className="w-3 h-3 text-rose-400 animate-pulse" />
            DEFCON {defconLevel}
          </span>

          {isCriticalState ? (
            <div className="flex items-center gap-1.5 text-rose-300 font-semibold text-[11px]">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400 animate-bounce" />
              <span>ACTIVE THREATS: {criticalCount} Critical, {highCount} High</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-[11px]">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span>POSTURE: NORMAL</span>
            </div>
          )}

          <div className="hidden md:flex items-center gap-2 text-slate-400 text-[11px] font-mono">
            <span>• Contained: <b className="text-emerald-400">{containedCount}</b></span>
            <span>• Enclave: <b className="text-slate-300">TLS 1.3 / AES-256</b></span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {isAnalyzing && (
            <div className="flex items-center gap-1.5 text-indigo-300 bg-indigo-950/60 border border-indigo-700/60 px-2 py-0.5 rounded">
              <Sparkles className="w-3 h-3 text-indigo-400 animate-spin" />
              <span className="font-mono text-[11px] font-medium">AI Reasoning Active</span>
            </div>
          )}

          <span className="font-mono text-slate-400 hidden lg:inline text-[11px]">{timeUtc}</span>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setSoundEnabled(!soundEnabled)}
              title={soundEnabled ? 'Mute Alert Audio' : 'Enable Alert Audio'}
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            >
              {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-slate-300" /> : <VolumeX className="w-3.5 h-3.5 text-slate-500" />}
            </button>
            <button
              onClick={() => setIsLiveStreaming(!isLiveStreaming)}
              title={isLiveStreaming ? 'Pause Live Event Ingestion' : 'Resume Live Event Ingestion'}
              className={`flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[10px] border transition-colors cursor-pointer ${
                isLiveStreaming
                  ? 'bg-emerald-950/80 border-emerald-700 text-emerald-300 font-semibold'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}
            >
              {isLiveStreaming ? <Pause className="w-3 h-3 text-emerald-400" /> : <Play className="w-3 h-3 text-slate-400" />}
              <span>{isLiveStreaming ? 'STREAMING' : 'PAUSED'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Header & Nav Tabs */}
      <div className="px-4 sm:px-6 py-2.5 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-900 text-white flex items-center justify-center shadow-xs">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-900 text-base tracking-tight">CyberShield AI</span>
              <span className="bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider">
                SOC Grid
              </span>
            </div>
            <p className="text-[11px] text-slate-500 hidden sm:block">Autonomous Threat Detection & DFIR Platform</p>
          </div>
        </div>

        {/* Global Quick Command & Action Controls */}
        <div className="flex items-center gap-2">
          {/* Quick Command Launcher Button */}
          <button
            onClick={onOpenCommandPalette}
            className="flex items-center gap-2 bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer shadow-2xs"
            title="Open Quick Command Palette (Cmd+K)"
          >
            <Command className="w-3.5 h-3.5 text-slate-500" />
            <span className="hidden md:inline">Command Palette</span>
            <kbd className="hidden sm:inline font-mono text-[10px] bg-white border border-slate-300 px-1.5 py-0.5 rounded text-slate-500">
              ⌘K
            </kbd>
          </button>

          {/* Simulate Live Attack Trigger */}
          <button
            id="btn-simulate-attack"
            onClick={onOpenSimulateModal}
            className="flex items-center gap-1.5 bg-rose-600 hover:bg-rose-700 text-white font-semibold px-3 py-1.5 rounded-lg text-xs shadow-xs transition-all active:scale-98 cursor-pointer"
          >
            <Flame className="w-3.5 h-3.5 text-amber-200" />
            <span className="hidden sm:inline">Simulate Attack</span>
          </button>

          {/* Analyst Profile & Session Menu */}
          {currentUser && (
            <div className="relative">
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center gap-2 p-1 sm:px-2.5 sm:py-1 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer"
              >
                <div className="w-7 h-7 rounded-lg bg-slate-900 text-white overflow-hidden flex items-center justify-center text-xs font-bold shrink-0">
                  {currentUser.avatar ? (
                    <img
                      src={currentUser.avatar}
                      alt={currentUser.name}
                      referrerPolicy="no-referrer"
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <span>{currentUser.name.charAt(0)}</span>
                  )}
                </div>
                <div className="hidden md:block text-left">
                  <div className="text-xs font-bold text-slate-900 leading-tight">{currentUser.name}</div>
                  <div className="text-[10px] text-slate-500 font-mono leading-none">{currentUser.badgeNumber}</div>
                </div>
                <ChevronDown className="w-3 h-3 text-slate-400 hidden sm:block" />
              </button>

              {/* Dropdown Menu */}
              {isUserMenuOpen && (
                <div
                  className="absolute right-0 mt-2 w-64 bg-white rounded-xl shadow-xl border border-slate-200 py-2 z-50 animate-fadeIn font-sans"
                  onMouseLeave={() => setIsUserMenuOpen(false)}
                >
                  <div className="px-4 py-2 border-b border-slate-100">
                    <div className="text-xs font-bold text-slate-900">{currentUser.name}</div>
                    <div className="text-[11px] text-slate-500">{currentUser.email}</div>
                    <div className="mt-1.5 inline-block px-2 py-0.5 bg-amber-50 border border-amber-200 text-amber-800 text-[9px] font-mono font-bold rounded">
                      {currentUser.clearance}
                    </div>
                  </div>

                  <div className="py-1">
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onOpenUserModal();
                      }}
                      className="w-full text-left px-4 py-2 text-xs text-slate-700 hover:bg-slate-50 flex items-center gap-2 transition-colors cursor-pointer"
                    >
                      <UserCheck className="w-3.5 h-3.5 text-slate-500" />
                      <span>Analyst Profile & RBAC</span>
                    </button>

                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        lockSession();
                      }}
                      className="w-full text-left px-4 py-2 text-xs text-slate-700 hover:bg-slate-50 flex items-center gap-2 transition-colors cursor-pointer"
                    >
                      <Lock className="w-3.5 h-3.5 text-slate-500" />
                      <span>Lock Terminal Console</span>
                    </button>
                  </div>

                  <div className="pt-1 border-t border-slate-100">
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        logout();
                      }}
                      className="w-full text-left px-4 py-2 text-xs text-rose-600 hover:bg-rose-50 flex items-center gap-2 transition-colors font-medium cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5 text-rose-600" />
                      <span>Sign Out & Terminate Session</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="px-4 sm:px-6 flex gap-1 overflow-x-auto scrollbar-none border-t border-slate-100 bg-white">
        {navItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`nav-tab-${item.id}`}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center gap-2 px-3 py-2.5 text-xs font-medium border-b-2 transition-all whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'border-slate-900 text-slate-900 font-semibold bg-slate-50/80'
                  : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-50/50'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-slate-900' : 'text-slate-400'}`} />
              <span>{item.label}</span>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="bg-rose-100 text-rose-700 border border-rose-200 text-[10px] font-bold px-1.5 py-0.2 rounded-full">
                  {item.badge}
                </span>
              )}
              {item.countBadge && (
                <span className="bg-emerald-100 text-emerald-700 border border-emerald-200 text-[9px] font-bold px-1.5 py-0.2 rounded">
                  {item.countBadge}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </header>
  );
};

