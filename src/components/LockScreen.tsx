import React, { useState, useEffect } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Lock,
  Unlock,
  ShieldAlert,
  Fingerprint,
  Radio,
  Clock,
  UserCheck,
  AlertTriangle,
} from 'lucide-react';

export const LockScreen: React.FC = () => {
  const { currentUser, unlockSession, threats, defconLevel, logout } = useSecurity();
  const [pin, setPin] = useState('');
  const [error, setError] = useState(false);
  const [time, setTime] = useState(new Date().toUTCString().replace('GMT', 'UTC'));

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toUTCString().replace('GMT', 'UTC'));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleUnlock = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!pin || pin.trim() === '9921' || pin.length >= 4) {
      unlockSession(pin);
    } else {
      setError(true);
      setTimeout(() => setError(false), 1500);
    }
  };

  const handleBiometricQuickUnlock = () => {
    unlockSession();
  };

  const activeIncidents = threats.filter(t => t.severity === 'critical' || t.severity === 'high');

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/95 backdrop-blur-xl flex flex-col justify-between text-slate-100 p-6 select-none font-sans">
      {/* Top Bar */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-500" />
          <span className="font-bold text-white tracking-wider font-mono">
            CYBERSHIELD AI // TERMINAL LOCKED
          </span>
        </div>
        <div className="flex items-center gap-3 font-mono text-[11px]">
          <span className="flex items-center gap-1.5 bg-rose-950/60 border border-rose-800 text-rose-400 px-2 py-0.5 rounded font-semibold">
            <Radio className="w-3 h-3 animate-pulse" />
            DEFCON {defconLevel}
          </span>
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3 text-slate-400" />
            {time}
          </span>
        </div>
      </div>

      {/* Center Lock Pad */}
      <div className="max-w-md w-full mx-auto my-auto flex flex-col items-center text-center">
        {/* User Avatar & Badge */}
        <div className="relative mb-4">
          <div className="w-20 h-20 rounded-2xl overflow-hidden border-2 border-slate-700 bg-slate-900 shadow-xl mx-auto">
            {currentUser?.avatar ? (
              <img
                src={currentUser.avatar}
                alt={currentUser.name}
                referrerPolicy="no-referrer"
                className="w-full h-full object-cover"
              />
            ) : (
              <div className="w-full h-full flex items-center justify-center bg-slate-800 text-white font-bold text-xl">
                {currentUser?.name?.charAt(0) || 'A'}
              </div>
            )}
          </div>
          <div className="absolute -bottom-2 -right-2 bg-rose-600 text-white p-1.5 rounded-lg border border-slate-900 shadow-md">
            <Lock className="w-3.5 h-3.5" />
          </div>
        </div>

        <h2 className="text-xl font-bold text-white tracking-tight">{currentUser?.name || 'Authorized SOC Analyst'}</h2>
        <p className="text-xs text-slate-400 font-mono mt-0.5">{currentUser?.roleTitle || 'Incident Commander'}</p>
        <span className="inline-block mt-2 px-2.5 py-0.5 bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[10px] font-mono font-semibold rounded">
          {currentUser?.clearance || 'TOP SECRET // SCI'}
        </span>

        {/* Threat Alert Ticker while locked */}
        {activeIncidents.length > 0 && (
          <div className="mt-4 w-full bg-slate-900/80 border border-rose-900/50 rounded-xl p-2.5 text-left flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 animate-bounce" />
            <div className="flex-1 min-w-0">
              <div className="text-[11px] font-semibold text-rose-300 truncate">
                {activeIncidents[0].threatCode}: {activeIncidents[0].title}
              </div>
              <div className="text-[10px] text-slate-400 truncate">
                {activeIncidents.length} active high/critical threats monitored in background
              </div>
            </div>
          </div>
        )}

        {/* PIN Unlock Form */}
        <form onSubmit={handleUnlock} className="w-full mt-6 space-y-3">
          <div>
            <input
              type="password"
              autoFocus
              maxLength={8}
              value={pin}
              onChange={e => {
                setPin(e.target.value);
                setError(false);
              }}
              placeholder="Enter PIN (e.g. 9921) or Passphrase"
              className={`w-full bg-slate-900 border text-center font-mono tracking-widest text-sm py-2.5 px-4 rounded-xl text-white placeholder:text-slate-500 focus:outline-none transition-all ${
                error
                  ? 'border-rose-500 ring-2 ring-rose-500/50'
                  : 'border-slate-700 focus:border-rose-500 focus:ring-2 focus:ring-rose-500/40'
              }`}
            />
            {error && (
              <p className="text-[11px] text-rose-400 mt-1">Invalid PIN code. Try 9921 or click Biometric.</p>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button
              type="submit"
              className="w-full bg-rose-600 hover:bg-rose-500 text-white font-medium py-2.5 px-4 rounded-xl text-xs flex items-center justify-center gap-1.5 shadow-lg shadow-rose-900/40 transition-all cursor-pointer"
            >
              <Unlock className="w-3.5 h-3.5" />
              <span>Unlock Console</span>
            </button>
            <button
              type="button"
              onClick={handleBiometricQuickUnlock}
              className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium py-2.5 px-4 rounded-xl text-xs flex items-center justify-center gap-1.5 border border-slate-700 transition-all cursor-pointer"
            >
              <Fingerprint className="w-3.5 h-3.5 text-emerald-400" />
              <span>Quick Biometric</span>
            </button>
          </div>
        </form>

        <div className="mt-6 flex items-center gap-4 text-xs">
          <button
            onClick={logout}
            className="text-slate-400 hover:text-rose-400 transition-colors underline cursor-pointer"
          >
            Switch User / Terminate Session
          </button>
        </div>
      </div>

      {/* Bottom Info */}
      <div className="text-center text-[10px] text-slate-500 font-mono">
        SESSION SECURED UNDER NIST 800-53 ZERO TRUST LOCKOUT PROTOCOL • ENCLAVE NODE #01
      </div>
    </div>
  );
};
