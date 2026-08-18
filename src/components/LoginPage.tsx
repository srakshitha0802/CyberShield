import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { ANALYST_PERSONAS } from '../data/analystPersonas';
import { User, UserRole } from '../types/security';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  KeyRound,
  Fingerprint,
  Radio,
  Eye,
  EyeOff,
  UserCheck,
  ChevronRight,
  Sparkles,
  AlertTriangle,
  Server,
  Cpu,
} from 'lucide-react';

export const LoginPage: React.FC = () => {
  const { login, isAnalyzing } = useSecurity();

  const [email, setEmail] = useState('s.connor@cybershield.soc');
  const [password, setPassword] = useState('CyberDefense#2026!Sec');
  const [showPassword, setShowPassword] = useState(false);
  const [mfaCode, setMfaCode] = useState('849201');
  const [selectedRole, setSelectedRole] = useState<UserRole>('lead_soc_analyst');
  const [authMethod, setAuthMethod] = useState<'credentials' | 'biometric' | 'yubikey'>('credentials');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [biometricScanning, setBiometricScanning] = useState(false);

  // Quick preset selector
  const handleSelectPersona = (persona: User) => {
    setSelectedRole(persona.role);
    setEmail(persona.email);
    setPassword('CyberShield#9901!Auth');
    setErrorMessage(null);
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!email.trim() || !password.trim()) {
      setErrorMessage('Please provide both valid analyst credentials and security token.');
      return;
    }

    setIsSubmitting(true);

    try {
      // Find matching persona or create ad-hoc authenticated analyst
      const matchedPersona = ANALYST_PERSONAS.find(p => p.email.toLowerCase() === email.toLowerCase() || p.role === selectedRole);
      const targetUser = matchedPersona || {
        ...ANALYST_PERSONAS[0],
        email,
        name: email.split('@')[0].toUpperCase(),
      };

      await new Promise(resolve => setTimeout(resolve, 600));
      await login(targetUser, password, mfaCode);
    } catch {
      setErrorMessage('Authentication rejected by SOC Zero-Trust Controller.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBiometricAuth = async () => {
    setBiometricScanning(true);
    setErrorMessage(null);
    try {
      await new Promise(resolve => setTimeout(resolve, 1200));
      const targetPersona = ANALYST_PERSONAS.find(p => p.role === selectedRole) || ANALYST_PERSONAS[0];
      await login(targetPersona);
    } catch {
      setErrorMessage('WebAuthn biometric token failed verification.');
    } finally {
      setBiometricScanning(false);
    }
  };

  const currentSelectedPersona = ANALYST_PERSONAS.find(p => p.role === selectedRole) || ANALYST_PERSONAS[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between selection:bg-rose-500 selection:text-white relative overflow-hidden font-sans">
      {/* Dynamic Background Grid & Glows */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(120,119,198,0.15),rgba(255,255,255,0))] pointer-events-none" />
      <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-rose-500/40 to-transparent" />

      {/* Top Security Banner */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-2 text-xs flex flex-wrap items-center justify-between gap-2 z-10">
        <div className="flex items-center gap-2 text-slate-400">
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          <span className="font-mono text-[11px] uppercase tracking-wider text-amber-300 font-semibold">
            RESTRICTED ACCESS // DOD & NIST SP 800-61 COMPLIANT
          </span>
        </div>
        <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>ENCLAVE: ACTIVE (TLS 1.3 / AES-256)</span>
          </div>
          <span className="hidden sm:inline text-slate-600">•</span>
          <span className="hidden sm:inline">ZERO-TRUST POLICY ENFORCED</span>
        </div>
      </div>

      {/* Main Authentication Container */}
      <div className="flex-1 flex items-center justify-center p-4 sm:p-6 z-10">
        <div className="max-w-4xl w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          
          {/* Left Column: Platform Overview & System Telemetry */}
          <div className="lg:col-span-5 flex flex-col justify-between p-6 sm:p-8 rounded-2xl bg-slate-900/80 border border-slate-800 shadow-2xl backdrop-blur-md">
            <div>
              <div className="flex items-center gap-3 mb-6">
                <div className="w-11 h-11 rounded-xl bg-gradient-to-tr from-rose-600 to-amber-600 flex items-center justify-center text-white shadow-lg shadow-rose-500/20">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                    CyberShield AI
                    <span className="bg-rose-500/20 border border-rose-500/40 text-rose-300 text-[10px] font-mono px-2 py-0.5 rounded">
                      SOC v4.2
                    </span>
                  </h1>
                  <p className="text-xs text-slate-400">Autonomous Cyber Defense & DFIR Terminal</p>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed mb-6">
                Next-generation security operations center platform integrating real-time telemetry streaming, autonomous AI incident triage, MITRE ATT&CK correlation, and automated SOAR containment playbooks.
              </p>

              {/* Real-time Telemetry Pillbox */}
              <div className="space-y-2.5 mb-6">
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 text-slate-400">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    <span>SIEM Event Ingestion Engine</span>
                  </div>
                  <span className="font-mono text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
                    <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
                    100k EPS
                  </span>
                </div>

                <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 text-slate-400">
                    <Cpu className="w-3.5 h-3.5 text-purple-400" />
                    <span>Autonomous AI Co-Analyst</span>
                  </div>
                  <span className="font-mono text-[11px] text-purple-300 font-semibold">Gemini 3.7 Flash</span>
                </div>

                <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 text-slate-400">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    <span>SOAR Host Isolation Engine</span>
                  </div>
                  <span className="font-mono text-[11px] text-emerald-400 font-semibold">ARMED & READY</span>
                </div>
              </div>
            </div>

            {/* Quick Demo Analyst Presets */}
            <div className="pt-4 border-t border-slate-800/80">
              <div className="flex items-center justify-between mb-2.5">
                <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
                  Quick Select Operational Role
                </span>
                <span className="text-[10px] text-rose-400 font-mono">1-Click Test</span>
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {ANALYST_PERSONAS.slice(0, 4).map(persona => {
                  const isSelected = selectedRole === persona.role;
                  return (
                    <button
                      key={persona.id}
                      type="button"
                      onClick={() => handleSelectPersona(persona)}
                      className={`text-left p-2 rounded-lg border text-xs transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-rose-950/60 border-rose-500/50 text-white ring-1 ring-rose-500/40'
                          : 'bg-slate-950/40 border-slate-800/60 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-semibold truncate text-[11px] text-slate-200">{persona.name}</div>
                      <div className="text-[10px] text-slate-400 truncate">{persona.roleTitle.split('(')[0]}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Right Column: High-Security Login Form */}
          <div className="lg:col-span-7 bg-slate-900 p-6 sm:p-8 rounded-2xl border border-slate-800 shadow-2xl flex flex-col justify-between">
            <div>
              {/* Active Role Clearance Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-6">
                <div>
                  <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                    Analyst Authentication
                  </h2>
                  <p className="text-xs text-slate-400">Present cryptographic credentials to unlock console</p>
                </div>
                <div className="text-right">
                  <span className="inline-flex items-center gap-1.5 bg-amber-500/10 border border-amber-500/30 text-amber-300 text-[10px] font-mono font-semibold px-2 py-0.5 rounded">
                    <Lock className="w-3 h-3 text-amber-400" />
                    {currentSelectedPersona.clearance}
                  </span>
                </div>
              </div>

              {/* Error Alert */}
              {errorMessage && (
                <div className="mb-5 p-3 rounded-lg bg-rose-950/80 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-2.5 animate-shake">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex-1">{errorMessage}</div>
                </div>
              )}

              {/* Authentication Mode Tabs */}
              <div className="grid grid-cols-3 gap-1.5 p-1 bg-slate-950 rounded-xl border border-slate-800 mb-6">
                <button
                  type="button"
                  onClick={() => setAuthMethod('credentials')}
                  className={`py-2 text-xs font-medium rounded-lg flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                    authMethod === 'credentials'
                      ? 'bg-slate-800 text-white shadow-xs font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Password + MFA</span>
                </button>
                <button
                  type="button"
                  onClick={() => setAuthMethod('biometric')}
                  className={`py-2 text-xs font-medium rounded-lg flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                    authMethod === 'biometric'
                      ? 'bg-slate-800 text-white shadow-xs font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Fingerprint className="w-3.5 h-3.5" />
                  <span>Biometric</span>
                </button>
                <button
                  type="button"
                  onClick={() => setAuthMethod('yubikey')}
                  className={`py-2 text-xs font-medium rounded-lg flex items-center justify-center gap-1.5 transition-all cursor-pointer ${
                    authMethod === 'yubikey'
                      ? 'bg-slate-800 text-white shadow-xs font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>FIDO2 Token</span>
                </button>
              </div>

              {/* Mode 1: Standard Credentials Form */}
              {authMethod === 'credentials' && (
                <form onSubmit={handleLoginSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Analyst Corporate Email / Badge ID
                    </label>
                    <div className="relative">
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={e => setEmail(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-rose-500/50 focus:border-rose-500 transition-all font-mono"
                        placeholder="analyst@company.soc"
                      />
                      <span className="absolute right-3 top-2.5 text-[10px] text-slate-400 font-mono">
                        {currentSelectedPersona.badgeNumber}
                      </span>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <label className="block text-xs font-medium text-slate-300">
                        Cryptographic Master Passphrase
                      </label>
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1 cursor-pointer"
                      >
                        {showPassword ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                        <span>{showPassword ? 'Hide' : 'Show'}</span>
                      </button>
                    </div>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-rose-500/50 focus:border-rose-500 transition-all font-mono"
                      placeholder="••••••••••••••••"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                      <span>Multi-Factor 2FA Code (TOTP)</span>
                      <span className="text-[10px] text-emerald-400 font-mono">Verified Token: 849201</span>
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        maxLength={6}
                        value={mfaCode}
                        onChange={e => setMfaCode(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3.5 py-2.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-rose-500/50 focus:border-rose-500 transition-all font-mono tracking-widest text-center text-sm font-semibold"
                        placeholder="849201"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isSubmitting || isAnalyzing}
                    className="w-full mt-2 bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-semibold py-3 px-4 rounded-xl text-xs flex items-center justify-center gap-2 shadow-lg shadow-rose-900/40 transition-all active:scale-98 cursor-pointer disabled:opacity-50"
                  >
                    {isSubmitting ? (
                      <>
                        <Sparkles className="w-4 h-4 animate-spin text-white" />
                        <span>Validating Cryptographic Token...</span>
                      </>
                    ) : (
                      <>
                        <UserCheck className="w-4 h-4 text-white" />
                        <span>Authenticate & Access SOC Grid</span>
                        <ChevronRight className="w-4 h-4 text-white/80" />
                      </>
                    )}
                  </button>
                </form>
              )}

              {/* Mode 2: Biometric Fingerprint / Face Scanner */}
              {authMethod === 'biometric' && (
                <div className="py-8 flex flex-col items-center justify-center text-center">
                  <div
                    onClick={handleBiometricAuth}
                    className={`w-28 h-28 rounded-3xl border-2 flex items-center justify-center cursor-pointer transition-all duration-500 relative ${
                      biometricScanning
                        ? 'border-emerald-500 bg-emerald-950/40 shadow-xl shadow-emerald-500/20 animate-pulse'
                        : 'border-slate-700 bg-slate-950 hover:border-rose-500/80 hover:bg-slate-900 shadow-md'
                    }`}
                  >
                    <Fingerprint
                      className={`w-14 h-14 transition-colors ${
                        biometricScanning ? 'text-emerald-400' : 'text-slate-400 hover:text-rose-400'
                      }`}
                    />
                    {biometricScanning && (
                      <div className="absolute inset-x-2 top-0 h-1 bg-emerald-400 rounded-full animate-bounce shadow-md" />
                    )}
                  </div>

                  <h3 className="text-sm font-semibold text-white mt-4">
                    {biometricScanning ? 'Verifying WebAuthn Biometric Certificate...' : 'Touch Fingerprint Sensor or Face ID'}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1 max-w-xs">
                    Click sensor to emulate hardware-bound biometric authentication for {currentSelectedPersona.name} ({currentSelectedPersona.clearance}).
                  </p>

                  <button
                    type="button"
                    onClick={handleBiometricAuth}
                    disabled={biometricScanning}
                    className="mt-5 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white border border-slate-700 transition-all cursor-pointer"
                  >
                    {biometricScanning ? 'Authenticating...' : 'Simulate Biometric Verification'}
                  </button>
                </div>
              )}

              {/* Mode 3: Hardware Security Key (FIDO2/YubiKey) */}
              {authMethod === 'yubikey' && (
                <div className="py-8 flex flex-col items-center justify-center text-center">
                  <div
                    onClick={handleBiometricAuth}
                    className="w-28 h-28 rounded-3xl border-2 border-slate-700 bg-slate-950 hover:border-amber-500/80 flex items-center justify-center cursor-pointer transition-all shadow-md"
                  >
                    <KeyRound className="w-14 h-14 text-amber-400 animate-pulse" />
                  </div>
                  <h3 className="text-sm font-semibold text-white mt-4">Insert & Tap Hardware Security Key</h3>
                  <p className="text-xs text-slate-400 mt-1 max-w-xs">
                    FIDO2 / U2F Security Key detected on USB-C bus. Tap metal contact to sign cryptographic challenge.
                  </p>
                  <button
                    type="button"
                    onClick={handleBiometricAuth}
                    className="mt-5 px-5 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-xs font-semibold text-white shadow-lg shadow-amber-900/30 transition-all cursor-pointer"
                  >
                    Tap FIDO2 Key & Sign In
                  </button>
                </div>
              )}
            </div>

            {/* Bottom Security Compliance Disclaimer */}
            <div className="pt-4 border-t border-slate-800/80 text-center text-[10px] text-slate-500 font-mono">
              SESSION MONITORED UNDER NIST 800-53 / ISO 27001 AUDIT CONTROLS
            </div>
          </div>

        </div>
      </div>

      {/* Bottom Footer Information */}
      <footer className="bg-slate-900 border-t border-slate-800 px-6 py-3 text-xs text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-2 z-10">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500" />
          <span className="font-semibold text-slate-300">CyberShield SOC Production Enclave</span>
          <span>•</span>
          <span>All telemetry encrypted at rest (AES-256)</span>
        </div>
        <div className="font-mono text-[11px] text-slate-500">
          Node: us-east-soc-primary • Latency: 12ms
        </div>
      </footer>
    </div>
  );
};
