import React, { useState } from 'react';
import { SecurityProvider, useSecurity } from './context/SecurityContext';
import { LoginPage } from './components/LoginPage';
import { LockScreen } from './components/LockScreen';
import { Navbar } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { LiveMonitorView } from './components/LiveMonitorView';
import { ThreatsView } from './components/ThreatsView';
import { InvestigationView } from './components/InvestigationView';
import { IocExplorerView } from './components/IocExplorerView';
import { AnalyticsView } from './components/AnalyticsView';
import { CopilotView } from './components/CopilotView';
import { PhishingSandboxView } from './components/PhishingSandboxView';
import { SoarPlaybooksView } from './components/SoarPlaybooksView';
import { DetectionEngineeringView } from './components/DetectionEngineeringView';
import { VulnerabilityMatrixView } from './components/VulnerabilityMatrixView';
import { IncidentReportModal } from './components/IncidentReportModal';
import { SimulateAttackModal } from './components/SimulateAttackModal';
import { UserSessionModal } from './components/UserSessionModal';
import { CommandPaletteModal } from './components/CommandPaletteModal';
import { NotificationToast } from './components/NotificationToast';
import { ThreatAlert } from './types/security';

const AppContent: React.FC = () => {
  const { activeTab, isAuthenticated, isSessionLocked } = useSecurity();
  const [isSimulateModalOpen, setIsSimulateModalOpen] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [reportThreat, setReportThreat] = useState<ThreatAlert | null>(null);

  // If unauthenticated, show the high-security SOC Operations login portal
  if (!isAuthenticated) {
    return <LoginPage />;
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans relative">
      {/* Session Lock Screen Overlay */}
      {isSessionLocked && <LockScreen />}

      {/* Top Navigation & Real-time status */}
      <Navbar
        onOpenSimulateModal={() => setIsSimulateModalOpen(true)}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        onOpenUserModal={() => setIsUserModalOpen(true)}
      />

      {/* Main Workspace View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6 sm:px-6">
        {activeTab === 'dashboard' && <DashboardView onOpenSimulateModal={() => setIsSimulateModalOpen(true)} />}
        {activeTab === 'monitor' && <LiveMonitorView />}
        {activeTab === 'threats' && <ThreatsView />}
        {activeTab === 'investigation' && (
          <InvestigationView onOpenReportModal={threat => setReportThreat(threat)} />
        )}
        {activeTab === 'playbooks' && <SoarPlaybooksView />}
        {activeTab === 'detection' && <DetectionEngineeringView />}
        {activeTab === 'vulns' && <VulnerabilityMatrixView />}
        {activeTab === 'iocs' && <IocExplorerView />}
        {activeTab === 'analytics' && <AnalyticsView />}
        {activeTab === 'copilot' && <CopilotView />}
        {activeTab === 'phishing' && <PhishingSandboxView />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white px-6 py-4 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-3 mt-auto">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-emerald-500"></span>
          <span className="font-medium text-slate-700">CyberShield AI</span>
          <span className="text-slate-300">•</span>
          <span>Autonomous Threat Detection & SOC Investigation Platform</span>
        </div>
        <div className="font-mono text-[11px] text-slate-500 flex items-center gap-3">
          <span>Engine: Qwen & Gemini 3.7 Flash</span>
          <span className="text-slate-300">•</span>
          <span>NIST SP 800-61 / MITRE ATT&CK v14</span>
        </div>
      </footer>

      {/* Real-time Notification Toasts */}
      <NotificationToast />

      {/* Modals */}
      <SimulateAttackModal
        isOpen={isSimulateModalOpen}
        onClose={() => setIsSimulateModalOpen(false)}
      />

      <IncidentReportModal
        threat={reportThreat}
        onClose={() => setReportThreat(null)}
      />

      <UserSessionModal
        isOpen={isUserModalOpen}
        onClose={() => setIsUserModalOpen(false)}
      />

      <CommandPaletteModal
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onOpenSimulateModal={() => setIsSimulateModalOpen(true)}
        onOpenUserModal={() => setIsUserModalOpen(true)}
      />
    </div>
  );
};

export default function App() {
  return (
    <SecurityProvider>
      <AppContent />
    </SecurityProvider>
  );
}

