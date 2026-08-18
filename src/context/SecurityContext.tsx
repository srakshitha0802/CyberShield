import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  SecurityEvent,
  ThreatAlert,
  IncidentCampaign,
  IoCRecord,
  PlaybookAction,
  CopilotMessage,
  AttackScenario,
  User,
  UserRole,
  SecurityAuditLog,
} from '../types/security';
import { INITIAL_THREATS, INITIAL_CAMPAIGNS, SAMPLE_LOG_FEED } from '../data/sampleScenarios';
import { ANALYST_PERSONAS, INITIAL_AUDIT_LOGS } from '../data/analystPersonas';
import { detectThreatsFromEvents, generateSimulatedLiveEvent, parseRawSecurityLogs } from '../utils/detectionEngine';
import confetti from 'canvas-confetti';

const DEFAULT_SCENARIOS: AttackScenario[] = [
  {
    id: 'scenario-brute-force',
    name: 'Distributed Kerberos Password Spray & LSASS Dump',
    description: 'Rapid failed authentication barrage against Active Directory DC-01 from Tor/Russian hosting nodes, ending in successful admin Kerberos ticket and LSASS injection.',
    category: 'Brute Force Attack',
    severity: 'critical',
    threatActor: 'UNC2452 / APT-29',
    targetAssets: ['Active-Directory-DC01', 'Authentication-Relay-02'],
    mitreTechniques: ['T1110.003 Password Spraying', 'T1003.001 LSASS Memory', 'T1078 Valid Accounts'],
    events: [
      {
        timestamp: '2026-08-17 02:14:00 UTC',
        sourceIp: '185.220.101.5',
        destIp: '10.0.1.5',
        user: 'admin@company.com',
        action: 'KERBEROS_PREAUTH_FAILED',
        eventCategory: 'AUTH',
        rawMessage: 'Event ID 4771: Kerberos pre-authentication failed for admin@company.com (Code: 0x18 - Bad Password)',
        severity: 'high',
        assetName: 'Active-Directory-DC01',
      },
    ],
  },
  {
    id: 'scenario-ransomware',
    name: 'LockBit 3.0 Ransomware Outbreak & Shadow Wipe',
    description: 'Spear-phishing lure opens macro executing encoded PowerShell stager, vssadmin shadow copy deletion, and high-entropy canary file encryption on Finance DB.',
    category: 'Ransomware Outbreak',
    severity: 'critical',
    threatActor: 'LockBit Supporter Affiliate',
    targetAssets: ['Finance-DB-Server', 'Backup-NAS-01'],
    mitreTechniques: ['T1486 Data Encrypted for Impact', 'T1490 Inhibit System Recovery', 'T1059.001 PowerShell'],
    events: [
      {
        timestamp: '2026-08-17 01:45:00 UTC',
        sourceIp: '10.0.3.44',
        destIp: '10.0.3.44',
        user: 'SYSTEM',
        action: 'VSSADMIN_SHADOW_PURGE',
        eventCategory: 'ENDPOINT',
        rawMessage: 'CommandLine: vssadmin.exe delete shadows /all /quiet && wbadmin delete catalog -quiet',
        severity: 'critical',
        assetName: 'Finance-DB-Server',
      },
    ],
  },
  {
    id: 'scenario-cloud-exfil',
    name: 'Leaked AWS IAM Token & S3 Data Exfiltration',
    description: 'Compromised developer CI/CD secret used from unauthorized foreign cloud proxy to enumerate and exfiltrate customer databases via bulk S3 GetObject.',
    category: 'API Credential Abuse',
    severity: 'high',
    threatActor: 'Scattered Spider / Extortionist',
    targetAssets: ['Cloud-API-Gateway', 's3://prod-customer-backups-bucket'],
    mitreTechniques: ['T1530 Data from Cloud Storage Object', 'T1078.004 Cloud Accounts'],
    events: [
      {
        timestamp: '2026-08-17 02:01:14 UTC',
        sourceIp: '103.145.74.22',
        destIp: '35.198.22.90',
        user: 'aws_iam_terraform_deployer',
        action: 'S3_BULK_GET_OBJECT',
        eventCategory: 'CLOUD',
        rawMessage: 'CloudTrail: Bulk S3 GetObject loop (14,200 objects / 18.4 GB exfiltrated to foreign ASN)',
        severity: 'high',
        assetName: 'Cloud-API-Gateway',
      },
    ],
  },
  {
    id: 'scenario-c2-beacon',
    name: 'Cobalt Strike C2 Beaconing from HR Web Node',
    description: 'Post-exploitation beaconing over HTTPS with jittered intervals and matching JARM TLS fingerprint to hostile command-and-control server.',
    category: 'Malware & C2 Beaconing',
    severity: 'high',
    threatActor: 'APT41 / Barium',
    targetAssets: ['HR-Portal-Server'],
    mitreTechniques: ['T1071.001 Web Protocols', 'T1573.002 Asymmetric Cryptography'],
    events: [
      {
        timestamp: '2026-08-17 02:18:00 UTC',
        sourceIp: '10.0.2.18',
        destIp: '195.123.246.77',
        user: 'www-data',
        action: 'C2_HTTPS_BEACON',
        eventCategory: 'NETWORK',
        rawMessage: 'Suricata Alert: CobaltStrike C2 HTTPS Beaconing detected (JARM: 07d14d16d21d21d07c07d14d16d21d)',
        severity: 'high',
        assetName: 'HR-Portal-Server',
      },
    ],
  },
];

const INITIAL_COPILOT_MESSAGES: CopilotMessage[] = [
  {
    id: 'copilot-1',
    sender: 'assistant',
    timestamp: '02:00:00 UTC',
    text: `Hello Analyst. I am CyberShield AI, your autonomous SOC Copilot.

I have cross-correlated telemetry across your firewalls, Active Directory, cloud gateways, and endpoints. Currently, **1 Critical Incident (TH-1042: Kerberos Brute Force)** requires immediate mitigation.

How can I assist your investigation or containment workflow today?`,
  },
];

interface SecurityContextType {
  currentUser: User | null;
  isAuthenticated: boolean;
  isSessionLocked: boolean;
  defconLevel: 1 | 2 | 3 | 4 | 5;
  auditLogs: SecurityAuditLog[];
  events: SecurityEvent[];
  threats: ThreatAlert[];
  campaigns: IncidentCampaign[];
  selectedThreatId: string | null;
  activeTab: string;
  isLiveStreaming: boolean;
  streamSpeed: number;
  soundEnabled: boolean;
  isAnalyzing: boolean;
  copilotMessages: CopilotMessage[];
  sampleScenarios: AttackScenario[];
  attackScenarios: AttackScenario[];
  notification: { message: string; type: 'critical' | 'high' | 'success' | 'info' } | null;
  setActiveTab: (tab: string) => void;
  setSelectedThreatId: (id: string | null) => void;
  setIsLiveStreaming: (streaming: boolean) => void;
  setStreamSpeed: (speed: number) => void;
  setSoundEnabled: (enabled: boolean) => void;
  setDefconLevel: (level: 1 | 2 | 3 | 4 | 5) => void;
  clearNotification: () => void;
  login: (userOrRole: User | UserRole, password?: string, mfaCode?: string) => Promise<boolean>;
  logout: () => void;
  lockSession: () => void;
  unlockSession: (pin?: string) => boolean;
  switchUserRole: (role: UserRole) => void;
  addAuditLog: (entry: Omit<SecurityAuditLog, 'id' | 'timestamp' | 'userId' | 'userName' | 'userRole'>) => void;
  checkPermission: (permission: string) => boolean;
  ingestRawLogs: (rawText: string) => Promise<{ parsedCount: number; newThreatsCount: number }>;
  triggerAttackScenario: (scenarioOrId: string | AttackScenario) => Promise<void>;
  executePlaybookAction: (threatId: string, actionId: string) => Promise<boolean>;
  updateThreatStatus: (threatId: string, status: ThreatAlert['status']) => void;
  analyzeThreatWithAI: (threatId: string) => Promise<void>;
  sendCopilotMessage: (query: string, currentThreat?: ThreatAlert) => Promise<void>;
  getSelectedThreat: () => ThreatAlert | undefined;
  getAllIocs: () => IoCRecord[];
}

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Auth & Session States
  const [currentUser, setCurrentUser] = useState<User | null>(ANALYST_PERSONAS[0]); // Default logged in as Lead Incident Commander
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(true);
  const [isSessionLocked, setIsSessionLocked] = useState<boolean>(false);
  const [defconLevel, setDefconLevel] = useState<1 | 2 | 3 | 4 | 5>(2); // DEFCON 2: High Readiness
  const [auditLogs, setAuditLogs] = useState<SecurityAuditLog[]>(INITIAL_AUDIT_LOGS);

  const [events, setEvents] = useState<SecurityEvent[]>(SAMPLE_LOG_FEED);
  const [threats, setThreats] = useState<ThreatAlert[]>(INITIAL_THREATS);
  const [campaigns, setCampaigns] = useState<IncidentCampaign[]>(INITIAL_CAMPAIGNS);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>('threat-1042');
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);
  const [streamSpeed, setStreamSpeed] = useState<number>(3000);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [copilotMessages, setCopilotMessages] = useState<CopilotMessage[]>(INITIAL_COPILOT_MESSAGES);
  const [sampleScenarios] = useState<AttackScenario[]>(DEFAULT_SCENARIOS);
  const [notification, setNotification] = useState<{ message: string; type: 'critical' | 'high' | 'success' | 'info' } | null>(null);

  // Play audio alert
  const playAlertSound = useCallback((type: 'critical' | 'high' | 'action') => {
    if (!soundEnabled) return;
    try {
      const audioCtx = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      if (type === 'critical') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.3);
      } else if (type === 'action') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(523.25, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(659.25, audioCtx.currentTime + 0.2);
        gain.gain.setValueAtTime(0.06, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.2);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.2);
      }
    } catch {
      // Audio context may require gesture
    }
  }, [soundEnabled]);

  // Live streaming interval
  useEffect(() => {
    if (!isLiveStreaming) return;
    const interval = setInterval(() => {
      const newEvent = generateSimulatedLiveEvent();
      setEvents(prev => [newEvent, ...prev.slice(0, 199)]);

      if (newEvent.severity === 'critical') {
        setNotification({
          message: `🚨 Critical Telemetry Anomaly on ${newEvent.assetName}: ${newEvent.action}`,
          type: 'critical',
        });
      }
    }, streamSpeed);

    return () => clearInterval(interval);
  }, [isLiveStreaming, streamSpeed]);

  const clearNotification = () => setNotification(null);

  // Ingest raw logs
  const ingestRawLogs = async (rawText: string): Promise<{ parsedCount: number; newThreatsCount: number }> => {
    setIsAnalyzing(true);
    try {
      const parsed = parseRawSecurityLogs(rawText);
      if (parsed.length === 0) {
        setIsAnalyzing(false);
        return { parsedCount: 0, newThreatsCount: 0 };
      }

      setEvents(prev => [...parsed, ...prev].slice(0, 300));
      const detected = detectThreatsFromEvents(parsed, threats);

      if (detected.length > 0) {
        const primaryThreat = detected[0];
        try {
          const res = await fetch('/api/analyze-threat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              rawLogs: parsed.slice(0, 15),
              eventData: primaryThreat,
            }),
          });
          if (res.ok) {
            const aiData = await res.json();
            if (aiData.success && aiData.data) {
              primaryThreat.title = aiData.data.threatTitle || primaryThreat.title;
              primaryThreat.aiSummary = aiData.data.aiSummary || primaryThreat.aiSummary;
              primaryThreat.detailedReasoning = aiData.data.detailedReasoning || primaryThreat.detailedReasoning;
              primaryThreat.confidence = aiData.data.confidenceScore || primaryThreat.confidence;
              primaryThreat.severity = aiData.data.severity || primaryThreat.severity;
              if (aiData.data.attackPattern?.length) primaryThreat.attackPattern = aiData.data.attackPattern;
              if (aiData.data.mitreAttack?.length) primaryThreat.mitreAttack = aiData.data.mitreAttack;
              if (aiData.data.recommendedActions?.length) primaryThreat.recommendedActions = aiData.data.recommendedActions;
            }
          }
        } catch {
          // Fallback handled locally
        }

        setThreats(prev => [primaryThreat, ...detected.slice(1), ...prev]);
        setSelectedThreatId(primaryThreat.id);
        playAlertSound('critical');
        setNotification({
          message: `🚨 AI Threat Ingested: ${primaryThreat.title} (Confidence: ${primaryThreat.confidence}%)`,
          type: 'critical',
        });
      }

      setIsAnalyzing(false);
      return { parsedCount: parsed.length, newThreatsCount: detected.length };
    } catch (err) {
      console.error('Ingest error:', err);
      setIsAnalyzing(false);
      return { parsedCount: 0, newThreatsCount: 0 };
    }
  };

  // Trigger attack scenario
  const triggerAttackScenario = async (scenarioOrId: string | AttackScenario) => {
    setIsAnalyzing(true);
    const scenarioId = typeof scenarioOrId === 'string' ? scenarioOrId : scenarioOrId?.id || 'scenario-brute-force';
    let newThreatCode = 'TH-1055';
    let title = typeof scenarioOrId === 'object' && scenarioOrId?.name ? scenarioOrId.name : 'Automated Attack Injected';
    let threatCategory: ThreatAlert['threatType'] = (typeof scenarioOrId === 'object' && scenarioOrId?.category) ? scenarioOrId.category : 'Brute Force Attack';
    let severity: ThreatAlert['severity'] = (typeof scenarioOrId === 'object' && scenarioOrId?.severity) ? scenarioOrId.severity : 'critical';
    let sourceIp = '185.220.101.99';
    let targetAsset = (typeof scenarioOrId === 'object' && scenarioOrId?.targetAssets?.[0]) ? scenarioOrId.targetAssets[0] : 'Active-Directory-DC01';
    let summary = typeof scenarioOrId === 'object' && scenarioOrId?.description ? scenarioOrId.description : 'High-velocity simulated attack events injected into SOC event bus.';

    if (scenarioId === 'scenario-brute-force') {
      newThreatCode = 'TH-1051';
      title = 'Distributed Kerberos Password Spray & Domain Takeover Attempt';
      threatCategory = 'Brute Force Attack';
      severity = 'critical';
      sourceIp = '185.220.101.44';
      targetAsset = 'Active-Directory-DC01';
      summary = '50+ rapid failed Kerberos pre-auth requests from Tor exit nodes followed by admin ticket grant.';
    } else if (scenarioId === 'scenario-ransomware') {
      newThreatCode = 'TH-1052';
      title = 'LockBit 3.0 Ransomware Outbreak Simulation';
      threatCategory = 'Ransomware Outbreak';
      severity = 'critical';
      sourceIp = '91.240.118.99';
      targetAsset = 'Finance-DB-Server';
      summary = 'Phishing macro dropped PowerShell stager invoking vssadmin shadow copy purge.';
    } else if (scenarioId === 'scenario-cloud-exfil') {
      newThreatCode = 'TH-1053';
      title = 'Compromised Cloud IAM Token & S3 Data Exfiltration';
      threatCategory = 'API Credential Abuse';
      severity = 'high';
      sourceIp = '103.145.74.88';
      targetAsset = 'Cloud-API-Gateway';
      summary = 'Bulk S3 GetObject loop iterating over customer confidential database backups.';
    } else if (scenarioId === 'scenario-c2-beacon') {
      newThreatCode = 'TH-1054';
      title = 'CobaltStrike C2 Beaconing from HR Server';
      threatCategory = 'Malware & C2 Beaconing';
      severity = 'high';
      sourceIp = '195.123.246.77';
      targetAsset = 'HR-Portal-Server';
      summary = 'Periodic 30-second HTTPS beaconing with JARM signature match to foreign adversary listener.';
    }

    const generatedThreat: ThreatAlert = {
      id: `threat-injected-${Date.now()}`,
      threatCode: newThreatCode,
      title,
      threatType: threatCategory,
      severity,
      confidence: 98,
      status: 'investigating',
      firstDetected: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
      lastActivity: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
      sourceIps: [sourceIp],
      targetAccounts: ['admin@company.com', 'service_deployer'],
      riskScore: severity === 'critical' ? 96 : 84,
      aiSummary: summary,
      detailedReasoning: `Live Attack Injection Engine triggered: Multi-stage telemetry events generated across ${targetAsset}. Automated rule correlation and AI SOC analyst confirmed malicious activity requiring immediate containment.`,
      attackPattern: [
        {
          step: 1,
          phase: 'Initial Recon & Access',
          technique: 'Automated Exploitation (T1190)',
          description: `Telemetry surge observed targeting ${targetAsset} from ${sourceIp}.`,
          timestamp: new Date().toISOString().replace('T', ' ').substring(11, 19) + ' UTC',
          indicator: sourceIp,
          status: 'detected',
        },
        {
          step: 2,
          phase: 'Execution & Privilege Escalation',
          technique: 'Command and Scripting (T1059)',
          description: 'Process injected memory stager requesting elevated kernel handles.',
          timestamp: new Date().toISOString().replace('T', ' ').substring(11, 19) + ' UTC',
          indicator: 'Process ID #8812',
          status: 'in_progress',
        },
      ],
      mitreAttack: [
        {
          id: 'T1110',
          name: 'Brute Force',
          tactic: 'Credential Access',
          url: 'https://attack.mitre.org/techniques/T1110/',
          description: 'Iterating through passwords or hashes to gain access.',
        },
      ],
      iocs: [
        {
          id: `ioc-inj-${Date.now()}-1`,
          type: 'ip',
          value: sourceIp,
          risk: severity,
          associatedThreats: [newThreatCode],
          occurrences: 48,
          reputation: 'Adversary Infrastructure (Tor Exit / C2 Staging)',
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          notes: 'Source IP of injected attack scenario.',
        },
      ],
      affectedAssets: [
        {
          id: `asset-inj-${Date.now()}`,
          name: targetAsset,
          ip: '10.0.1.5',
          role: 'Production Core Asset',
          os: 'Windows Server 2022',
          criticality: 'Tier-1 Critical',
          status: 'targeted',
          vulnerabilities: ['Active Zero-Day Probe'],
        },
      ],
      recommendedActions: [
        {
          id: `act-inj-1`,
          priority: 'P1 (Immediate)',
          title: `Block Attacking IP ${sourceIp} on Edge Firewall`,
          action: `Deploy perimeter rule to drop all incoming packets from ${sourceIp}.`,
          rationale: 'Sever adversary connection instantly.',
          type: 'block_ip',
          target: sourceIp,
          executed: false,
          commandSnippet: `iptables -I INPUT -s ${sourceIp} -j DROP`,
        },
        {
          id: `act-inj-2`,
          priority: 'P2 (Containment)',
          title: `Isolate ${targetAsset} from Internal VLAN`,
          action: 'Apply EDR host isolation policy.',
          rationale: 'Stop lateral movement to adjacent subnets.',
          type: 'isolate_host',
          target: targetAsset,
          executed: false,
        },
      ],
      correlatedEventIds: [],
      remediationHistory: [],
    };

    setThreats(prev => [generatedThreat, ...prev]);
    setSelectedThreatId(generatedThreat.id);
    setActiveTab('investigation');
    setIsAnalyzing(false);
    playAlertSound('critical');
    setNotification({
      message: `🚨 NEW THREAT DETECTED: [${newThreatCode}] ${title}`,
      type: 'critical',
    });
  };

  // Execute interactive playbook containment action
  const executePlaybookAction = async (threatId: string, actionId: string): Promise<boolean> => {
    let success = false;
    setThreats(prev =>
      prev.map(t => {
        if (t.id === threatId) {
          const action = t.recommendedActions.find(a => a.id === actionId);
          if (!action) return t;

          const updatedActions = t.recommendedActions.map(a =>
            a.id === actionId ? { ...a, executed: true, executionTime: new Date().toISOString() } : a
          );

          const allP1Executed = updatedActions.filter(a => a.priority === 'P1 (Immediate)').every(a => a.executed);
          const newStatus: ThreatAlert['status'] = allP1Executed ? 'contained' : t.status;

          const newLog = {
            id: `rem-${Date.now()}`,
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
            actionTitle: action.title,
            performedBy: 'CyberShield Autonomous Response & SOC Analyst',
            status: 'SUCCESS' as const,
            details: `Successfully executed: ${action.action}. Target [${action.target}] contained.`,
          };

          const updatedAssets = t.affectedAssets.map(asset => {
            if (action.type === 'isolate_host' && (asset.name.includes(action.target) || asset.ip.includes(action.target))) {
              return { ...asset, status: 'isolated' as const };
            }
            return asset;
          });

          success = true;
          return {
            ...t,
            status: newStatus,
            recommendedActions: updatedActions,
            affectedAssets: updatedAssets,
            remediationHistory: [newLog, ...t.remediationHistory],
          };
        }
        return t;
      })
    );

    if (success) {
      playAlertSound('action');
      confetti({
        particleCount: 40,
        spread: 60,
        origin: { y: 0.8 },
        colors: ['#10b981', '#06b6d4', '#3b82f6'],
      });
      setNotification({
        message: '🛡️ Containment action successfully executed! Threat isolated.',
        type: 'success',
      });
    }

    return success;
  };

  const updateThreatStatus = (threatId: string, status: ThreatAlert['status']) => {
    setThreats(prev =>
      prev.map(t => (t.id === threatId ? { ...t, status } : t))
    );
  };

  const analyzeThreatWithAI = async (threatId: string) => {
    const targetThreat = threats.find(t => t.id === threatId);
    if (!targetThreat) return;

    setIsAnalyzing(true);
    try {
      const res = await fetch('/api/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rawLogs: targetThreat.aiSummary + '\n' + targetThreat.detailedReasoning,
          eventData: targetThreat,
        }),
      });

      if (res.ok) {
        const result = await res.json();
        if (result.success && result.data) {
          setThreats(prev =>
            prev.map(t => {
              if (t.id === threatId) {
                return {
                  ...t,
                  title: result.data.threatTitle || t.title,
                  aiSummary: result.data.aiSummary || t.aiSummary,
                  detailedReasoning: result.data.detailedReasoning || t.detailedReasoning,
                  confidence: result.data.confidenceScore || t.confidence,
                  attackPattern: result.data.attackPattern?.length ? result.data.attackPattern : t.attackPattern,
                  mitreAttack: result.data.mitreAttack?.length ? result.data.mitreAttack : t.mitreAttack,
                  recommendedActions: result.data.recommendedActions?.length ? result.data.recommendedActions : t.recommendedActions,
                };
              }
              return t;
            })
          );
        }
      }
    } catch (err) {
      console.error('AI refresh error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const sendCopilotMessage = async (query: string, currentThreat?: ThreatAlert) => {
    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}`,
      sender: 'user',
      timestamp: new Date().toISOString().replace('T', ' ').substring(11, 19) + ' UTC',
      text: query,
    };

    setCopilotMessages(prev => [...prev, userMsg]);

    try {
      const res = await fetch('/api/security/copilot-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: query,
          threatContext: currentThreat || threats[0],
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const aiMsg: CopilotMessage = {
          id: `msg-ai-${Date.now()}`,
          sender: 'assistant',
          timestamp: new Date().toISOString().replace('T', ' ').substring(11, 19) + ' UTC',
          text: data.reply,
          codeSnippet: data.codeSnippet,
          threatCode: currentThreat?.threatCode,
        };
        setCopilotMessages(prev => [...prev, aiMsg]);
        return;
      }
    } catch (err) {
      console.error('Copilot API error:', err);
    }

    // Heuristic Fallback reply
    const fallbackReply: CopilotMessage = {
      id: `msg-ai-${Date.now()}`,
      sender: 'assistant',
      timestamp: new Date().toISOString().replace('T', ' ').substring(11, 19) + ' UTC',
      text: `Based on incident telemetry for ${currentThreat?.threatCode || 'active threats'}, this attack exhibits high-frequency adversary probing with credential abuse indicators. 

**Recommended Action Plan:**
1. Block attacking IP origin at the boundary firewall
2. Isolate target host from internal routing
3. Force credential rotation for targeted identities`,
      codeSnippet: `iptables -A INPUT -s ${currentThreat?.sourceIps[0] || '185.220.101.5'} -j DROP`,
      threatCode: currentThreat?.threatCode,
    };
    setCopilotMessages(prev => [...prev, fallbackReply]);
  };

  const addAuditLog = useCallback(
    (entry: Omit<SecurityAuditLog, 'id' | 'timestamp' | 'userId' | 'userName' | 'userRole'>) => {
      const newEntry: SecurityAuditLog = {
        id: `audit-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
        userId: currentUser?.id || 'anonymous',
        userName: currentUser?.name || 'Unauthenticated User',
        userRole: currentUser?.roleTitle || 'Guest',
        ...entry,
      };
      setAuditLogs(prev => [newEntry, ...prev.slice(0, 99)]);
    },
    [currentUser]
  );

  const checkPermission = useCallback(
    (permission: string): boolean => {
      if (!currentUser) return false;
      if (currentUser.permissions.includes('ALL_PERMISSIONS')) return true;
      return currentUser.permissions.includes(permission);
    },
    [currentUser]
  );

  const login = async (userOrRole: User | UserRole, _password?: string, _mfaCode?: string): Promise<boolean> => {
    let targetUser: User | undefined;
    if (typeof userOrRole === 'string') {
      targetUser = ANALYST_PERSONAS.find(p => p.role === userOrRole) || ANALYST_PERSONAS[0];
    } else {
      targetUser = userOrRole;
    }

    const updatedUser = {
      ...targetUser,
      sessionStarted: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
      lastActive: 'Just now',
    };

    setCurrentUser(updatedUser);
    setIsAuthenticated(true);
    setIsSessionLocked(false);

    addAuditLog({
      action: 'SOC_SESSION_LOGIN',
      category: 'AUTH',
      target: 'CyberShield SOC Terminal',
      ipAddress: '10.0.0.' + Math.floor(Math.random() * 200 + 10),
      status: 'AUTHORIZED',
      details: `Analyst authenticated via ${updatedUser.mfaMethod} with clearance level ${updatedUser.clearance}.`,
    });

    playAlertSound('action');
    setNotification({
      message: `🔐 Authenticated as ${updatedUser.name} (${updatedUser.roleTitle})`,
      type: 'success',
    });

    return true;
  };

  const logout = () => {
    if (currentUser) {
      addAuditLog({
        action: 'SOC_SESSION_LOGOUT',
        category: 'AUTH',
        target: 'CyberShield SOC Terminal',
        ipAddress: '10.0.0.84',
        status: 'AUTHORIZED',
        details: 'Analyst terminated active security session and cleared access tokens.',
      });
    }
    setCurrentUser(null);
    setIsAuthenticated(false);
    setIsSessionLocked(false);
    setNotification({
      message: '🔒 Security session ended. Please re-authenticate.',
      type: 'info',
    });
  };

  const lockSession = () => {
    setIsSessionLocked(true);
    addAuditLog({
      action: 'SOC_SESSION_LOCK',
      category: 'AUTH',
      target: 'Console Lock Screen',
      ipAddress: '10.0.0.84',
      status: 'AUTHORIZED',
      details: 'Terminal session manually locked by analyst.',
    });
  };

  const unlockSession = (_pin?: string): boolean => {
    setIsSessionLocked(false);
    addAuditLog({
      action: 'SOC_SESSION_UNLOCK',
      category: 'AUTH',
      target: 'Console Lock Screen',
      ipAddress: '10.0.0.84',
      status: 'AUTHORIZED',
      details: 'Terminal session unlocked via PIN / Biometric confirmation.',
    });
    return true;
  };

  const switchUserRole = (role: UserRole) => {
    const targetPersona = ANALYST_PERSONAS.find(p => p.role === role) || ANALYST_PERSONAS[0];
    setCurrentUser(targetPersona);
    addAuditLog({
      action: 'SECURITY_ROLE_SWITCH',
      category: 'AUTH',
      target: role,
      ipAddress: '10.0.0.84',
      status: 'AUTHORIZED',
      details: `Switched operational context to ${targetPersona.roleTitle} (${targetPersona.clearance}).`,
    });
    setNotification({
      message: `Switched operational role to: ${targetPersona.roleTitle}`,
      type: 'info',
    });
  };

  const getSelectedThreat = () => threats.find(t => t.id === selectedThreatId) || threats[0];

  const getAllIocs = (): IoCRecord[] => {
    const map = new Map<string, IoCRecord>();
    threats.forEach(t => {
      t.iocs.forEach(ioc => {
        if (!map.has(ioc.value)) {
          map.set(ioc.value, { ...ioc });
        } else {
          const existing = map.get(ioc.value)!;
          existing.occurrences += ioc.occurrences;
          if (!existing.associatedThreats.includes(t.threatCode)) {
            existing.associatedThreats.push(t.threatCode);
          }
        }
      });
    });
    return Array.from(map.values());
  };

  return (
    <SecurityContext.Provider
      value={{
        currentUser,
        isAuthenticated,
        isSessionLocked,
        defconLevel,
        auditLogs,
        events,
        threats,
        campaigns,
        selectedThreatId,
        activeTab,
        isLiveStreaming,
        streamSpeed,
        soundEnabled,
        isAnalyzing,
        copilotMessages,
        sampleScenarios,
        attackScenarios: sampleScenarios,
        notification,
        setActiveTab,
        setSelectedThreatId,
        setIsLiveStreaming,
        setStreamSpeed,
        setSoundEnabled,
        setDefconLevel,
        clearNotification,
        login,
        logout,
        lockSession,
        unlockSession,
        switchUserRole,
        addAuditLog,
        checkPermission,
        ingestRawLogs,
        triggerAttackScenario,
        executePlaybookAction,
        updateThreatStatus,
        analyzeThreatWithAI,
        sendCopilotMessage,
        getSelectedThreat,
        getAllIocs,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (!context) throw new Error('useSecurity must be used within a SecurityProvider');
  return context;
};
