export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ThreatStatus = 'investigating' | 'open' | 'contained' | 'remediated' | 'false_positive';
export type ThreatCategory = 
  | 'Brute Force Attack'
  | 'Ransomware Outbreak'
  | 'Phishing Campaign'
  | 'Malware & C2 Beaconing'
  | 'API Credential Abuse'
  | 'Insider Data Exfiltration'
  | 'DDoS Flooding'
  | 'Privilege Escalation'
  | 'Suspicious Anomaly';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  user: string;
  action: string;
  eventCategory: 'AUTH' | 'FIREWALL' | 'ENDPOINT' | 'NETWORK' | 'CLOUD' | 'EMAIL' | 'SYSTEM';
  sourceCountry: string;
  protocol: string;
  port: number;
  rawMessage: string;
  severity: Severity;
  assetName: string;
  isAnomaly: boolean;
  threatCode?: string;
}

export interface IoCRecord {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'user' | 'cve';
  value: string;
  risk: Severity;
  associatedThreats: string[]; // Threat IDs / codes
  occurrences: number;
  reputation: string; // e.g. "AbuseIPDB 98% Malicious" or "Known CobaltStrike C2"
  firstSeen: string;
  lastSeen: string;
  notes: string;
}

export interface AffectedAsset {
  id: string;
  name: string;
  ip: string;
  role: string;
  os: string;
  criticality: 'Tier-1 Critical' | 'High' | 'Medium' | 'Low';
  status: 'compromised' | 'targeted' | 'at_risk' | 'secure' | 'isolated';
  vulnerabilities: string[];
}

export interface AttackStep {
  step: number;
  phase: string; // e.g. "Initial Access", "Credential Access", "Lateral Movement"
  technique: string;
  description: string;
  timestamp: string;
  indicator: string;
  status: 'detected' | 'blocked' | 'in_progress';
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  url: string;
  description: string;
}

export interface PlaybookAction {
  id: string;
  priority: 'P1 (Immediate)' | 'P2 (Containment)' | 'P3 (Eradication/Recovery)';
  title: string;
  action: string;
  rationale: string;
  type: 'block_ip' | 'isolate_host' | 'revoke_token' | 'quarantine_email' | 'patch_cve' | 'manual';
  target: string;
  executed: boolean;
  executionTime?: string;
  commandSnippet?: string;
}

export interface RemediationLog {
  id: string;
  timestamp: string;
  actionTitle: string;
  performedBy: string;
  status: 'SUCCESS' | 'FAILED' | 'PENDING';
  details: string;
}

export interface ThreatAlert {
  id: string;
  threatCode: string; // e.g. "TH-1042"
  title: string;
  threatType: ThreatCategory;
  severity: Severity;
  confidence: number; // 0 - 100
  status: ThreatStatus;
  firstDetected: string;
  lastActivity: string;
  sourceIps: string[];
  targetAccounts: string[];
  affectedAssets: AffectedAsset[];
  iocs: IoCRecord[];
  attackPattern: AttackStep[];
  mitreAttack: MitreTechnique[];
  aiSummary: string;
  detailedReasoning: string;
  recommendedActions: PlaybookAction[];
  riskScore: number; // 0 - 100
  correlatedEventIds: string[];
  remediationHistory: RemediationLog[];
  campaignId?: string;
  campaignTitle?: string;
}

export interface IncidentCampaign {
  id: string;
  title: string;
  threatActor: string;
  threatIds: string[];
  summary: string;
  severity: Severity;
  status: 'active' | 'contained' | 'remediated';
  killChainProgress: number; // 0 - 100
  firstSeen: string;
  targetedAssetsCount: number;
}

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant';
  timestamp: string;
  text: string;
  codeSnippet?: string;
  threatCode?: string;
}

export interface PhishingAnalysisResult {
  isPhishing: boolean;
  confidence: number;
  phishingType: string;
  riskLevel: Severity;
  indicators: string[];
  extractedLinks: string[];
  spoofedBrand: string;
  recommendation: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  category: ThreatCategory;
  severity: Severity;
  threatActor?: string;
  targetAssets: string[];
  mitreTechniques: string[];
  events: Partial<SecurityEvent>[];
  threatPayload?: ThreatAlert;
}

export type UserRole = 
  | 'lead_soc_analyst'
  | 'dfir_investigator'
  | 'threat_hunter'
  | 'ciso_executive'
  | 'junior_analyst';

export type ClearanceLevel = 
  | 'TOP SECRET // SCI'
  | 'SECRET // SOC-DFIR'
  | 'CONFIDENTIAL // TLP:AMBER'
  | 'EXECUTIVE READ-ONLY';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  roleTitle: string;
  clearance: ClearanceLevel;
  badgeNumber: string;
  mfaEnabled: boolean;
  mfaMethod: 'TOTP Authenticator' | 'Hardware Security Key (FIDO2)' | 'Biometric WebAuthn';
  avatar: string;
  assignedJurisdiction: string;
  department: string;
  sessionStarted: string;
  lastActive: string;
  permissions: string[];
}

export interface SecurityAuditLog {
  id: string;
  timestamp: string;
  userId: string;
  userName: string;
  userRole: string;
  action: string;
  category: 'AUTH' | 'CONTAINMENT' | 'INVESTIGATION' | 'PLAYBOOK' | 'POLICY' | 'EXPORT';
  target: string;
  ipAddress: string;
  status: 'AUTHORIZED' | 'DENIED' | 'FLAGGED';
  details: string;
}

