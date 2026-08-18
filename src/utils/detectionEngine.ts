import { SecurityEvent, ThreatAlert, Severity, ThreatCategory, IoCRecord, AttackStep, MitreTechnique, PlaybookAction } from '../types/security';

// Parse raw logs in various formats (CSV, JSON, Syslog, Key-Value)
export function parseRawSecurityLogs(rawText: string): SecurityEvent[] {
  const events: SecurityEvent[] = [];
  const lines = rawText.split(/\r?\n/).filter(line => line.trim().length > 0);

  // Check if JSON array
  if (rawText.trim().startsWith('[') && rawText.trim().endsWith(']')) {
    try {
      const parsed = JSON.parse(rawText);
      if (Array.isArray(parsed)) {
        return parsed.map((item, idx) => normalizeJsonEvent(item, idx));
      }
    } catch {
      // fallback to line parsing
    }
  }

  // Check if CSV
  const firstLine = lines[0];
  if (firstLine && (firstLine.includes(',') || firstLine.includes(';')) && (firstLine.toLowerCase().includes('ip') || firstLine.toLowerCase().includes('user') || firstLine.toLowerCase().includes('action') || firstLine.toLowerCase().includes('timestamp'))) {
    return parseCsvLogs(lines);
  }

  // Parse line by line (Syslog / Auth log / Web log / General)
  lines.forEach((line, idx) => {
    const event = parseSingleLogLine(line, idx);
    if (event) events.push(event);
  });

  return events;
}

function parseCsvLogs(lines: string[]): SecurityEvent[] {
  const delimiter = lines[0].includes(';') ? ';' : ',';
  const headers = lines[0].split(delimiter).map(h => h.trim().toLowerCase().replace(/['"]/g, ''));
  const events: SecurityEvent[] = [];

  for (let i = 1; i < lines.length; i++) {
    const row = lines[i].split(delimiter).map(val => val.trim().replace(/['"]/g, ''));
    if (row.length < 2) continue;

    const getField = (keys: string[]): string => {
      for (const k of keys) {
        const idx = headers.indexOf(k);
        if (idx !== -1 && row[idx]) return row[idx];
      }
      return '';
    };

    const ip = getField(['ip', 'source_ip', 'sourceip', 'src_ip', 'srcip', 'client_ip']) || '185.220.101.' + (10 + (i % 200));
    const user = getField(['user', 'username', 'account', 'target_user']) || 'admin';
    const action = getField(['action', 'event', 'status', 'command', 'activity']) || 'LOGIN_ATTEMPT';
    const destIp = getField(['dest_ip', 'destination_ip', 'destip', 'dst_ip', 'server_ip']) || '10.0.1.5';
    const asset = getField(['asset', 'hostname', 'server', 'device', 'target']) || 'Auth-Server-01';
    const timestamp = getField(['time', 'timestamp', 'date', 'datetime']) || new Date(Date.now() - (lines.length - i) * 60000).toISOString();

    const isFailed = action.toLowerCase().includes('fail') || action.toLowerCase().includes('denied') || action.toLowerCase().includes('drop') || action.toLowerCase().includes('reject');
    const isCritical = action.toLowerCase().includes('shadow') || action.toLowerCase().includes('encrypt') || action.toLowerCase().includes('mimikatz') || action.toLowerCase().includes('c2') || action.toLowerCase().includes('beacon');

    events.push({
      id: `csv-evt-${Date.now()}-${i}`,
      timestamp,
      sourceIp: ip,
      destIp,
      user,
      action: action.toUpperCase(),
      eventCategory: inferCategory(action),
      sourceCountry: inferCountry(ip),
      protocol: 'TCP',
      port: 443,
      rawMessage: lines[i],
      severity: isCritical ? 'critical' : isFailed ? 'high' : 'low',
      assetName: asset,
      isAnomaly: isFailed || isCritical,
    });
  }

  return events;
}

function normalizeJsonEvent(item: Record<string, unknown>, idx: number): SecurityEvent {
  const ip = (item.source_ip || item.sourceIp || item.ip || item.src_ip || '192.168.1.100') as string;
  const user = (item.user || item.username || item.account || 'system') as string;
  const action = (item.action || item.event || item.status || 'EVENT_LOG') as string;
  const destIp = (item.dest_ip || item.destIp || item.dst_ip || '10.0.1.5') as string;
  const asset = (item.assetName || item.asset || item.hostname || 'Enterprise-Node') as string;
  const time = (item.timestamp || item.time || new Date().toISOString()) as string;
  const rawMsg = (item.rawMessage || item.message || JSON.stringify(item)) as string;
  const category = (item.eventCategory || inferCategory(action)) as SecurityEvent['eventCategory'];
  
  const isFailed = action.toLowerCase().includes('fail') || action.toLowerCase().includes('drop');
  const isCritical = action.toLowerCase().includes('ransom') || action.toLowerCase().includes('c2') || action.toLowerCase().includes('shadow') || action.toLowerCase().includes('exploit');
  const severity: Severity = isCritical ? 'critical' : isFailed ? 'high' : 'low';

  return {
    id: `json-evt-${Date.now()}-${idx}`,
    timestamp: time,
    sourceIp: ip,
    destIp,
    user,
    action: action.toUpperCase(),
    eventCategory: category,
    sourceCountry: inferCountry(ip),
    protocol: (item.protocol || 'TCP') as string,
    port: Number(item.port) || 443,
    rawMessage: rawMsg,
    severity: (item.severity as Severity) || severity,
    assetName: asset,
    isAnomaly: Boolean(item.isAnomaly ?? (isFailed || isCritical)),
  };
}

function parseSingleLogLine(line: string, idx: number): SecurityEvent {
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const ips = line.match(ipRegex) || [];
  const sourceIp = ips[0] || '198.51.100.' + (idx % 250);
  const destIp = ips[1] || '10.0.1.5';

  let user = 'anonymous';
  const userMatch = line.match(/(?:user|for|account|login)\s+([a-zA-Z0-9_\-\.@]+)/i);
  if (userMatch && userMatch[1]) {
    user = userMatch[1];
  }

  let action = 'GENERAL_LOG';
  if (/failed|failure|invalid|refused/i.test(line)) action = 'LOGIN_FAILED';
  else if (/accepted|succeeded|successful/i.test(line)) action = 'LOGIN_SUCCESS';
  else if (/vssadmin|shadow|encrypt|ransom/i.test(line)) action = 'RANSOMWARE_INDICATOR';
  else if (/beacon|c2|trojan|cobalt/i.test(line)) action = 'C2_COMMUNICATION';
  else if (/s3|exfiltration|bulk|dump/i.test(line)) action = 'DATA_EXFILTRATION';
  else if (/drop|blocked|denied/i.test(line)) action = 'FIREWALL_DROP';

  const isFailed = /fail|invalid|refused|drop|blocked|denied/i.test(line);
  const isCritical = /ransom|shadow|encrypt|beacon|c2|mimikatz|unauthorized/i.test(line);
  const severity: Severity = isCritical ? 'critical' : isFailed ? 'high' : 'low';

  return {
    id: `log-evt-${Date.now()}-${idx}`,
    timestamp: new Date(Date.now() - (idx * 5000)).toISOString(),
    sourceIp,
    destIp,
    user,
    action,
    eventCategory: inferCategory(action),
    sourceCountry: inferCountry(sourceIp),
    protocol: line.includes('ssh') ? 'SSH' : line.includes('http') ? 'HTTP' : 'TCP',
    port: line.includes('ssh') ? 22 : line.includes('443') ? 443 : 80,
    rawMessage: line,
    severity,
    assetName: line.includes('DC') ? 'Active-Directory-DC01' : line.includes('Fin') ? 'Finance-DB-Server' : 'Edge-Ingress-Proxy-01',
    isAnomaly: isFailed || isCritical,
  };
}

function inferCategory(action: string): SecurityEvent['eventCategory'] {
  const a = action.toLowerCase();
  if (a.includes('login') || a.includes('auth') || a.includes('kerberos') || a.includes('password')) return 'AUTH';
  if (a.includes('firewall') || a.includes('drop') || a.includes('syn') || a.includes('port')) return 'FIREWALL';
  if (a.includes('process') || a.includes('vssadmin') || a.includes('powershell') || a.includes('file')) return 'ENDPOINT';
  if (a.includes('c2') || a.includes('beacon') || a.includes('dns') || a.includes('http')) return 'NETWORK';
  if (a.includes('s3') || a.includes('iam') || a.includes('cloudtrail') || a.includes('aws')) return 'CLOUD';
  if (a.includes('mail') || a.includes('phish') || a.includes('smtp')) return 'EMAIL';
  return 'SYSTEM';
}

function inferCountry(ip: string): string {
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) return 'Internal LAN';
  if (ip.startsWith('185.220.') || ip.startsWith('185.')) return 'Tor Exit Node / Seychelles';
  if (ip.startsWith('194.26.') || ip.startsWith('91.')) return 'Eastern Europe (ASN 44050)';
  if (ip.startsWith('103.145.')) return 'Vietnam (ASN 135905)';
  if (ip.startsWith('195.123.')) return 'Latvia (ASN 51167)';
  if (ip.startsWith('45.142.') || ip.startsWith('45.')) return 'Bulgaria (ASN 206264)';
  return 'External WAN';
}

// Rule-Based Threat Analyzer: checks event batches for high-confidence attack signatures
export function detectThreatsFromEvents(events: SecurityEvent[], existingThreats: ThreatAlert[] = []): ThreatAlert[] {
  const newThreats: ThreatAlert[] = [];
  const eventIdsUsed = new Set<string>();

  // 1. Check for High-Frequency Failed Logins (Brute Force / Password Spraying)
  const failedAuthsByIp: Record<string, SecurityEvent[]> = {};
  events.forEach(e => {
    if (e.action.includes('FAIL') || e.action.includes('AUTH') || e.rawMessage.toLowerCase().includes('failed password')) {
      if (!failedAuthsByIp[e.sourceIp]) failedAuthsByIp[e.sourceIp] = [];
      failedAuthsByIp[e.sourceIp].push(e);
    }
  });

  Object.entries(failedAuthsByIp).forEach(([ip, group]) => {
    if (group.length >= 3) {
      const code = `TH-${1050 + Math.floor(Math.random() * 800)}`;
      const targetUsers = Array.from(new Set(group.map(g => g.user)));
      const assets = Array.from(new Set(group.map(g => g.assetName)));
      group.forEach(g => eventIdsUsed.add(g.id));

      newThreats.push({
        id: `threat-auto-${Date.now()}-${Math.random().toString(36).substring(7)}`,
        threatCode: code,
        title: `Automated Brute Force / Password Spray from ${ip}`,
        threatType: 'Brute Force Attack',
        severity: group.length > 8 ? 'critical' : 'high',
        confidence: Math.min(98, 85 + group.length * 2),
        status: 'open',
        firstDetected: group[0].timestamp,
        lastActivity: group[group.length - 1].timestamp,
        sourceIps: [ip],
        targetAccounts: targetUsers,
        riskScore: Math.min(96, 75 + group.length * 3),
        aiSummary: `Rule Engine triggered: ${group.length} authentication failure events detected in rapid succession against accounts [${targetUsers.join(', ')}] on target ${assets.join(', ')}.`,
        detailedReasoning: `Heuristic Rule #BRUTE-01 matched: Source IP ${ip} exceeded standard threshold of 3 failed auths within detection window. High probability of credential stuffing or automated dictionary spray.`,
        attackPattern: [
          {
            step: 1,
            phase: 'Initial Access',
            technique: 'Password Spraying (T1110.003)',
            description: `${group.length} failed attempts against authentication service.`,
            timestamp: group[0].timestamp,
            indicator: `${ip}`,
            status: 'detected',
          },
        ],
        mitreAttack: [
          {
            id: 'T1110.003',
            name: 'Password Spraying',
            tactic: 'Credential Access',
            url: 'https://attack.mitre.org/techniques/T1110/003/',
            description: 'Adversaries may use a single or small list of commonly used passwords against many different accounts.',
          },
        ],
        iocs: [
          {
            id: `ioc-${Date.now()}-1`,
            type: 'ip',
            value: ip,
            risk: group.length > 8 ? 'critical' : 'high',
            associatedThreats: [code],
            occurrences: group.length,
            reputation: `AbuseIPDB Suspicious (${inferCountry(ip)})`,
            firstSeen: group[0].timestamp,
            lastSeen: group[group.length - 1].timestamp,
            notes: 'High-volume failed authentication origin.',
          },
        ],
        affectedAssets: assets.map((a, i) => ({
          id: `asset-auto-${i}`,
          name: a,
          ip: group[i]?.destIp || '10.0.1.5',
          role: 'Authentication / Identity Node',
          os: 'Linux / Windows Server',
          criticality: 'Tier-1 Critical',
          status: 'targeted',
          vulnerabilities: ['Rapid Auth Failure Flood'],
        })),
        recommendedActions: [
          {
            id: `act-auto-${Date.now()}-1`,
            priority: 'P1 (Immediate)',
            title: `Block Attacking IP ${ip}`,
            action: `Inject perimeter firewall rule dropping all incoming packets from ${ip}.`,
            rationale: 'Stop dictionary guessing in real-time.',
            type: 'block_ip',
            target: ip,
            executed: false,
            commandSnippet: `iptables -A INPUT -s ${ip} -j DROP`,
          },
          {
            id: `act-auto-${Date.now()}-2`,
            priority: 'P2 (Containment)',
            title: `Force Password Reset on Targeted Accounts`,
            action: `Lock out and require FIDO2 MFA challenge for users [${targetUsers.join(', ')}].`,
            rationale: 'Ensure credentials cannot be brute-forced into active sessions.',
            type: 'revoke_token',
            target: targetUsers[0] || 'admin',
            executed: false,
          },
        ],
        correlatedEventIds: group.map(g => g.id),
        remediationHistory: [],
      });
    }
  });

  // 2. Check for Ransomware / Shadow Deletion Indicators
  const ransomwareEvents = events.filter(e => 
    e.action.includes('RANSOM') || 
    e.action.includes('VSSADMIN') || 
    e.rawMessage.toLowerCase().includes('shadow') || 
    e.rawMessage.toLowerCase().includes('delete shadows') ||
    e.rawMessage.toLowerCase().includes('.lockbit') ||
    e.rawMessage.toLowerCase().includes('.enc')
  );

  if (ransomwareEvents.length > 0) {
    const code = `TH-${1080 + Math.floor(Math.random() * 50)}`;
    const asset = ransomwareEvents[0].assetName || 'Finance-DB-Server';
    newThreats.push({
      id: `threat-auto-${Date.now()}-ransom`,
      threatCode: code,
      title: `Ransomware Canary / Volume Shadow Deletion on ${asset}`,
      threatType: 'Ransomware Outbreak',
      severity: 'critical',
      confidence: 99,
      status: 'open',
      firstDetected: ransomwareEvents[0].timestamp,
      lastActivity: ransomwareEvents[ransomwareEvents.length - 1].timestamp,
      sourceIps: [ransomwareEvents[0].sourceIp],
      targetAccounts: [ransomwareEvents[0].user],
      riskScore: 98,
      aiSummary: `Critical EDR Alert: Host ${asset} invoked backup inhibitor commands (vssadmin delete shadows / bcdedit) and abnormal file extension modifications.`,
      detailedReasoning: `Signature Rule #RANSOM-09 matched. Immediate host containment required to prevent encryptor lateral spread across SMB cluster.`,
      attackPattern: [
        {
          step: 1,
          phase: 'Inhibit System Recovery',
          technique: 'Inhibit System Recovery: Delete Volume Shadow Copies (T1490)',
          description: 'Shadow copy wipe detected.',
          timestamp: ransomwareEvents[0].timestamp,
          indicator: 'vssadmin.exe execution',
          status: 'detected',
        },
      ],
      mitreAttack: [
        {
          id: 'T1490',
          name: 'Inhibit System Recovery',
          tactic: 'Impact',
          url: 'https://attack.mitre.org/techniques/T1490/',
          description: 'Adversaries may delete or disable system recovery mechanisms.',
        },
      ],
      iocs: [
        {
          id: `ioc-${Date.now()}-ransom`,
          type: 'ip',
          value: ransomwareEvents[0].sourceIp,
          risk: 'critical',
          associatedThreats: [code],
          occurrences: ransomwareEvents.length,
          reputation: 'Ransomware C2 Staging IP',
          firstSeen: ransomwareEvents[0].timestamp,
          lastSeen: ransomwareEvents[0].timestamp,
          notes: 'Source associated with payload execution.',
        },
      ],
      affectedAssets: [
        {
          id: `asset-auto-ransom`,
          name: asset,
          ip: ransomwareEvents[0].destIp,
          role: 'Core Cluster Asset',
          os: 'Windows Server 2022',
          criticality: 'Tier-1 Critical',
          status: 'at_risk',
          vulnerabilities: ['Ransomware Stager Executed'],
        },
      ],
      recommendedActions: [
        {
          id: `act-auto-ransom-1`,
          priority: 'P1 (Immediate)',
          title: `Isolate ${asset} Network Adapter`,
          action: 'Immediately isolate host from internal network via EDR agent.',
          rationale: 'Stop lateral encryption propagation across SMB/NFS mounts.',
          type: 'isolate_host',
          target: asset,
          executed: false,
        },
      ],
      correlatedEventIds: ransomwareEvents.map(r => r.id),
      remediationHistory: [],
    });
  }

  return newThreats;
}

// Generate realistic live streaming events for active demo mode
export function generateSimulatedLiveEvent(): SecurityEvent {
  const random = Math.random();
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  if (random < 0.25) {
    // Brute force event
    const attackers = ['185.220.101.5', '194.26.29.112', '45.154.255.89', '91.240.118.42'];
    const users = ['admin', 'root', 'svc_backup', 'jdoe', 'administrator', 'cfo_assistant'];
    const ip = attackers[Math.floor(Math.random() * attackers.length)];
    const user = users[Math.floor(Math.random() * users.length)];
    return {
      id: `live-evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp,
      sourceIp: ip,
      destIp: '10.0.1.5',
      user,
      action: 'LOGIN_FAILED',
      eventCategory: 'AUTH',
      sourceCountry: inferCountry(ip),
      protocol: 'SSH',
      port: 22,
      rawMessage: `sshd[${Math.floor(40000 + Math.random() * 20000)}]: Failed password for ${user} from ${ip} port ${Math.floor(40000 + Math.random() * 20000)} ssh2`,
      severity: 'high',
      assetName: 'Active-Directory-DC01',
      isAnomaly: true,
      threatCode: 'TH-1042',
    };
  } else if (random < 0.45) {
    // C2 Beaconing event
    return {
      id: `live-evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp,
      sourceIp: '195.123.246.88',
      destIp: '10.0.2.80',
      user: 'www-data',
      action: 'C2_HTTPS_BEACON',
      eventCategory: 'NETWORK',
      sourceCountry: 'Latvia (ASN 51167)',
      protocol: 'HTTPS',
      port: 443,
      rawMessage: `Suricata [1:2024119:1] CobaltStrike Malleable C2 Beacon Interval 29.8s from 10.0.2.80 to 195.123.246.88:443`,
      severity: 'critical',
      assetName: 'HR-Portal-Server',
      isAnomaly: true,
      threatCode: 'TH-1045',
    };
  } else if (random < 0.65) {
    // Normal Web / Database event
    return {
      id: `live-evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp,
      sourceIp: `192.168.1.${Math.floor(10 + Math.random() * 200)}`,
      destIp: '10.0.3.44',
      user: 'app_service',
      action: 'QUERY_EXECUTE_OK',
      eventCategory: 'SYSTEM',
      sourceCountry: 'Internal LAN',
      protocol: 'PostgreSQL',
      port: 5432,
      rawMessage: `PostgreSQL Audit: user=app_service db=production query="SELECT * FROM transactions WHERE status='settled' LIMIT 100" duration=4.2ms`,
      severity: 'low',
      assetName: 'Finance-DB-Server',
      isAnomaly: false,
    };
  } else if (random < 0.85) {
    // Cloud API query
    return {
      id: `live-evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp,
      sourceIp: '103.145.74.22',
      destIp: '35.198.22.90',
      user: 'aws_iam_terraform_deployer',
      action: 'S3_GET_OBJECT',
      eventCategory: 'CLOUD',
      sourceCountry: 'Vietnam',
      protocol: 'HTTPS',
      port: 443,
      rawMessage: `CloudTrail: s3.amazonaws.com GetObject bucket=corp-analytics-prod-backup object_key=exports/2026/q2_dump_${Math.floor(Math.random() * 100)}.tar.gz`,
      severity: 'high',
      assetName: 'Cloud-API-Gateway',
      isAnomaly: true,
      threatCode: 'TH-1044',
    };
  } else {
    // Normal Firewall heartbeat
    return {
      id: `live-evt-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp,
      sourceIp: '10.0.0.1',
      destIp: '10.0.1.254',
      user: 'palo_alto_core',
      action: 'INTERFACE_HEALTHCHECK',
      eventCategory: 'FIREWALL',
      sourceCountry: 'Internal LAN',
      protocol: 'ICMP',
      port: 0,
      rawMessage: 'PAN-OS System Log: Interface eth0/1 link UP 10000Mbps Full-Duplex BGP neighbor 10.0.1.254 ESTABLISHED',
      severity: 'low',
      assetName: 'Edge-Ingress-Proxy-01',
      isAnomaly: false,
    };
  }
}
