import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ThreatAlert, SecurityEvent, IncidentCampaign } from '../types/security';

// Color Palette Constants
const COLORS = {
  primary: [15, 23, 42] as [number, number, number], // slate-900
  secondary: [79, 70, 229] as [number, number, number], // indigo-600
  accent: [225, 29, 72] as [number, number, number], // rose-600
  warning: [217, 119, 6] as [number, number, number], // amber-600
  success: [16, 185, 129] as [number, number, number], // emerald-500
  slateLight: [248, 250, 252] as [number, number, number], // slate-50
  slateBorder: [226, 232, 240] as [number, number, number], // slate-200
  textDark: [15, 23, 42] as [number, number, number],
  textMuted: [100, 116, 139] as [number, number, number], // slate-500
};

/**
 * Add standard header and footer to PDF pages
 */
function addDocumentDecorations(doc: jsPDF, title: string, classification = 'TLP:AMBER+STRICT | SOC CONFIDENTIAL') {
  const pageCount = (doc as any).internal.getNumberOfPages();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();

  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);

    // Top Classification Header Bar
    doc.setFillColor(15, 23, 42); // slate-900
    doc.rect(0, 0, pageWidth, 8, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(255, 255, 255);
    doc.text(classification, pageWidth / 2, 5.5, { align: 'center' });

    // Bottom Footer
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.5);
    doc.line(14, pageHeight - 12, pageWidth - 14, pageHeight - 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('CyberShield AI SOC • Digital Forensics & Incident Response', 14, pageHeight - 7);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 14, pageHeight - 7, { align: 'right' });
  }
}

/**
 * Export a comprehensive Incident Forensic & Investigation Dossier into a PDF
 */
export function exportThreatInvestigationPDF(threat: ThreatAlert): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let currentY = 16;

  // Title & Metadata Header
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(...COLORS.primary);
  doc.text(`NIST SP 800-61 DFIR INCIDENT REPORT`, 14, currentY);
  currentY += 6;

  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.secondary);
  doc.text(`[${threat.threatCode}] ${threat.title}`, 14, currentY);
  currentY += 6;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textMuted);
  doc.text(`Generated: ${new Date().toUTCString()}  •  Standard: NIST SP 800-61 Rev 2 / SANS PICERL`, 14, currentY);
  currentY += 6;

  // Summary Metrics Box (Banner)
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(14, currentY, pageWidth - 28, 24, 2, 2, 'FD');

  const colW = (pageWidth - 28) / 4;
  const boxY = currentY + 6;

  // Metric 1: Severity
  doc.setFontSize(7.5);
  doc.setTextColor(...COLORS.textMuted);
  doc.text('INCIDENT SEVERITY', 18, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  if (threat.severity === 'critical') doc.setTextColor(...COLORS.accent);
  else if (threat.severity === 'high') doc.setTextColor(...COLORS.warning);
  else doc.setTextColor(...COLORS.secondary);
  doc.text(threat.severity.toUpperCase(), 18, boxY + 6);

  // Metric 2: Risk Index
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...COLORS.textMuted);
  doc.text('RISK INDEX (CVSS)', 18 + colW, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.accent);
  doc.text(`${threat.riskScore} / 100`, 18 + colW, boxY + 6);

  // Metric 3: AI Confidence
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...COLORS.textMuted);
  doc.text('AI CONFIDENCE', 18 + colW * 2, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.secondary);
  doc.text(`${threat.confidence}%`, 18 + colW * 2, boxY + 6);

  // Metric 4: Containment Status
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...COLORS.textMuted);
  doc.text('CURRENT STATUS', 18 + colW * 3, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  if (threat.status === 'contained' || threat.status === 'remediated') {
    doc.setTextColor(...COLORS.success);
  } else {
    doc.setTextColor(...COLORS.accent);
  }
  doc.text(threat.status.toUpperCase(), 18 + colW * 3, boxY + 6);

  currentY += 30;

  // Section 1: Executive Summary
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...COLORS.primary);
  doc.text('1. Executive Summary & AI Triage Assessment', 14, currentY);
  currentY += 4;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textDark);
  const splitSummary = doc.splitTextToSize(
    threat.aiSummary || 'Active security breach detected through behavioral and rule-based anomaly correlation.',
    pageWidth - 28
  );
  doc.text(splitSummary, 14, currentY);
  currentY += splitSummary.length * 4.2 + 4;

  // Section 2: Detailed Root Cause Analysis & Reasoning
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...COLORS.primary);
  doc.text('2. Root Cause Analysis & Threat Intelligence Correlation', 14, currentY);
  currentY += 4;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textDark);
  const splitReasoning = doc.splitTextToSize(
    threat.detailedReasoning || 'Comprehensive threat intelligence indicates malicious reconnaissance and persistent credential abuse.',
    pageWidth - 28
  );
  doc.text(splitReasoning, 14, currentY);
  currentY += splitReasoning.length * 4.2 + 6;

  // Section 3: Kill Chain Timeline Table
  if (threat.attackPattern && threat.attackPattern.length > 0) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.primary);
    doc.text('3. Chronological Attack Pattern & Kill Chain Progression', 14, currentY);
    currentY += 2;

    const patternRows = threat.attackPattern.map(step => [
      `#${step.step}`,
      step.phase,
      step.technique,
      step.timestamp,
      step.description,
      step.status.toUpperCase(),
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Step', 'Kill Chain Phase', 'Technique', 'Timestamp', 'Event Description', 'Status']],
      body: patternRows,
      theme: 'striped',
      headStyles: {
        fillColor: COLORS.primary,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.5,
        overflow: 'linebreak',
      },
      columnStyles: {
        0: { cellWidth: 10, halign: 'center' },
        1: { cellWidth: 26, fontStyle: 'bold' },
        2: { cellWidth: 24 },
        3: { cellWidth: 22, fontStyle: 'italic' },
        4: { cellWidth: 'auto' },
        5: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Section 4: Indicators of Compromise (IoCs)
  if (threat.iocs && threat.iocs.length > 0) {
    if (currentY > 230) {
      doc.addPage();
      currentY = 16;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.primary);
    doc.text('4. Indicators of Compromise (IoCs)', 14, currentY);
    currentY += 2;

    const iocRows = threat.iocs.map(ioc => [
      ioc.type.toUpperCase(),
      ioc.value,
      ioc.risk.toUpperCase(),
      ioc.reputation,
      ioc.notes || 'Associated with current campaign',
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Type', 'Indicator Value', 'Risk', 'Threat Intel Reputation', 'Context / Notes']],
      body: iocRows,
      theme: 'striped',
      headStyles: {
        fillColor: COLORS.primary,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.5,
      },
      columnStyles: {
        0: { cellWidth: 18, fontStyle: 'bold' },
        1: { cellWidth: 46, fontStyle: 'bold' },
        2: { cellWidth: 16, halign: 'center' },
        3: { cellWidth: 42 },
        4: { cellWidth: 'auto' },
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Section 5: MITRE ATT&CK Mapping
  if (threat.mitreAttack && threat.mitreAttack.length > 0) {
    if (currentY > 230) {
      doc.addPage();
      currentY = 16;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.primary);
    doc.text('5. MITRE ATT&CK Matrix Alignment (Enterprise v14)', 14, currentY);
    currentY += 2;

    const mitreRows = threat.mitreAttack.map(m => [
      m.id,
      m.name,
      m.tactic,
      m.description,
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Technique ID', 'Technique Name', 'Tactic', 'Adversary Behavior Description']],
      body: mitreRows,
      theme: 'striped',
      headStyles: {
        fillColor: COLORS.primary,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.5,
      },
      columnStyles: {
        0: { cellWidth: 24, fontStyle: 'bold' },
        1: { cellWidth: 38, fontStyle: 'bold' },
        2: { cellWidth: 30 },
        3: { cellWidth: 'auto' },
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Section 6: Affected Assets & Blast Radius
  if (threat.affectedAssets && threat.affectedAssets.length > 0) {
    if (currentY > 230) {
      doc.addPage();
      currentY = 16;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.primary);
    doc.text('6. Targeted Assets & Blast Radius Analysis', 14, currentY);
    currentY += 2;

    const assetRows = threat.affectedAssets.map(a => [
      a.name,
      a.ip,
      a.os,
      a.criticality,
      a.status.toUpperCase(),
      (a.vulnerabilities || []).join(', ') || 'None reported',
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Asset Name', 'IP Address', 'OS Platform', 'Criticality', 'Posture Status', 'Known Weaknesses']],
      body: assetRows,
      theme: 'striped',
      headStyles: {
        fillColor: COLORS.primary,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.5,
      },
      columnStyles: {
        0: { cellWidth: 36, fontStyle: 'bold' },
        1: { cellWidth: 26 },
        2: { cellWidth: 24 },
        3: { cellWidth: 24 },
        4: { cellWidth: 22, fontStyle: 'bold' },
        5: { cellWidth: 'auto' },
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Section 7: Playbook Actions & Remediation Plan
  if (threat.recommendedActions && threat.recommendedActions.length > 0) {
    if (currentY > 230) {
      doc.addPage();
      currentY = 16;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.primary);
    doc.text('7. SOAR Containment & Remediation Playbook Actions', 14, currentY);
    currentY += 2;

    const playbookRows = threat.recommendedActions.map(action => [
      action.priority,
      action.title,
      action.action,
      action.commandSnippet || action.target || 'N/A',
      action.executed ? 'EXECUTED' : 'PENDING',
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Priority', 'Action Title', 'Remediation Step', 'Executable Script / Command', 'Execution Status']],
      body: playbookRows,
      theme: 'striped',
      headStyles: {
        fillColor: COLORS.primary,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.5,
      },
      columnStyles: {
        0: { cellWidth: 26, fontStyle: 'bold' },
        1: { cellWidth: 34, fontStyle: 'bold' },
        2: { cellWidth: 44 },
        3: { cellWidth: 'auto', fontStyle: 'italic' },
        4: { cellWidth: 20, halign: 'center', fontStyle: 'bold' },
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Final document decorations (Header, Footers, Page numbers)
  addDocumentDecorations(doc, `Incident Report: ${threat.threatCode}`);

  // Save the PDF
  const filename = `DFIR_Report_${threat.threatCode}_${Date.now()}.pdf`;
  doc.save(filename);
}

/**
 * Export the overall Dashboard Security Posture & Findings into a PDF
 */
export function exportDashboardExecutiveReportPDF(data: {
  threats: ThreatAlert[];
  events: SecurityEvent[];
  campaigns: IncidentCampaign[];
}): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let currentY = 16;

  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(...COLORS.primary);
  doc.text('EXECUTIVE CYBERSECURITY POSTURE REPORT', 14, currentY);
  currentY += 6;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.secondary);
  doc.text('SOC Threat Intelligence, Active Incidents & Risk Assessment', 14, currentY);
  currentY += 5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textMuted);
  doc.text(`Assessment Date: ${new Date().toUTCString()}  •  Scope: Global Enterprise Telemetry`, 14, currentY);
  currentY += 6;

  // Metrics summary
  const criticalThreats = data.threats.filter(t => t.severity === 'critical');
  const highThreats = data.threats.filter(t => t.severity === 'high');
  const uncontained = data.threats.filter(t => t.status !== 'contained' && t.status !== 'remediated');
  const overallRisk = Math.max(...data.threats.map(t => t.riskScore), 65);

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(14, currentY, pageWidth - 28, 24, 2, 2, 'FD');

  const colW = (pageWidth - 28) / 4;
  const boxY = currentY + 6;

  // Metric 1: Overall Risk
  doc.setFontSize(7.5);
  doc.setTextColor(...COLORS.textMuted);
  doc.text('OVERALL RISK INDEX', 18, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.accent);
  doc.text(`${overallRisk} / 100`, 18, boxY + 6);

  // Metric 2: Active Threats
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...COLORS.textMuted);
  doc.text('ACTIVE THREATS', 18 + colW, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.primary);
  doc.text(`${data.threats.length} (${uncontained.length} uncontained)`, 18 + colW, boxY + 6);

  // Metric 3: Critical Incidents
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...COLORS.textMuted);
  doc.text('CRITICAL / HIGH', 18 + colW * 2, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.accent);
  doc.text(`${criticalThreats.length} Crit / ${highThreats.length} High`, 18 + colW * 2, boxY + 6);

  // Metric 4: Ingested Events
  doc.setFontSize(7.5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...COLORS.textMuted);
  doc.text('INGESTED TELEMETRY', 18 + colW * 3, boxY);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...COLORS.success);
  doc.text(`${data.events.length} Events`, 18 + colW * 3, boxY + 6);

  currentY += 30;

  // Executive Overview Summary
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...COLORS.primary);
  doc.text('1. Executive Threat Summary & Posture Evaluation', 14, currentY);
  currentY += 4;

  const summaryText =
    `During the current monitoring interval, the CyberShield AI SOC platform identified ${data.threats.length} distinct security threats, of which ${uncontained.length} remain in active investigation and triage. High-fidelity correlation of ingress authentication feeds, firewall logs, and endpoint heuristics revealed active adversary activity with a peak organizational risk index of ${overallRisk}/100. Immediate containment playbooks have been staged for executive oversight and automated SOC dispatch.`;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textDark);
  const splitSummary = doc.splitTextToSize(summaryText, pageWidth - 28);
  doc.text(splitSummary, 14, currentY);
  currentY += splitSummary.length * 4.2 + 6;

  // Active Incidents Table
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...COLORS.primary);
  doc.text('2. Prioritized Incident Queue & Triage Matrix', 14, currentY);
  currentY += 2;

  const incidentRows = data.threats.map(t => [
    t.threatCode,
    t.title,
    t.threatType,
    t.severity.toUpperCase(),
    `${t.riskScore}/100`,
    `${t.confidence}%`,
    t.status.toUpperCase(),
  ]);

  autoTable(doc, {
    startY: currentY,
    head: [['Code', 'Incident Title', 'Threat Category', 'Severity', 'Risk', 'AI Conf.', 'Status']],
    body: incidentRows,
    theme: 'striped',
    headStyles: {
      fillColor: COLORS.primary,
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold',
    },
    styles: {
      fontSize: 7.5,
      cellPadding: 2.5,
    },
    columnStyles: {
      0: { cellWidth: 18, fontStyle: 'bold' },
      1: { cellWidth: 50, fontStyle: 'bold' },
      2: { cellWidth: 34 },
      3: { cellWidth: 18, halign: 'center' },
      4: { cellWidth: 18, halign: 'center' },
      5: { cellWidth: 18, halign: 'center' },
      6: { cellWidth: 26, halign: 'center', fontStyle: 'bold' },
    },
    margin: { left: 14, right: 14 },
  });

  currentY = (doc as any).lastAutoTable.finalY + 8;

  // Adversary Campaigns & APT Tracking
  if (data.campaigns && data.campaigns.length > 0) {
    if (currentY > 230) {
      doc.addPage();
      currentY = 16;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.primary);
    doc.text('3. Correlated Adversary Campaigns & Threat Actors', 14, currentY);
    currentY += 2;

    const campaignRows = data.campaigns.map(c => [
      c.title,
      c.threatActor,
      c.severity.toUpperCase(),
      `${c.killChainProgress}%`,
      `${c.targetedAssetsCount} Hosts`,
      c.summary,
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Campaign Title', 'Threat Actor', 'Severity', 'Kill Chain %', 'Blast Radius', 'Summary Description']],
      body: campaignRows,
      theme: 'striped',
      headStyles: {
        fillColor: COLORS.primary,
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2.5,
      },
      columnStyles: {
        0: { cellWidth: 38, fontStyle: 'bold' },
        1: { cellWidth: 26, fontStyle: 'bold' },
        2: { cellWidth: 18, halign: 'center' },
        3: { cellWidth: 22, halign: 'center' },
        4: { cellWidth: 22, halign: 'center' },
        5: { cellWidth: 'auto' },
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Strategic Security Recommendations
  if (currentY > 230) {
    doc.addPage();
    currentY = 16;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(...COLORS.primary);
  doc.text('4. Recommended Strategic Security Enhancements', 14, currentY);
  currentY += 4;

  const recommendations = [
    '• Immediate Credential Rotation: Force immediate password reset and session revocation on targeted domain administrator identities.',
    '• Lateral Movement Barrier: Enforce micro-segmentation and strict Windows RPC/SMB firewall inspection across Tier-1 Domain Controllers and database servers.',
    '• Automated SOAR Kill-Switch: Authorize automated IP blocklist propagation for malicious external C2 infrastructure across perimeter edge gateways.',
    '• Vulnerability Patching: Prioritize high-priority patches for CISA KEV-cataloged vulnerabilities on perimeter VPN and email relays.',
  ];

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textDark);
  recommendations.forEach(rec => {
    const splitRec = doc.splitTextToSize(rec, pageWidth - 28);
    doc.text(splitRec, 14, currentY);
    currentY += splitRec.length * 4.2 + 2;
  });

  addDocumentDecorations(doc, 'Executive Cybersecurity Posture Report');

  const filename = `SOC_Executive_Report_${Date.now()}.pdf`;
  doc.save(filename);
}

/**
 * Convenient alias wrapper for exportDashboardExecutiveReportPDF
 */
export function exportExecutiveDashboardPDF(
  threats: ThreatAlert[],
  campaigns: IncidentCampaign[] = [],
  events: SecurityEvent[] = []
): void {
  exportDashboardExecutiveReportPDF({ threats, campaigns, events });
}

/**
 * Export arbitrary markdown or plain text report to a cleanly styled PDF
 */
export function exportMarkdownReportToPDF(title: string, markdownText: string): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let currentY = 18;

  // Document Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(...COLORS.primary);
  doc.text(title.toUpperCase(), 14, currentY);
  currentY += 6;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...COLORS.textMuted);
  doc.text(`Exported: ${new Date().toUTCString()} • CyberShield AI Intelligence Document`, 14, currentY);
  currentY += 8;

  // Split lines and parse basic Markdown
  const lines = markdownText.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (!line) {
      currentY += 3;
      continue;
    }

    if (currentY > 270) {
      doc.addPage();
      currentY = 18;
    }

    if (line.startsWith('# ')) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(13);
      doc.setTextColor(...COLORS.primary);
      doc.text(line.replace('# ', ''), 14, currentY);
      currentY += 6;
    } else if (line.startsWith('## ')) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(11);
      doc.setTextColor(...COLORS.secondary);
      doc.text(line.replace('## ', ''), 14, currentY);
      currentY += 5;
    } else if (line.startsWith('### ')) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9.5);
      doc.setTextColor(...COLORS.primary);
      doc.text(line.replace('### ', ''), 14, currentY);
      currentY += 4.5;
    } else if (line.startsWith('---')) {
      doc.setDrawColor(226, 232, 240);
      doc.line(14, currentY, pageWidth - 14, currentY);
      currentY += 4;
    } else {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(...COLORS.textDark);
      const cleanLine = line.replace(/\*\*/g, '').replace(/`/g, '');
      const split = doc.splitTextToSize(cleanLine, pageWidth - 28);
      doc.text(split, 14, currentY);
      currentY += split.length * 4.2 + 1;
    }
  }

  addDocumentDecorations(doc, title);
  doc.save(`${title.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.pdf`);
}
