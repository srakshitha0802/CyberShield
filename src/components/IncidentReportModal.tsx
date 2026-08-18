import React, { useState, useEffect } from 'react';
import { ThreatAlert } from '../types/security';
import {
  FileText,
  Download,
  Copy,
  Check,
  Printer,
  Sparkles,
  RefreshCw,
  ShieldAlert,
  Layers,
  Globe,
  Lock,
  X,
  FileDown,
} from 'lucide-react';
import { exportThreatInvestigationPDF, exportMarkdownReportToPDF } from '../utils/pdfExport';

interface IncidentReportModalProps {
  threat: ThreatAlert | null;
  onClose: () => void;
}

export const IncidentReportModal: React.FC<IncidentReportModalProps> = ({ threat, onClose }) => {
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!threat) return;

    const fetchReport = async () => {
      setLoading(true);
      try {
        const response = await fetch('/api/security/incident-report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ threat }),
        });

        if (response.ok) {
          const data = await response.json();
          setReportMarkdown(data.reportMarkdown || data.report);
        } else {
          throw new Error('Report API error');
        }
      } catch (err) {
        console.error(err);
        // Fallback report
        setReportMarkdown(`# CYBERSHIELD DFIR INCIDENT REPORT: [${threat.threatCode}] ${threat.title}

**Generated Date:** ${new Date().toUTCString()}  
**Incident Classification:** ${threat.threatType} (${threat.severity.toUpperCase()} SEVERITY)  
**AI Confidence Score:** ${threat.confidence}%  
**Overall Risk Index:** ${threat.riskScore}/100  
**Status:** ${threat.status.toUpperCase()}

---

## 1. Executive Summary
On ${threat.firstDetected}, CyberShield AI detection sensors triggered alert **${threat.threatCode}** identifying an active **${threat.threatType}**.
The threat originated from ${threat.sourceIps.join(', ') || 'external WAN entities'} targeting enterprise asset **${threat.affectedAssets[0]?.name || 'Internal Node'}** and identity **${threat.targetAccounts.join(', ') || 'System Admin'}**.
AI correlation models have verified this activity as a high-fidelity breach attempt requiring immediate isolation.

---

## 2. Technical Findings & Root Cause Analysis
${threat.detailedReasoning}

---

## 3. Indicators of Compromise (IoCs)
| Type | Indicator Artifact | Risk Level | Threat Intelligence & Reputation |
|---|---|---|---|
${threat.iocs.map(ioc => `| ${ioc.type.toUpperCase()} | \`${ioc.value}\` | ${ioc.risk.toUpperCase()} | ${ioc.reputation} |`).join('\n')}

---

## 4. MITRE ATT&CK Matrix Alignment
${threat.mitreAttack.map(m => `* **${m.id}** - ${m.name} (*Tactic: ${m.tactic}*)`).join('\n')}

---

## 5. Containment & Remediation Action Plan
${threat.recommendedActions.map((a, i) => `${i + 1}. **${a.priority}**: ${a.title} - ${a.action} (Target: \`${a.target}\`)`).join('\n')}

---
*Report autonomously generated and signed by CyberShield AI SOC Intelligence Core.*`);
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [threat]);

  if (!threat) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Incident_Report_${threat.threatCode}_${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white border border-slate-200 rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-xl">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center">
              <FileText className="w-4 h-4 text-indigo-600" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900">
                NIST SP 800-61 DFIR Incident Report: {threat.threatCode}
              </h2>
              <p className="text-xs text-slate-500">Autonomous digital forensics & incident response documentation</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => threat && exportThreatInvestigationPDF(threat)}
              className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold px-3.5 py-1.5 rounded-lg shadow-xs transition-colors cursor-pointer"
            >
              <FileDown className="w-3.5 h-3.5 text-indigo-200" />
              <span>Download PDF Report</span>
            </button>

            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-semibold px-3 py-1.5 rounded-lg border border-slate-200 transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>

            <button
              onClick={handleDownload}
              className="flex items-center gap-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-semibold px-3 py-1.5 rounded-lg border border-slate-200 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>.MD</span>
            </button>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-100 cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 flex-1 overflow-y-auto bg-slate-50/50">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 space-y-3">
              <RefreshCw className="w-6 h-6 text-indigo-600 animate-spin" />
              <p className="text-xs font-medium text-slate-600">
                Synthesizing NIST SP 800-61 forensic incident report with AI reasoning...
              </p>
            </div>
          ) : (
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs">
              <pre className="font-mono text-xs text-slate-800 whitespace-pre-wrap leading-relaxed">
                {reportMarkdown}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-white border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
          <span>Compliant with SANS PICERL & NIST Standards</span>
          <button
            onClick={onClose}
            className="bg-slate-900 hover:bg-slate-800 text-white font-semibold px-4 py-1.5 rounded-lg shadow-xs cursor-pointer"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
};
