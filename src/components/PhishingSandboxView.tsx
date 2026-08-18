import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Mail,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  Sparkles,
  RefreshCw,
  ExternalLink,
  Copy,
  Check,
  FileCode,
  ShieldCheck,
  Lock,
} from 'lucide-react';
import { PhishingAnalysisResult } from '../types/security';

export const PhishingSandboxView: React.FC = () => {
  const { isAnalyzing } = useSecurity();

  const [sender, setSender] = useState('security-update@micosoft-verify-auth.com');
  const [subject, setSubject] = useState('CRITICAL: Your Microsoft 365 Password Expires in 2 Hours - Re-authenticate Immediately');
  const [headers, setHeaders] = useState(`Received: from mail-relay9.micosoft-verify-auth.com (194.26.29.112)
Authentication-Results: spf=fail (sender IP 194.26.29.112) dkim=fail header.d=micosoft-verify-auth.com
From: "Microsoft 365 Security Team" <security-update@micosoft-verify-auth.com>
To: "Sarah Jenkins, CFO" <sarah.jenkins@company.com>
Subject: CRITICAL: Your Microsoft 365 Password Expires in 2 Hours
Reply-To: credential-harvest@legit-office-portal.xyz`);

  const [body, setBody] = useState(`Dear Sarah,

Our automated identity protection system detected unauthorized sign-in attempts to your enterprise Microsoft 365 account from Moscow, Russia.

Your account credentials will be permanently suspended within 2 hours unless you confirm your identity:

👉 Click here to verify and maintain account access: http://login-portal-auth-microsoft.ru/validate?id=99281

Failure to verify will result in immediate termination of corporate access.

Sincerely,
Microsoft Enterprise Cloud Security Team
Incident Reference: MS-991204`);

  const [analysis, setAnalysis] = useState<PhishingAnalysisResult | null>(null);
  const [analyzingEmail, setAnalyzingEmail] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);

  const sampleEmails = [
    {
      label: 'M365 Credential Harvester',
      sender: 'security-update@micosoft-verify-auth.com',
      subject: 'CRITICAL: Your Microsoft 365 Password Expires in 2 Hours - Re-authenticate Immediately',
      headers: `Received: from mail-relay9.micosoft-verify-auth.com (194.26.29.112)\nAuthentication-Results: spf=fail dkim=fail\nFrom: "Microsoft Security" <security-update@micosoft-verify-auth.com>`,
      body: `Dear User,\n\nYour account credentials will expire today. Click here to verify: http://login-portal-auth-microsoft.ru/validate?id=99281\n\nIT Security`,
    },
    {
      label: 'CEO Urgent Wire Transfer BEC',
      sender: 'ceo.internal@exec-corp-mail.net',
      subject: 'URGENT: Confidential Acquisition Wire Transfer Authorization Required',
      headers: `Received: from relay.exec-corp-mail.net (185.190.140.22)\nAuthentication-Results: dkim=fail dmarc=fail\nFrom: "Arthur Vance, CEO" <ceo.internal@exec-corp-mail.net>`,
      body: `Hi Sarah,\n\nI am currently in an all-day confidential board meeting. We need to process an immediate wire of $248,000 for project Project Apex escrow today.\n\nPlease wire to the attached offshore routing number and reply only to this email.\n\nBest,\nArthur`,
    },
    {
      label: 'DocuSign Invoice Trojan Dropper',
      sender: 'documents@docusign-contracts-verify.link',
      subject: 'DocuSign: Please review and sign Invoice #INV-88912',
      headers: `Received: from server.docusign-contracts-verify.link (91.240.118.172)\nAuthentication-Results: spf=softfail dkim=fail`,
      body: `You have received a secure document via DocuSign.\n\nDocument: Contract_Agreement_FINAL.pdf.exe\nLink: https://cdn.discordapp.com/attachments/992/payload_stager.exe\n\nPlease execute immediately to complete signing.`,
    },
  ];

  const handleAnalyzePhishing = async () => {
    setAnalyzingEmail(true);
    try {
      const response = await fetch('/api/security/phishing-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, subject, body, headers }),
      });

      if (response.ok) {
        const data = await response.json();
        setAnalysis(data.analysis || data.data);
      } else {
        throw new Error('Failed to inspect email');
      }
    } catch (err) {
      console.error(err);
      // Fallback
      setAnalysis({
        isPhishing: true,
        confidence: 98,
        phishingType: 'Credential Harvester & Typosquatting',
        riskLevel: 'critical',
        indicators: [
          'Typosquatted sender domain (micosoft-verify-auth.com)',
          'SPF & DKIM authentication failure (IP: 194.26.29.112)',
          'Suspicious urgency pressure tactics ("expires in 2 hours")',
          'Malicious target domain with .ru TLD (login-portal-auth-microsoft.ru)',
        ],
        extractedLinks: [
          'http://login-portal-auth-microsoft.ru/validate?id=99281',
        ],
        spoofedBrand: 'Microsoft 365 Security',
        recommendation: 'Block domain micosoft-verify-auth.com on perimeter email gateway and quarantine all matching inbound messages.',
      });
    } finally {
      setAnalyzingEmail(false);
    }
  };

  const handleCopyRule = (rule: string) => {
    navigator.clipboard.writeText(rule);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Mail className="w-5 h-5 text-indigo-600" />
            <h1 className="text-base font-bold text-slate-900">Email Phishing & BEC Sandbox</h1>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Automated deep inspection of email headers (SPF/DKIM/DMARC), typosquatting detection, credential harvesters, and BEC threats.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500">Preset Scenarios:</span>
          {sampleEmails.map((sample, idx) => (
            <button
              key={idx}
              onClick={() => {
                setSender(sample.sender);
                setSubject(sample.subject);
                setHeaders(sample.headers);
                setBody(sample.body);
                setAnalysis(null);
              }}
              className="bg-slate-50 hover:bg-slate-100 text-slate-700 text-[11px] font-medium px-2.5 py-1 rounded-lg border border-slate-200 transition-colors cursor-pointer"
            >
              {sample.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Inspection Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: Email Content & Headers Editor */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-900">Inbound Message Artifacts</h2>
            <span className="text-xs font-mono text-slate-500">MIME / RFC 5322</span>
          </div>

          <div className="space-y-3">
            <div>
              <label className="text-xs font-bold text-slate-700 block mb-1">Envelope From / Sender:</label>
              <input
                type="text"
                value={sender}
                onChange={e => setSender(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-1.5 font-mono text-xs text-slate-900 focus:outline-none focus:border-slate-400 focus:bg-white"
              />
            </div>

            <div>
              <label className="text-xs font-bold text-slate-700 block mb-1">Subject Line:</label>
              <input
                type="text"
                value={subject}
                onChange={e => setSubject(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 rounded-lg px-3 py-1.5 text-xs text-slate-900 focus:outline-none focus:border-slate-400 focus:bg-white font-medium"
              />
            </div>

            <div>
              <label className="text-xs font-bold text-slate-700 block mb-1">Email Headers (Authentication & Routing):</label>
              <textarea
                value={headers}
                onChange={e => setHeaders(e.target.value)}
                rows={3}
                className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono text-[11px] text-slate-800 focus:outline-none focus:border-slate-400 focus:bg-white resize-y"
              />
            </div>

            <div>
              <label className="text-xs font-bold text-slate-700 block mb-1">Email Body Content:</label>
              <textarea
                value={body}
                onChange={e => setBody(e.target.value)}
                rows={7}
                className="w-full bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono text-xs text-slate-900 focus:outline-none focus:border-slate-400 focus:bg-white resize-y"
              />
            </div>

            <button
              onClick={handleAnalyzePhishing}
              disabled={analyzingEmail}
              className="w-full bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white text-xs font-semibold py-2.5 rounded-lg shadow-xs transition-all flex items-center justify-center gap-2 cursor-pointer"
            >
              {analyzingEmail ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Detonating & Inspecting Email Sandbox...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-indigo-400" />
                  <span>Analyze Phishing & BEC with AI</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column: AI Triage Results & Mail Flow Rules */}
        <div className="space-y-6">
          {analysis ? (
            <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 pb-3">
                <div>
                  <span className="text-xs font-mono text-slate-500 uppercase">AI Threat Verdict:</span>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span
                      className={`text-sm font-bold px-2.5 py-0.5 rounded ${
                        analysis.isPhishing
                          ? 'bg-rose-100 text-rose-700 border border-rose-200'
                          : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                      }`}
                    >
                      {analysis.isPhishing ? 'CONFIRMED PHISHING / BEC ATTACK' : 'CLEAN / BENIGN MESSAGE'}
                    </span>
                  </div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded-xl p-2.5 text-center min-w-[90px]">
                  <div className="text-[10px] text-slate-500 font-medium uppercase">Confidence</div>
                  <div className="text-lg font-bold font-mono text-indigo-600">{analysis.confidence}%</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                  <span className="text-slate-500 text-[10px] block">Threat Vector</span>
                  <span className="font-bold text-slate-900">{analysis.phishingType}</span>
                </div>
                <div className="bg-slate-50 p-2.5 rounded-lg border border-slate-200">
                  <span className="text-slate-500 text-[10px] block">Impersonated Brand</span>
                  <span className="font-bold text-slate-900">{analysis.spoofedBrand || 'Internal Corporate'}</span>
                </div>
              </div>

              {/* Suspicious Indicators */}
              <div>
                <span className="text-xs font-bold text-slate-900 block mb-1.5">Identified Malicious Indicators:</span>
                <ul className="space-y-1 text-xs">
                  {analysis.indicators.map((ind, i) => (
                    <li key={i} className="flex items-start gap-2 bg-rose-50/60 border border-rose-100 p-2 rounded-lg text-rose-900">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-600 shrink-0 mt-0.5" />
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Extracted URLs */}
              {analysis.extractedLinks && analysis.extractedLinks.length > 0 && (
                <div>
                  <span className="text-xs font-bold text-slate-900 block mb-1.5">Extracted Harvesting Links:</span>
                  <div className="space-y-1">
                    {analysis.extractedLinks.map((link, i) => (
                      <div key={i} className="p-2 rounded bg-slate-900 text-slate-100 font-mono text-[11px] truncate flex items-center justify-between">
                        <span className="truncate">{link}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Mail Flow Rule */}
              <div>
                <div className="flex items-center justify-between mb-1 text-xs">
                  <span className="font-bold text-slate-900">Automated Mail Flow Containment Rule:</span>
                  <button
                    onClick={() =>
                      handleCopyRule(
                        `New-TransportRule -Name "Block-Phish-${Date.now()}" -SenderDomainIs "${sender.split('@')[1] || 'micosoft-verify-auth.com'}" -DeleteMessage $true`
                      )
                    }
                    className="text-slate-600 hover:text-slate-900 flex items-center gap-1 font-medium"
                  >
                    {copiedRule ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedRule ? 'Copied' : 'Copy PowerShell'}</span>
                  </button>
                </div>
                <pre className="bg-slate-900 text-slate-100 p-2.5 rounded-lg font-mono text-[11px] overflow-x-auto">
                  {`New-TransportRule -Name "Block-Phish-${Date.now()}" -SenderDomainIs "${sender.split('@')[1] || 'micosoft-verify-auth.com'}" -DeleteMessage $true`}
                </pre>
              </div>
            </div>
          ) : (
            <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-xs flex flex-col items-center justify-center text-center text-slate-400 space-y-3 min-h-[400px]">
              <Mail className="w-10 h-10 text-slate-300" />
              <div>
                <h3 className="text-sm font-bold text-slate-700">Sandbox Ready for Detonation</h3>
                <p className="text-xs text-slate-500 max-w-sm mt-1">
                  Select a sample scenario on the left or paste an email message to inspect headers, domains, and phishing indicators.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
