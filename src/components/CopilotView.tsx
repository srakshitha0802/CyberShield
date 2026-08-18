import React, { useState, useRef, useEffect } from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Bot,
  Send,
  Sparkles,
  User,
  Copy,
  Check,
  RefreshCw,
  Terminal,
  ShieldAlert,
  Zap,
  HelpCircle,
  Code,
  Flame,
} from 'lucide-react';
import { CopilotMessage } from '../types/security';

export const CopilotView: React.FC = () => {
  const { copilotMessages, sendCopilotMessage, threats, selectedThreatId } = useSecurity();
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const chatBottomRef = useRef<HTMLDivElement>(null);

  const currentThreat = threats.find(t => t.id === selectedThreatId) || threats[0];

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [copilotMessages, isTyping]);

  const handleSendMessage = async (textToSend?: string) => {
    const query = textToSend || inputText;
    if (!query.trim()) return;

    setInputText('');
    setIsTyping(true);
    try {
      await sendCopilotMessage(query, currentThreat);
    } finally {
      setIsTyping(false);
    }
  };

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(code);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const promptSuggestions = [
    `Why is alert ${currentThreat?.threatCode || 'TH-1042'} classified as critical?`,
    'What are the immediate containment actions for active threats?',
    'Write iptables and AWS WAF rules to block all attacking IP indicators',
    'Summarize our security posture and recent breaches for an Executive briefing',
    'Explain the ransomware kill chain detected on Finance-DB-Server',
    'How do I remediate the compromised admin service credentials?',
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center">
              <Bot className="w-5 h-5 text-indigo-600" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-900 flex items-center gap-2">
                CyberShield AI SOC Copilot
                <span className="bg-indigo-50 text-indigo-700 border border-indigo-200 text-[10px] font-bold px-2 py-0.5 rounded">
                  Qwen + Gemini 3.7 Flash Engine
                </span>
              </h1>
              <p className="text-xs text-slate-500">
                Interactive cyber assistant for threat investigation, triage explanations, and automated script synthesis.
              </p>
            </div>
          </div>
        </div>

        <div className="text-xs font-mono text-slate-600 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200">
          Context Active: <b className="text-slate-900">{currentThreat?.threatCode || 'Global SOC'}</b>
        </div>
      </div>

      {/* Main Chat Interface */}
      <div className="bg-white border border-slate-200 rounded-xl flex flex-col h-[600px] overflow-hidden shadow-xs">
        {/* Messages Scroll Area */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {copilotMessages.map(msg => (
            <div
              key={msg.id}
              className={`flex items-start gap-3 ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.sender === 'assistant' && (
                <div className="w-7 h-7 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center shrink-0 mt-1">
                  <Bot className="w-4 h-4 text-indigo-600" />
                </div>
              )}

              <div
                className={`max-w-2xl rounded-2xl p-4 text-xs leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-slate-900 text-white font-medium'
                    : 'bg-slate-50 border border-slate-200 text-slate-800 shadow-xs'
                }`}
              >
                <div className="whitespace-pre-wrap font-sans">{msg.text}</div>

                {msg.codeSnippet && (
                  <div className="mt-3">
                    <div className="flex items-center justify-between text-[10px] text-slate-400 font-mono mb-1">
                      <span>Executable Mitigation Script:</span>
                      <button
                        onClick={() => handleCopy(msg.codeSnippet!)}
                        className="text-slate-600 hover:text-slate-900 font-sans font-semibold flex items-center gap-1"
                      >
                        {copiedCode === msg.codeSnippet ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedCode === msg.codeSnippet ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <pre className="bg-slate-900 text-slate-100 p-3 rounded-lg font-mono text-[11px] overflow-x-auto">
                      {msg.codeSnippet}
                    </pre>
                  </div>
                )}

                <div className="text-[10px] text-slate-400 font-mono mt-2 text-right">
                  {msg.timestamp}
                </div>
              </div>

              {msg.sender === 'user' && (
                <div className="w-7 h-7 rounded-lg bg-slate-200 flex items-center justify-center shrink-0 mt-1">
                  <User className="w-4 h-4 text-slate-700" />
                </div>
              )}
            </div>
          ))}

          {isTyping && (
            <div className="flex items-center gap-3">
              <div className="w-7 h-7 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-center shrink-0">
                <RefreshCw className="w-4 h-4 text-indigo-600 animate-spin" />
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-2xl px-4 py-2.5 text-xs text-slate-500 font-medium">
                CyberShield AI is analyzing telemetry & formulating response...
              </div>
            </div>
          )}

          <div ref={chatBottomRef} />
        </div>

        {/* Suggested Prompts Bar */}
        <div className="px-4 py-2.5 bg-slate-50 border-t border-slate-200 flex items-center gap-2 overflow-x-auto scrollbar-none">
          <span className="text-[11px] text-slate-500 font-medium whitespace-nowrap">Suggested:</span>
          {promptSuggestions.map((prompt, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(prompt)}
              className="bg-white hover:bg-slate-100 text-slate-700 text-[11px] font-medium px-2.5 py-1 rounded-full border border-slate-200 whitespace-nowrap transition-colors cursor-pointer"
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-4 bg-white border-t border-slate-200">
          <form
            onSubmit={e => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex gap-2"
          >
            <input
              type="text"
              value={inputText}
              onChange={e => setInputText(e.target.value)}
              placeholder="Ask CyberShield Copilot (e.g. 'Write firewall rules to block attacking IPs', 'Explain alert TH-1042')..."
              className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 text-xs text-slate-900 focus:outline-none focus:border-slate-400 focus:bg-white"
            />
            <button
              type="submit"
              disabled={!inputText.trim() || isTyping}
              className="bg-slate-900 hover:bg-slate-800 disabled:opacity-50 text-white text-xs font-semibold px-4 py-2.5 rounded-xl shadow-xs transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
