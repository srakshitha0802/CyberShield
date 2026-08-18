import React from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  AlertTriangle,
  CheckCircle,
  Info,
  X,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';

export const NotificationToast: React.FC = () => {
  const { notification, clearNotification, setActiveTab } = useSecurity();

  if (!notification) return null;

  const isCritical = notification.type === 'critical';
  const isHigh = notification.type === 'high';
  const isSuccess = notification.type === 'success';

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-full shadow-2xl rounded-2xl border animate-slideUp font-sans overflow-hidden bg-white">
      <div
        className={`p-4 flex items-start gap-3 border-l-4 ${
          isCritical
            ? 'border-l-rose-600 bg-rose-50/50 border-rose-200'
            : isHigh
            ? 'border-l-amber-500 bg-amber-50/50 border-amber-200'
            : isSuccess
            ? 'border-l-emerald-500 bg-emerald-50/50 border-emerald-200'
            : 'border-l-blue-500 bg-blue-50/50 border-blue-200'
        }`}
      >
        <div className="shrink-0 mt-0.5">
          {isCritical ? (
            <div className="w-8 h-8 rounded-xl bg-rose-100 text-rose-700 flex items-center justify-center animate-pulse">
              <AlertTriangle className="w-4 h-4" />
            </div>
          ) : isHigh ? (
            <div className="w-8 h-8 rounded-xl bg-amber-100 text-amber-700 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
          ) : isSuccess ? (
            <div className="w-8 h-8 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center">
              <CheckCircle className="w-4 h-4" />
            </div>
          ) : (
            <div className="w-8 h-8 rounded-xl bg-blue-100 text-blue-700 flex items-center justify-center">
              <Info className="w-4 h-4" />
            </div>
          )}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 font-mono">
              {isCritical ? 'CRITICAL INCIDENT ALERT' : isHigh ? 'SECURITY EVENT WARNING' : isSuccess ? 'CONTAINMENT SUCCESS' : 'SYSTEM NOTIFICATION'}
            </h4>
            <button
              onClick={clearNotification}
              className="text-slate-400 hover:text-slate-700 p-1 rounded-md transition-colors cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          <p className="text-xs font-medium text-slate-800 mt-1 leading-snug">
            {notification.message}
          </p>

          {(isCritical || isHigh) && (
            <div className="mt-2.5 flex items-center gap-2">
              <button
                onClick={() => {
                  setActiveTab('investigation');
                  clearNotification();
                }}
                className="inline-flex items-center gap-1 text-[11px] font-bold text-rose-700 bg-rose-100 hover:bg-rose-200 px-2.5 py-1 rounded-md transition-colors cursor-pointer"
              >
                <span>Launch DFIR Investigation</span>
                <ArrowRight className="w-3 h-3" />
              </button>
              <button
                onClick={() => {
                  setActiveTab('playbooks');
                  clearNotification();
                }}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600 hover:text-slate-900 px-2 py-1 rounded transition-colors cursor-pointer"
              >
                <span>View SOAR Playbook</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
