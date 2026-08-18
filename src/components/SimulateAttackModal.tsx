import React from 'react';
import { useSecurity } from '../context/SecurityContext';
import {
  Flame,
  X,
  Zap,
  ShieldAlert,
  Server,
  Users,
  Play,
  Layers,
  Sparkles,
} from 'lucide-react';
import { AttackScenario } from '../types/security';

interface SimulateAttackModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SimulateAttackModal: React.FC<SimulateAttackModalProps> = ({ isOpen, onClose }) => {
  const { attackScenarios, sampleScenarios, triggerAttackScenario, setActiveTab } = useSecurity();

  if (!isOpen) return null;

  const scenariosList = (attackScenarios && attackScenarios.length > 0) ? attackScenarios : (sampleScenarios || []);

  const handleTrigger = async (scenario: AttackScenario) => {
    onClose();
    await triggerAttackScenario(scenario);
    setActiveTab('investigation');
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white border border-slate-200 rounded-2xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-xl">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-50 border border-rose-200 flex items-center justify-center">
              <Flame className="w-5 h-5 text-rose-600" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900">
                Red Team Adversary Simulation Studio
              </h2>
              <p className="text-xs text-slate-500">Inject high-fidelity attack vectors directly into the live AI SOC sensor feed</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-100 cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body: Scenarios List */}
        <div className="p-6 flex-1 overflow-y-auto space-y-4 bg-slate-50/50">
          <p className="text-xs text-slate-600">
            Select an attack campaign below to inject realistic multi-stage adversarial telemetry (failed authentications, process injections, C2 beacons, and ransom staging). CyberShield AI will ingest, correlate, and open the active investigation dossier.
          </p>

          <div className="space-y-3">
            {scenariosList.map(scenario => (
              <div
                key={scenario.id}
                className="bg-white border border-slate-200 hover:border-slate-300 rounded-xl p-4 shadow-xs transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 max-w-xl">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                        scenario.severity === 'critical'
                          ? 'bg-rose-100 text-rose-700 border border-rose-200'
                          : 'bg-amber-100 text-amber-800 border border-amber-200'
                      }`}
                    >
                      {scenario.severity}
                    </span>
                    <span className="text-xs font-bold text-slate-900">{scenario.name}</span>
                  </div>

                  <p className="text-xs text-slate-600 leading-relaxed">{scenario.description}</p>

                  <div className="flex flex-wrap items-center gap-2 pt-1 font-mono text-[11px] text-slate-500">
                    <span>Target: <b className="text-slate-800">{scenario.targetAssets.join(', ')}</b></span>
                    <span>•</span>
                    <span>Actor: <b className="text-rose-700">{scenario.threatActor || 'Unknown APT'}</b></span>
                    <span>•</span>
                    <span>MITRE: <b>{scenario.mitreTechniques.join(', ')}</b></span>
                  </div>
                </div>

                <button
                  onClick={() => handleTrigger(scenario)}
                  className="bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-xs transition-all flex items-center gap-1.5 shrink-0 self-start sm:self-center cursor-pointer"
                >
                  <Flame className="w-3.5 h-3.5 text-amber-200" />
                  <span>Launch Simulation</span>
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-white border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
          <span>Telemetry is securely isolated within the sandbox stream</span>
          <button
            onClick={onClose}
            className="text-slate-600 hover:text-slate-900 font-semibold px-3 py-1.5 rounded-lg border border-slate-200 cursor-pointer"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
