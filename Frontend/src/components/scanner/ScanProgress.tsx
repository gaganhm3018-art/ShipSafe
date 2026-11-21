import React from 'react';
import { ScanStage } from '../../types/security';
import { CheckCircle2, Loader2, Circle, AlertCircle, FileSearch, Shield, Terminal } from 'lucide-react';

interface ScanProgressProps {
  stages: ScanStage[];
  currentStageIndex: number;
  progressPct: number;
  targetName: string;
  isScanning: boolean;
  onFinishScan: () => void;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  stages,
  currentStageIndex,
  progressPct,
  targetName,
  isScanning,
  onFinishScan
}) => {
  const isComplete = !isScanning && progressPct >= 100;
  const totalFindingsFound = stages.reduce((acc, s) => acc + (s.findingsFound || 0), 0);
  const totalFilesChecked = stages.reduce((acc, s) => acc + (s.filesChecked || 0), 0);

  return (
    <div className="space-y-5">
      {/* Target & overall progress bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-accent-secondary" />
            <span className="text-text-secondary">Auditing:</span>
            <span className="font-semibold text-text-primary">{targetName}</span>
          </div>
          <span className="text-accent-primary font-bold">{progressPct}%</span>
        </div>

        <div className="h-2 w-full bg-bg-main rounded-full overflow-hidden border border-border">
          <div
            className="h-full bg-accent-primary transition-all duration-300 ease-out"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>

      {/* Real-time telemetry banner */}
      <div className="grid grid-cols-3 gap-2 p-3 rounded bg-[#0D1219] border border-border text-center font-mono text-xs">
        <div>
          <div className="text-[10px] uppercase text-text-muted">Stages Active</div>
          <div className="font-bold text-text-primary mt-0.5">
            {currentStageIndex + 1} / {stages.length}
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase text-text-muted">Files Analyzed</div>
          <div className="font-bold text-accent-secondary mt-0.5">
            {totalFilesChecked}
          </div>
        </div>
        <div>
          <div className="text-[10px] uppercase text-text-muted">Findings Flagged</div>
          <div className={`font-bold mt-0.5 ${totalFindingsFound > 0 ? 'text-severity-critical' : 'text-accent-primary'}`}>
            {totalFindingsFound}
          </div>
        </div>
      </div>

      {/* 7-Stage Process Checklist */}
      <div className="border border-border rounded divide-y divide-border bg-bg-secondary overflow-hidden">
        {stages.map((stage, idx) => {
          const isDone = stage.status === 'COMPLETED';
          const isActive = stage.status === 'ACTIVE';
          const isPending = stage.status === 'PENDING';

          return (
            <div
              key={stage.id}
              className={`p-3 flex items-center justify-between text-xs transition-colors ${
                isActive ? 'bg-bg-elevated/70' : isDone ? 'bg-bg-secondary/60' : 'opacity-60'
              }`}
            >
              <div className="flex items-center gap-3">
                {/* Status Icon */}
                <div className="flex-shrink-0">
                  {isDone && <CheckCircle2 className="w-4 h-4 text-accent-primary" />}
                  {isActive && <Loader2 className="w-4 h-4 text-accent-secondary animate-spin" />}
                  {isPending && <Circle className="w-4 h-4 text-text-muted" />}
                </div>

                <div>
                  <div className={`font-medium ${isActive ? 'text-text-primary' : isDone ? 'text-text-primary' : 'text-text-muted'}`}>
                    <span className="font-mono text-text-muted mr-1.5">{stage.id}.</span>
                    {stage.name}
                  </div>
                  <div className="text-[11px] text-text-muted">
                    {stage.description}
                  </div>
                </div>
              </div>

              {/* Stage telemetry */}
              <div className="font-mono text-[11px] text-right">
                {isDone && (
                  <span className="text-text-muted">
                    {stage.durationMs}ms
                    {stage.findingsFound && stage.findingsFound > 0 ? (
                      <span className="ml-2 text-severity-critical font-semibold">
                        +{stage.findingsFound} flagged
                      </span>
                    ) : (
                      <span className="ml-2 text-accent-primary">clean</span>
                    )}
                  </span>
                )}
                {isActive && (
                  <span className="text-accent-secondary animate-pulse">
                    inspecting...
                  </span>
                )}
                {isPending && (
                  <span className="text-text-muted">pending</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Done action */}
      {isComplete && (
        <div className="pt-2 flex justify-end">
          <button
            onClick={onFinishScan}
            className="w-full py-2.5 px-4 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-bold font-mono transition-colors shadow-subtle flex items-center justify-center gap-2"
          >
            <span>Scan Completed — View Structured Findings</span>
          </button>
        </div>
      )}
    </div>
  );
};
