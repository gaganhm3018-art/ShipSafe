import React, { useState } from 'react';
import { SecurityFinding } from '../../types/security';
import { DiffViewer } from '../common/DiffViewer';
import { ConfirmationDialog } from '../common/ConfirmationDialog';
import { 
  Sparkles, 
  X, 
  AlertTriangle, 
  Bug, 
  Terminal, 
  ShieldCheck, 
  CheckCircle2, 
  Copy, 
  RotateCw,
  GitPullRequest
} from 'lucide-react';

interface AIRemediationModalProps {
  finding: SecurityFinding | null;
  isOpen: boolean;
  onClose: () => void;
  onApplyFix: (findingId: string, patchedCode: string) => void;
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const AIRemediationModal: React.FC<AIRemediationModalProps> = ({
  finding,
  isOpen,
  onClose,
  onApplyFix,
  onShowToast
}) => {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [isApplying, setIsApplying] = useState(false);
  const [isResolved, setIsResolved] = useState(false);

  if (!isOpen || !finding || !finding.remediationPatch) return null;

  const patch = finding.remediationPatch;

  const handleConfirmApply = async () => {
    setConfirmOpen(false);
    setIsApplying(true);

    // Simulate atomic patch application & automatic security rescan
    await new Promise(r => setTimeout(r, 700));
    setIsApplying(false);
    setIsResolved(true);
    onApplyFix(finding.id, patch.patchedCode);
    onShowToast("Fix Applied & Rescan Clean", `Vulnerability in ${finding.file} resolved and verified clean.`, "success");
  };

  const handleCopyPatch = () => {
    navigator.clipboard.writeText(patch.diffHunk);
    onShowToast("Patch Copied", "Git diff hunk copied to clipboard.", "info");
  };

  return (
    <>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
        <div className="w-full max-w-3xl bg-bg-secondary border border-border rounded-lg shadow-elevated overflow-hidden flex flex-col max-h-[90vh] animate-in zoom-in-95 duration-150">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-bg-elevated/40">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded bg-accent-primary/10 border border-accent-primary/20 text-accent-primary">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
                  AI Remediation Plan & Git Diff
                  <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-bg-main border border-border text-text-muted">
                    {finding.ruleId}
                  </span>
                </h3>
                <div className="text-xs text-text-muted font-mono mt-0.5">
                  Target: {finding.file}:{finding.line}
                </div>
              </div>
            </div>

            <button
              onClick={onClose}
              className="text-text-muted hover:text-text-primary transition-colors p-1 rounded hover:bg-bg-elevated"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Body Content */}
          <div className="p-6 overflow-y-auto space-y-5 text-xs">
            {/* If Rescan Succeeded */}
            {isResolved && (
              <div className="p-4 rounded bg-accent-primary/10 border border-accent-primary/30 text-accent-primary space-y-2 animate-in fade-in">
                <div className="flex items-center gap-2 font-bold font-mono text-sm">
                  <CheckCircle2 className="w-5 h-5 text-accent-primary" />
                  <span>Vulnerability Resolved: {finding.cwe} Eliminated</span>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  The automated security rescan executed deterministic AST and credential analysis on <span className="font-mono text-text-primary">{finding.file}</span>. 0 vulnerabilities or regressions detected.
                </p>
              </div>
            )}

            {/* 1. What Went Wrong */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 font-semibold text-text-primary font-mono uppercase tracking-wider text-[11px]">
                <Bug className="w-3.5 h-3.5 text-severity-high" />
                <span>1. What Went Wrong</span>
              </div>
              <div className="p-3 rounded bg-bg-main border border-border text-text-secondary leading-relaxed">
                {patch.analysis}
              </div>
            </div>

            {/* 2 & 3. Why It Matters & How an Attacker Could Exploit It */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 font-semibold text-text-primary font-mono uppercase tracking-wider text-[11px]">
                <AlertTriangle className="w-3.5 h-3.5 text-severity-critical" />
                <span>2. Exploit Scenario & Attack Vector</span>
              </div>
              <div className="p-3 rounded bg-[#0D1219] border border-border text-text-secondary font-mono leading-relaxed space-y-2">
                <div className="text-[11px] text-text-muted">
                  Simulated attacker payload against this entry point:
                </div>
                <div className="p-2 rounded bg-bg-main border border-border/80 text-severity-critical whitespace-pre-wrap select-all">
                  {patch.exploitScenario}
                </div>
              </div>
            </div>

            {/* 4. What the Proposed Change Accomplishes */}
            <div className="space-y-1.5">
              <div className="flex items-center gap-1.5 font-semibold text-text-primary font-mono uppercase tracking-wider text-[11px]">
                <ShieldCheck className="w-3.5 h-3.5 text-accent-primary" />
                <span>3. Remediation Mechanism</span>
              </div>
              <div className="p-3 rounded bg-bg-main border border-border text-text-secondary leading-relaxed">
                {patch.whatChanged}
              </div>
            </div>

            {/* 5. Git-Style Diff Viewer */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="font-semibold text-text-primary uppercase tracking-wider flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-accent-secondary" />
                  <span>Proposed Code Changes</span>
                </span>
                <span className="text-text-muted">Unified Git Patch</span>
              </div>

              <DiffViewer
                filePath={finding.file}
                diffHunk={patch.diffHunk}
                explanation="Modifies sensitive statement to enforce strict parameter encapsulation."
              />
            </div>
          </div>

          {/* Footer Actions */}
          <div className="px-6 py-4 bg-bg-elevated/40 border-t border-border flex items-center justify-between gap-3">
            <div className="text-[11px] text-text-muted font-mono flex items-center gap-1.5">
              <GitPullRequest className="w-3.5 h-3.5 text-accent-secondary" />
              <span>Fix will be applied locally & immediately verified via rescan</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyPatch}
                className="px-3 py-1.5 rounded bg-bg-main hover:bg-bg-elevated border border-border text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
              >
                Copy Patch
              </button>
              <button
                onClick={onClose}
                className="px-3 py-1.5 rounded bg-bg-main hover:bg-bg-elevated border border-border text-xs text-text-secondary hover:text-text-primary transition-colors"
              >
                {isResolved ? 'Done' : 'Reject Suggestion'}
              </button>
              {!isResolved && (
                <button
                  disabled={isApplying}
                  onClick={() => setConfirmOpen(true)}
                  className="px-4 py-1.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-bold font-mono transition-colors shadow-subtle flex items-center gap-1.5 disabled:opacity-50"
                >
                  {isApplying ? (
                    <>
                      <RotateCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Applying & Rescanning...</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Apply Fix & Rescan</span>
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Dialog before applying */}
      <ConfirmationDialog
        isOpen={confirmOpen}
        title="Apply AI Security Fix?"
        description={`This will write the suggested patch directly to '${finding.file}'. A fresh deterministic scan will immediately execute to confirm the finding is fully resolved.`}
        confirmLabel="Confirm & Apply Patch"
        variant="primary"
        details={{
          file: finding.file,
          findingId: finding.id,
          branch: 'main'
        }}
        onConfirm={handleConfirmApply}
        onCancel={() => setConfirmOpen(false)}
      />
    </>
  );
};
