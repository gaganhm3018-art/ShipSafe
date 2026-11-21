import React, { useState } from 'react';
import { SecurityPolicy, Severity } from '../../types/security';
import { DEFAULT_POLICY } from '../../data/mockSecurityData';
import { 
  Sliders, 
  ShieldAlert, 
  Key, 
  Code2, 
  FileTerminal, 
  Save, 
  RotateCcw, 
  Lock, 
  Layers, 
  AlertTriangle,
  FolderMinus
} from 'lucide-react';

interface PoliciesSettingsViewProps {
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const PoliciesSettingsView: React.FC<PoliciesSettingsViewProps> = ({ onShowToast }) => {
  const [policy, setPolicy] = useState<SecurityPolicy>({ ...DEFAULT_POLICY });
  const [ignoredPathsText, setIgnoredPathsText] = useState(policy.ignoredPaths.join('\n'));

  const handleSave = () => {
    const updatedPaths = ignoredPathsText.split('\n').map(p => p.trim()).filter(Boolean);
    setPolicy(prev => ({ ...prev, ignoredPaths: updatedPaths }));
    onShowToast("Security Policies Saved", "Deployment failure gates and deterministic detection rules updated.", "success");
  };

  const handleReset = () => {
    setPolicy({ ...DEFAULT_POLICY });
    setIgnoredPathsText(DEFAULT_POLICY.ignoredPaths.join('\n'));
    onShowToast("Policy Defaults Restored", "Reset to standard enterprise security thresholds.", "info");
  };

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <h1 className="text-base font-bold text-text-primary flex items-center gap-2">
            <Sliders className="w-5 h-5 text-accent-primary" />
            Security Policies & Deployment Gates
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Configure automated pass/fail criteria, rule sensitivity, and exclusion masks
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-bg-secondary hover:bg-bg-elevated border border-border text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>
          <button
            onClick={handleSave}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-bold font-mono transition-colors shadow-subtle"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save Policies</span>
          </button>
        </div>
      </div>

      {/* 1. CI/CD Deployment Failure Gates */}
      <div className="bg-bg-secondary border border-border rounded p-5 space-y-4">
        <div className="flex items-center gap-2 text-xs font-semibold text-text-primary uppercase tracking-wider font-mono">
          <ShieldAlert className="w-4 h-4 text-severity-critical" />
          <span>CI/CD Pipeline Failure Thresholds</span>
        </div>

        <p className="text-xs text-text-secondary leading-relaxed">
          Specify the minimum finding severity that causes pre-commit hooks and GitHub Actions checks to exit with a non-zero status code and block deployment.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
          <div className="space-y-1.5">
            <label className="text-xs font-mono font-medium text-text-secondary">
              Block Commits & Pull Requests On:
            </label>
            <select
              value={policy.failOnSeverity}
              onChange={(e) => setPolicy({ ...policy, failOnSeverity: e.target.value as Severity })}
              className="w-full bg-bg-main border border-border rounded px-3 py-2 text-xs font-mono text-text-primary focus:outline-none focus:border-accent-secondary"
            >
              <option value="CRITICAL">Critical Only (Allow High, Medium, Low)</option>
              <option value="HIGH">High & Critical (Recommended for production)</option>
              <option value="MEDIUM">Medium, High & Critical (Strict audit)</option>
              <option value="LOW">Low and Above (Zero tolerance)</option>
            </select>
          </div>

          <div className="space-y-2 pt-1 font-mono text-xs">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={policy.blockPRsOnCritical}
                onChange={(e) => setPolicy({ ...policy, blockPRsOnCritical: e.target.checked })}
                className="rounded border-border text-accent-primary focus:ring-0 bg-bg-main"
              />
              <span className="text-text-primary">Enforce Hard-Block on any CRITICAL vulnerability</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={policy.blockPRsOnHigh}
                onChange={(e) => setPolicy({ ...policy, blockPRsOnHigh: e.target.checked })}
                className="rounded border-border text-accent-primary focus:ring-0 bg-bg-main"
              />
              <span className="text-text-primary">Require team lead approval if HIGH severity present</span>
            </label>
          </div>
        </div>
      </div>

      {/* 2. Deterministic Rule Modules */}
      <div className="bg-bg-secondary border border-border rounded p-5 space-y-4">
        <div className="flex items-center gap-2 text-xs font-semibold text-text-primary uppercase tracking-wider font-mono">
          <Layers className="w-4 h-4 text-accent-secondary" />
          <span>Deterministic Security Engines</span>
        </div>

        <div className="divide-y divide-border border border-border rounded bg-bg-main">
          {/* Secret & Credentials */}
          <div className="p-3.5 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="font-mono text-xs font-semibold text-text-primary flex items-center gap-2">
                <Key className="w-3.5 h-3.5 text-accent-primary" />
                <span>Deterministic Secret & Cloud Key Detection</span>
              </div>
              <div className="text-[11px] text-text-muted">
                Detects AWS, OpenAI, GitHub tokens, database URIs, and private RSA/SSH keys.
              </div>
            </div>
            <input
              type="checkbox"
              checked={true}
              disabled
              className="rounded border-border text-accent-primary bg-bg-elevated cursor-not-allowed"
            />
          </div>

          {/* Shannon Entropy Threshold */}
          <div className="p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="font-mono text-xs font-semibold text-text-primary">
                  Shannon Entropy Heuristic Threshold
                </div>
                <div className="text-[11px] text-text-muted">
                  Flags high-randomness string literals as candidate unclassified secrets (Default: 4.5).
                </div>
              </div>
              <span className="font-mono text-xs font-bold text-accent-secondary">
                {policy.entropyThreshold.toFixed(1)}
              </span>
            </div>
            <input
              type="range"
              min="3.8"
              max="5.2"
              step="0.1"
              value={policy.entropyThreshold}
              onChange={(e) => setPolicy({ ...policy, entropyThreshold: parseFloat(e.target.value) })}
              className="w-full accent-accent-primary"
            />
          </div>

          {/* SQL & Command Injections */}
          <div className="p-3.5 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="font-mono text-xs font-semibold text-text-primary flex items-center gap-2">
                <Code2 className="w-3.5 h-3.5 text-severity-critical" />
                <span>SQL & OS Command Injection Engine (AST Analysis)</span>
              </div>
              <div className="text-[11px] text-text-muted">
                Detects f-strings in cursor.execute(), template literals, and subprocess shell=True.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.enableASTInjections}
              onChange={(e) => setPolicy({ ...policy, enableASTInjections: e.target.checked })}
              className="rounded border-border text-accent-primary focus:ring-0 bg-bg-main"
            />
          </div>

          {/* DOM & XSS */}
          <div className="p-3.5 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="font-mono text-xs font-semibold text-text-primary flex items-center gap-2">
                <FileTerminal className="w-3.5 h-3.5 text-severity-high" />
                <span>DOM Manipulation & React DangerouslySetInnerHTML Checks</span>
              </div>
              <div className="text-[11px] text-text-muted">
                Flags un-sanitized dynamic markup passed into React or native innerHTML sinks.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.enableXSSChecks}
              onChange={(e) => setPolicy({ ...policy, enableXSSChecks: e.target.checked })}
              className="rounded border-border text-accent-primary focus:ring-0 bg-bg-main"
            />
          </div>

          {/* Missing Auth & IDOR */}
          <div className="p-3.5 flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="font-mono text-xs font-semibold text-text-primary flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 text-accent-secondary" />
                <span>Missing Route Authentication & IDOR Checks</span>
              </div>
              <div className="text-[11px] text-text-muted">
                Identifies sensitive endpoints lacking authentication guards and tenancy filters.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.enableAuthChecks}
              onChange={(e) => setPolicy({ ...policy, enableAuthChecks: e.target.checked })}
              className="rounded border-border text-accent-primary focus:ring-0 bg-bg-main"
            />
          </div>
        </div>
      </div>

      {/* 3. Ignored Paths (.shipsafeignore) */}
      <div className="bg-bg-secondary border border-border rounded p-5 space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-text-primary uppercase tracking-wider font-mono">
          <FolderMinus className="w-4 h-4 text-text-muted" />
          <span>Ignored Paths & File Masks (.shipsafeignore)</span>
        </div>

        <p className="text-xs text-text-secondary leading-relaxed">
          Paths and glob patterns excluded from AST inspection and credential scans:
        </p>

        <textarea
          rows={5}
          value={ignoredPathsText}
          onChange={(e) => setIgnoredPathsText(e.target.value)}
          className="w-full p-3 rounded bg-bg-main border border-border font-mono text-xs text-text-secondary focus:outline-none focus:border-accent-secondary leading-relaxed"
          placeholder="node_modules/**\n.git/**\ntests/fixtures/**"
        />
      </div>
    </div>
  );
};
