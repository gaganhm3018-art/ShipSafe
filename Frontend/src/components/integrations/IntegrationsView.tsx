import React, { useState } from 'react';
import { 
  Terminal, 
  GitBranch, 
  CheckCircle2, 
  ShieldAlert, 
  Copy, 
  Check, 
  ExternalLink,
  Code2,
  Cpu,
  GitPullRequest,
  AlertTriangle,
  Play
} from 'lucide-react';
import { GithubIcon } from '../common/Icons';

interface IntegrationsViewProps {
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const IntegrationsView: React.FC<IntegrationsViewProps> = ({ onShowToast }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [simulatedCIState, setSimulatedCIState] = useState<'blocked' | 'passed'>('blocked');

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    onShowToast(`${label} Copied`, "Configuration snippet copied to clipboard.", "info");
  };

  const githubActionsYaml = `name: ShipSafe Security Audit

on:
  push:
    branches: [ "main", "staging" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-audit:
    name: ShipSafe Deterministic Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout Codebase
        uses: actions/checkout@v4

      - name: Run ShipSafe Security Engine
        uses: shipsafe/scan-action@v2
        with:
          fail-on: high          # Options: critical, high, medium
          token: \${{ secrets.SHIPSAFE_API_KEY }}
          sarif-export: results.sarif
          auto-pr-comment: true

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif`;

  const preCommitYaml = `# .pre-commit-config.yaml
repos:
  - repo: https://github.com/shipsafe/pre-commit-hook
    rev: v2.4.0
    hooks:
      - id: shipsafe-precommit
        name: ShipSafe Local Secret & Injection Guard
        entry: shipsafe scan --staged --fail-on high
        language: system
        pass_filenames: false`;

  const bashHookScript = `#!/usr/bin/env bash
# .git/hooks/pre-commit
set -e

echo "[ShipSafe] Running deterministic pre-commit security check..."
shipsafe scan --staged --fail-on high

if [ $? -ne 0 ]; then
    echo "❌ [ShipSafe] Commit blocked! Fix flagged security findings before pushing."
    exit 1
fi
echo "✅ [ShipSafe] All pre-commit security checks passed."`;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-border pb-4">
        <h1 className="text-base font-bold text-text-primary flex items-center gap-2">
          <Cpu className="w-5 h-5 text-accent-secondary" />
          Developer Tooling & CI/CD Integrations
        </h1>
        <p className="text-xs text-text-muted mt-0.5">
          Prevent vulnerable Python and JavaScript code from reaching production via automated pipeline gates
        </p>
      </div>

      {/* 1. Live CI/CD Commit Status Simulation Widget (Section 10 Requirement) */}
      <div className="p-4 rounded border border-border bg-bg-secondary space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <GitPullRequest className="w-4 h-4 text-accent-secondary" />
            <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
              CI/CD Pull Request Gate Status (Live Preview)
            </h2>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-text-muted">Simulate PR Gate:</span>
            <button
              onClick={() => setSimulatedCIState(simulatedCIState === 'blocked' ? 'passed' : 'blocked')}
              className="px-2.5 py-1 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-text-primary font-semibold transition-colors"
            >
              Toggle: {simulatedCIState === 'blocked' ? 'Failing (Blocked)' : 'Passing (Clean)'}
            </button>
          </div>
        </div>

        {/* PR Status Card */}
        <div className="p-4 rounded bg-[#0D1219] border border-border font-mono text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-border/80 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-text-primary">PR #142:</span>
              <span className="text-text-secondary">feat(api): optimize user retrieval query</span>
            </div>
            <div className="text-[11px] text-text-muted flex items-center gap-1">
              <GitBranch className="w-3 h-3" />
              <span>feature/user-opt &rarr; main</span>
            </div>
          </div>

          {simulatedCIState === 'blocked' ? (
            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2 text-severity-critical font-bold">
                <ShieldAlert className="w-4 h-4" />
                <span>❌ Checks Failed — ShipSafe Security Guard (fail-on: high)</span>
              </div>
              <div className="p-3 rounded bg-severity-critical/10 border border-severity-critical/20 text-text-secondary space-y-1">
                <div className="text-severity-critical font-semibold">
                  Policy Violated: Release Blocked on CRITICAL and HIGH severity findings.
                </div>
                <div className="text-[11px] text-text-muted">
                  Findings causing CI failure:
                </div>
                <ul className="list-disc list-inside text-[11px] text-text-primary font-mono space-y-0.5">
                  <li><span className="text-severity-critical">[CRITICAL]</span> INJ-001 (SQL Injection) in <code className="text-text-primary">backend/api/user_controller.py:42</code></li>
                  <li><span className="text-severity-critical">[CRITICAL]</span> SEC-001 (Exposed AWS Key) in <code className="text-text-primary">backend/auth/aws_client.py:14</code></li>
                  <li><span className="text-severity-high">[HIGH]</span> DOM-001 (XSS dangerouslySetInnerHTML) in <code className="text-text-primary">frontend/src/components/UserProfileCard.tsx:37</code></li>
                </ul>
              </div>
            </div>
          ) : (
            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2 text-accent-primary font-bold">
                <CheckCircle2 className="w-4 h-4" />
                <span>✅ All Checks Passed — ShipSafe Security Guard</span>
              </div>
              <div className="p-3 rounded bg-accent-primary/10 border border-accent-primary/20 text-accent-primary text-[11px]">
                0 policy violations detected across 64 files. Commit is verified safe to merge and ship.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Grid of 4 Core Integrations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* 1. GitHub App */}
        <div className="bg-bg-secondary border border-border rounded p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded bg-bg-elevated border border-border text-text-primary">
                <GithubIcon className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-text-primary">GitHub App</h3>
                <div className="text-xs text-text-muted">Automated PR checks & comment bots</div>
              </div>
            </div>
            <span className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20 font-semibold">
              <CheckCircle2 className="w-3 h-3" /> Connected
            </span>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            The ShipSafe GitHub App automatically inspects pull request diffs, checks policy failure thresholds, and posts inline security reviews with Git-style patch recommendations.
          </p>

          <div className="space-y-2 pt-2 border-t border-border/80 font-mono text-xs">
            <div className="flex items-center justify-between text-text-muted">
              <span>Organization:</span>
              <span className="text-text-primary font-semibold">Acme-Org</span>
            </div>
            <div className="flex items-center justify-between text-text-muted">
              <span>Active Repositories:</span>
              <span className="text-accent-secondary font-semibold">4 Repositories</span>
            </div>
            <div className="flex items-center justify-between text-text-muted">
              <span>PR Inline Comments:</span>
              <span className="text-accent-primary">Enabled</span>
            </div>
          </div>
        </div>

        {/* 2. CLI Tool */}
        <div className="bg-bg-secondary border border-border rounded p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded bg-bg-elevated border border-border text-accent-primary">
                <Terminal className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-text-primary">ShipSafe Developer CLI</h3>
                <div className="text-xs text-text-muted">Local command-line scanning & auto-patching</div>
              </div>
            </div>
            <span className="inline-flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20 font-semibold">
              v2.4.0 Active
            </span>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Scan your project directly in your terminal before committing. Instantly view findings, CVSS scores, and apply suggested patches in your terminal.
          </p>

          <div className="p-3 rounded bg-bg-main border border-border font-mono text-xs space-y-2">
            <div className="flex items-center justify-between text-text-muted text-[10px]">
              <span>Install command:</span>
              <button
                onClick={() => copyToClipboard('npm install -g @shipsafe/cli', 'cli-inst', 'CLI install')}
                className="hover:text-text-primary flex items-center gap-1"
              >
                {copiedKey === 'cli-inst' ? <Check className="w-3 h-3 text-accent-primary" /> : <Copy className="w-3 h-3" />}
                <span>Copy</span>
              </button>
            </div>
            <div className="text-accent-secondary select-all">
              npm install -g @shipsafe/cli
            </div>

            <div className="flex items-center justify-between text-text-muted text-[10px] pt-1">
              <span>Run local scan:</span>
              <button
                onClick={() => copyToClipboard('shipsafe scan . --fail-on high', 'cli-run', 'CLI scan command')}
                className="hover:text-text-primary flex items-center gap-1"
              >
                {copiedKey === 'cli-run' ? <Check className="w-3 h-3 text-accent-primary" /> : <Copy className="w-3 h-3" />}
                <span>Copy</span>
              </button>
            </div>
            <div className="text-text-primary select-all">
              shipsafe scan . --fail-on high
            </div>
          </div>
        </div>

        {/* 3. GitHub Actions CI/CD */}
        <div className="bg-bg-secondary border border-border rounded p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded bg-bg-elevated border border-border text-accent-secondary">
                <Code2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-text-primary">GitHub Actions Workflow</h3>
                <div className="text-xs text-text-muted">.github/workflows/shipsafe.yml</div>
              </div>
            </div>
            <button
              onClick={() => copyToClipboard(githubActionsYaml, 'gha-yml', 'GitHub Actions YAML')}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
            >
              {copiedKey === 'gha-yml' ? <Check className="w-3.5 h-3.5 text-accent-primary" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy YAML</span>
            </button>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Drop this workflow file into your repository to enforce security policies and export findings to the GitHub Security tab automatically.
          </p>

          <pre className="p-3 rounded bg-bg-main border border-border font-mono text-[11px] text-text-secondary overflow-x-auto max-h-48 leading-relaxed">
            {githubActionsYaml}
          </pre>
        </div>

        {/* 4. Git Pre-Commit Hook */}
        <div className="bg-bg-secondary border border-border rounded p-5 space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded bg-bg-elevated border border-border text-severity-high">
                <GitBranch className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-text-primary">Git Pre-Commit Hook</h3>
                <div className="text-xs text-text-muted">Intercept vulnerabilities at commit time</div>
              </div>
            </div>
            <button
              onClick={() => copyToClipboard(preCommitYaml, 'pre-yml', 'pre-commit YAML')}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
            >
              {copiedKey === 'pre-yml' ? <Check className="w-3.5 h-3.5 text-accent-primary" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy Hook</span>
            </button>
          </div>

          <p className="text-xs text-text-secondary leading-relaxed">
            Guarantees that credentials, SQL injections, and outdated dependencies never enter your Git history by running deterministic rules before commit creation.
          </p>

          <pre className="p-3 rounded bg-bg-main border border-border font-mono text-[11px] text-text-secondary overflow-x-auto max-h-48 leading-relaxed">
            {preCommitYaml}
          </pre>
        </div>
      </div>
    </div>
  );
};
