import React, { useState } from 'react';
import { SecurityFinding } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { CodeViewer } from '../common/CodeViewer';
import { 
  Sparkles, 
  ExternalLink, 
  Copy, 
  Check, 
  ShieldAlert, 
  AlertTriangle, 
  FileCode, 
  RotateCw, 
  CheckCircle2, 
  EyeOff,
  Terminal,
  Info
} from 'lucide-react';

interface FindingInspectorProps {
  finding: SecurityFinding | null;
  onOpenRemediation: (finding: SecurityFinding) => void;
  onMarkStatus: (findingId: string, newStatus: 'OPEN' | 'REMEDIATED' | 'IGNORED') => void;
  onRescanFile: (filePath: string) => void;
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const FindingInspector: React.FC<FindingInspectorProps> = ({
  finding,
  onOpenRemediation,
  onMarkStatus,
  onRescanFile,
  onShowToast
}) => {
  const [copiedId, setCopiedId] = useState(false);

  if (!finding) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 text-center text-text-muted bg-bg-main space-y-3">
        <ShieldAlert className="w-10 h-10 text-text-muted opacity-30" />
        <div className="font-mono text-xs">No vulnerability selected</div>
        <p className="text-xs max-w-xs text-text-muted">
          Select a security finding from the left panel to inspect deterministic detection rules, affected lines, and AI-suggested remediation.
        </p>
      </div>
    );
  }

  const handleCopyId = () => {
    navigator.clipboard.writeText(finding.id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
    onShowToast("Finding ID Copied", finding.id, "info");
  };

  const isRemediated = finding.status === 'REMEDIATED';
  const isIgnored = finding.status === 'IGNORED';

  return (
    <div className="h-full flex flex-col bg-bg-main overflow-y-auto">
      {/* Top sticky action toolbar */}
      <div className="sticky top-0 z-10 px-6 py-3 bg-bg-secondary border-b border-border flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <SeverityBadge severity={finding.severity} size="md" />
          <button
            onClick={handleCopyId}
            className="flex items-center gap-1.5 font-mono text-xs text-text-muted hover:text-text-primary px-2 py-1 rounded bg-bg-elevated border border-border transition-colors"
            title="Click to copy ID"
          >
            <span>{finding.id}</span>
            {copiedId ? <Check className="w-3 h-3 text-accent-primary" /> : <Copy className="w-3 h-3" />}
          </button>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {/* Rescan target file */}
          <button
            onClick={() => onRescanFile(finding.file)}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
            title="Rescan this target file"
          >
            <RotateCw className="w-3.5 h-3.5 text-accent-secondary" />
            <span>Rescan File</span>
          </button>

          {/* Toggle False Positive */}
          <button
            onClick={() => onMarkStatus(finding.id, isIgnored ? 'OPEN' : 'IGNORED')}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-secondary hover:text-text-primary transition-colors"
          >
            <EyeOff className="w-3.5 h-3.5" />
            <span>{isIgnored ? 'Re-open' : 'Ignore (False Positive)'}</span>
          </button>

          {/* Primary Remediation CTA */}
          <button
            onClick={() => onOpenRemediation(finding)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-bold font-mono transition-colors shadow-subtle"
          >
            <Sparkles className="w-3.5 h-3.5 fill-current" />
            <span>Remediate with AI</span>
          </button>
        </div>
      </div>

      {/* Main Inspector Details */}
      <div className="p-6 space-y-6 max-w-4xl">
        {/* Status banner if already remediated */}
        {isRemediated && (
          <div className="p-3 rounded bg-accent-primary/10 border border-accent-primary/30 text-accent-primary text-xs font-mono flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-accent-primary" />
              <span>Vulnerability resolved via atomic patch & verified by fresh security rescan.</span>
            </div>
            <button
              onClick={() => onMarkStatus(finding.id, 'OPEN')}
              className="text-[11px] underline hover:text-accent-primary-hover"
            >
              Re-open finding
            </button>
          </div>
        )}

        {/* 1. Vulnerability Overview */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs font-mono text-text-muted">
            <span className="text-accent-secondary uppercase font-semibold">{finding.type}</span>
            <span>•</span>
            <span>Detected: {new Date(finding.detectedAt).toLocaleString()}</span>
          </div>
          <h2 className="text-lg font-bold text-text-primary tracking-tight">
            {finding.name}
          </h2>
          <p className="text-xs text-text-secondary leading-relaxed">
            {finding.description}
          </p>
        </div>

        {/* Technical Metadata Ribbon */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 font-mono text-xs">
          <div className="p-2.5 rounded bg-bg-secondary border border-border">
            <span className="text-[10px] text-text-muted uppercase">Rule ID</span>
            <div className="font-semibold text-text-primary mt-0.5">{finding.ruleId}</div>
          </div>
          <div className="p-2.5 rounded bg-bg-secondary border border-border">
            <span className="text-[10px] text-text-muted uppercase">CWE Reference</span>
            <div className="font-semibold text-accent-secondary mt-0.5 flex items-center gap-1">
              <span>{finding.cwe}</span>
              <a
                href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                target="_blank"
                rel="noreferrer"
                className="hover:text-text-primary"
              >
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
          <div className="p-2.5 rounded bg-bg-secondary border border-border">
            <span className="text-[10px] text-text-muted uppercase">CVSS 3.1 Score</span>
            <div className="font-semibold text-severity-critical mt-0.5">
              {finding.cvss ? `${finding.cvss} / 10.0` : 'N/A'}
            </div>
          </div>
          <div className="p-2.5 rounded bg-bg-secondary border border-border">
            <span className="text-[10px] text-text-muted uppercase">Language</span>
            <div className="font-semibold text-text-primary mt-0.5 uppercase">
              {finding.language}
            </div>
          </div>
        </div>

        {/* 2. Why this is dangerous */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-text-primary uppercase tracking-wider flex items-center gap-1.5 font-mono">
            <AlertTriangle className="w-3.5 h-3.5 text-severity-high" />
            <span>Why This Is Dangerous</span>
          </h3>
          <div className="p-3.5 rounded bg-bg-secondary border border-border text-xs text-text-secondary leading-relaxed">
            {finding.whyDangerous || finding.description}
          </div>
        </div>

        {/* 3 & 4. Exact affected file, line & Syntax-highlighted Code Snippet */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-text-primary uppercase tracking-wider flex items-center gap-1.5 font-mono">
              <FileCode className="w-3.5 h-3.5 text-accent-secondary" />
              <span>Vulnerable Code Snippet</span>
            </h3>
            <span className="font-mono text-[11px] text-text-muted">
              Line {finding.line}
            </span>
          </div>

          <CodeViewer
            filePath={finding.file}
            snippet={finding.snippet}
            language={finding.language}
          />
        </div>

        {/* 7. Potential Impact */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-text-primary uppercase tracking-wider flex items-center gap-1.5 font-mono">
            <ShieldAlert className="w-3.5 h-3.5 text-severity-critical" />
            <span>Potential Impact</span>
          </h3>
          <div className="p-3.5 rounded bg-bg-secondary border border-border text-xs text-text-secondary leading-relaxed">
            {finding.impact}
          </div>
        </div>

        {/* 8. Recommended Remediation */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-text-primary uppercase tracking-wider flex items-center gap-1.5 font-mono">
            <CheckCircle2 className="w-3.5 h-3.5 text-accent-primary" />
            <span>Recommended Remediation</span>
          </h3>
          <div className="p-3.5 rounded bg-bg-secondary border border-border text-xs text-text-secondary leading-relaxed space-y-2">
            <p>{finding.remediation}</p>
            <div className="pt-2">
              <button
                onClick={() => onOpenRemediation(finding)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-accent-primary/10 border border-accent-primary/30 text-accent-primary hover:bg-accent-primary/20 text-xs font-mono font-semibold transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Open AI Patch Diff & Fix Plan</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
