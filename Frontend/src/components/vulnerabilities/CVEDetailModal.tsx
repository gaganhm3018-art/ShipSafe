import React from 'react';
import { CVEDependencyFinding } from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { 
  X, 
  ExternalLink, 
  ShieldAlert, 
  Package, 
  Layers, 
  ArrowRight, 
  CheckCircle2, 
  FileCode,
  Terminal,
  Info
} from 'lucide-react';

interface CVEDetailModalProps {
  vulnerability: CVEDependencyFinding | null;
  isOpen: boolean;
  onClose: () => void;
}

export const CVEDetailModal: React.FC<CVEDetailModalProps> = ({
  vulnerability,
  isOpen,
  onClose
}) => {
  if (!isOpen || !vulnerability) return null;

  const {
    vulnerabilityId,
    cveId,
    ghsaId,
    packageName,
    installedVersion,
    ecosystem,
    manifestFile,
    isDirect,
    severity,
    cvssScore,
    cvssVector,
    summary,
    details,
    affectedRange,
    fixedVersion,
    references
  } = vulnerability;

  const upgradeCommand = ecosystem === 'PyPI'
    ? (fixedVersion ? `pip install --upgrade "${packageName}>=${fixedVersion}"` : `pip install --upgrade ${packageName}`)
    : (fixedVersion ? `npm install ${packageName}@^${fixedVersion}` : `npm update ${packageName}`);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="bg-bg-secondary border border-border rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="p-5 border-b border-border flex items-start justify-between bg-bg-elevated/40">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-base font-bold text-text-primary">
                {vulnerabilityId}
              </span>
              <SeverityBadge severity={severity} size="sm" />
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-secondary/10 text-accent-secondary border border-accent-secondary/20">
                {ecosystem}
              </span>
            </div>
            <div className="flex items-center gap-3 text-xs text-text-muted font-mono">
              <span className="flex items-center gap-1">
                <Package className="w-3.5 h-3.5 text-text-muted" />
                Package: <strong className="text-text-primary">{packageName}</strong>
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <Layers className="w-3.5 h-3.5 text-text-muted" />
                Installed: <strong className="text-text-primary">{installedVersion}</strong>
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <FileCode className="w-3.5 h-3.5 text-text-muted" />
                {manifestFile}
              </span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-bg-elevated text-text-muted hover:text-text-primary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-text-secondary">
          {/* Summary Banner */}
          <div className="p-3.5 rounded-lg bg-bg-elevated border border-border space-y-1.5">
            <div className="font-semibold text-text-primary text-sm flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-severity-critical" />
              {summary || `Vulnerability in ${packageName}`}
            </div>
            {cveId && cveId !== vulnerabilityId && (
              <div className="text-[11px] font-mono text-text-muted">
                Official CVE: <span className="text-text-primary">{cveId}</span>
                {ghsaId && ghsaId !== vulnerabilityId && (
                  <> &nbsp;|&nbsp; GitHub Security Advisory: <span className="text-text-primary">{ghsaId}</span></>
                )}
              </div>
            )}
          </div>

          {/* CVSS & Version Matrix Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Version Impact Card */}
            <div className="p-4 rounded-lg bg-bg-elevated/50 border border-border space-y-3">
              <div className="text-[11px] font-mono uppercase tracking-wider text-text-muted font-medium">
                Version Analysis
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-text-muted">Installed Version:</span>
                  <span className="font-mono font-medium px-2 py-0.5 rounded bg-severity-critical/10 text-severity-critical border border-severity-critical/20">
                    {installedVersion}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-text-muted">Affected Range:</span>
                  <span className="font-mono font-medium text-text-primary">
                    {affectedRange || 'All versions'}
                  </span>
                </div>

                <div className="flex items-center justify-between pt-1 border-t border-border/60">
                  <span className="text-text-muted font-medium">Patched / Fixed In:</span>
                  {fixedVersion ? (
                    <span className="font-mono font-semibold px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20 flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5 text-accent-primary" />
                      &gt;= {fixedVersion}
                    </span>
                  ) : (
                    <span className="text-text-muted font-mono">No patch published</span>
                  )}
                </div>
              </div>
            </div>

            {/* CVSS Severity Card */}
            <div className="p-4 rounded-lg bg-bg-elevated/50 border border-border space-y-3">
              <div className="text-[11px] font-mono uppercase tracking-wider text-text-muted font-medium">
                Vulnerability Metrics (CVSS v3.1)
              </div>
              
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-lg bg-bg-secondary border border-border flex flex-col items-center justify-center">
                  <span className="text-lg font-bold font-mono text-text-primary">
                    {cvssScore !== null && cvssScore !== undefined ? cvssScore.toFixed(1) : 'N/A'}
                  </span>
                  <span className="text-[9px] font-mono uppercase text-text-muted">
                    Base Score
                  </span>
                </div>

                <div className="space-y-1 min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={severity} size="sm" />
                    <span className="text-text-muted text-[11px]">Severity Rating</span>
                  </div>
                  {cvssVector && (
                    <div className="font-mono text-[10px] text-text-muted truncate" title={cvssVector}>
                      Vector: {cvssVector}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Technical Description */}
          {details && (
            <div className="space-y-2">
              <div className="text-[11px] font-mono uppercase tracking-wider text-text-muted font-medium">
                Advisory Details
              </div>
              <div className="p-3.5 rounded bg-bg-sidebar border border-border font-mono text-[11px] leading-relaxed whitespace-pre-wrap max-h-48 overflow-y-auto text-text-secondary">
                {details}
              </div>
            </div>
          )}

          {/* Remediation Action */}
          <div className="p-4 rounded-lg bg-accent-primary/5 border border-accent-primary/20 space-y-2.5">
            <div className="font-semibold text-text-primary flex items-center gap-2 text-xs">
              <Terminal className="w-4 h-4 text-accent-primary" />
              Recommended Remediation
            </div>
            <p className="text-[11px] text-text-secondary">
              {fixedVersion 
                ? `Upgrade ${packageName} to version ${fixedVersion} or higher in your manifest / lockfile.`
                : `No official fixed version has been released yet. Monitor vendor security updates or apply mitigation controls.`}
            </p>
            
            <div className="flex items-center justify-between p-2.5 rounded bg-bg-secondary border border-border font-mono text-xs">
              <code className="text-accent-primary select-all">{upgradeCommand}</code>
              <button
                onClick={() => navigator.clipboard?.writeText(upgradeCommand)}
                className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-bg-elevated hover:bg-bg-hover text-text-muted hover:text-text-primary border border-border"
              >
                Copy
              </button>
            </div>
          </div>

          {/* External References */}
          {references && references.length > 0 && (
            <div className="space-y-2">
              <div className="text-[11px] font-mono uppercase tracking-wider text-text-muted font-medium">
                Official Advisory References
              </div>
              <div className="space-y-1.5 max-h-36 overflow-y-auto">
                {references.map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-2 rounded bg-bg-elevated/40 hover:bg-bg-elevated border border-border hover:border-border-active transition-colors group"
                  >
                    <span className="font-mono text-[11px] text-text-secondary group-hover:text-text-primary truncate">
                      {ref.url}
                    </span>
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono text-accent-secondary flex-shrink-0 ml-2">
                      {ref.type} <ExternalLink className="w-3 h-3" />
                    </span>
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-border flex items-center justify-between bg-bg-elevated/30">
          <div className="text-[11px] font-mono text-text-muted flex items-center gap-1">
            <Info className="w-3.5 h-3.5" />
            Vulnerability sourced in real-time from OSV.dev database
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-mono font-medium rounded bg-bg-elevated hover:bg-bg-hover text-text-primary border border-border"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
