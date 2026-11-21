import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  ArrowRight, 
  GitBranch, 
  FolderGit2, 
  ExternalLink,
  CheckCircle2,
  Lock,
  Play
} from 'lucide-react';
import { SecurityFinding, ProjectRepo, SecurityActivity, Severity } from '../../types/security';
import { SecurityMetric } from '../common/SecurityMetric';
import { SeverityBadge } from '../common/SeverityBadge';

interface OverviewDashboardProps {
  findings: SecurityFinding[];
  projects: ProjectRepo[];
  activities: SecurityActivity[];
  onSelectFinding: (f: SecurityFinding) => void;
  onNavigateToFindings: () => void;
  onNavigateToProjects: () => void;
  onStartScan: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  findings,
  projects,
  activities,
  onSelectFinding,
  onNavigateToFindings,
  onNavigateToProjects,
  onStartScan
}) => {
  const openFindings = findings.filter(f => f.status === 'OPEN');
  const criticalCount = openFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = openFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = openFindings.filter(f => f.severity === 'LOW').length;
  const infoCount = openFindings.filter(f => f.severity === 'INFORMATIONAL').length;

  const totalOpen = openFindings.length;
  const fixedCount = findings.filter(f => f.status === 'REMEDIATED').length + 42;

  const isSafe = criticalCount === 0 && highCount === 0;

  // Priority Actions: Critical & High findings that need immediate attention
  const priorityFindings = openFindings
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 3);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* 1. Core Triad: Is my code safe? What are the risks? What should I do next? */}
      <div className={`p-4 rounded border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 transition-colors ${
        isSafe 
          ? 'bg-accent-primary/5 border-accent-primary/30' 
          : 'bg-severity-critical/10 border-severity-critical/30'
      }`}>
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded mt-0.5 ${
            isSafe ? 'bg-accent-primary/20 text-accent-primary' : 'bg-severity-critical/20 text-severity-critical'
          }`}>
            {isSafe ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-semibold uppercase tracking-wider text-text-muted">
                Deployment Gate Status
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                isSafe ? 'bg-accent-primary/20 text-accent-primary' : 'bg-severity-critical/20 text-severity-critical'
              }`}>
                {isSafe ? 'Safe to Ship' : 'Blocked in CI/CD'}
              </span>
            </div>
            <h1 className="text-base font-bold text-text-primary mt-0.5">
              {isSafe
                ? "All critical security policies satisfied across workspace repositories."
                : `${criticalCount} Critical and ${highCount} High vulnerabilities are currently blocking production releases.`}
            </h1>
            <p className="text-xs text-text-secondary mt-1 max-w-3xl leading-relaxed">
              {isSafe
                ? "No active rule violations detected. Automated pre-commit hooks and GitHub Actions pass without warnings."
                : "Deterministic rules detected credentials and unescaped injection sinks. Resolve priority findings below or review suggested AI patches to unblock CI."}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-shrink-0 self-end md:self-center">
          <button
            onClick={onStartScan}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-text-primary transition-colors"
          >
            <Play className="w-3.5 h-3.5 text-accent-primary" />
            <span>Rescan All</span>
          </button>
          {!isSafe && (
            <button
              onClick={onNavigateToFindings}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-severity-critical hover:bg-severity-critical/90 text-white text-xs font-semibold font-mono transition-colors shadow-subtle"
            >
              <span>Remediate Risks</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* 2. Security Posture Summary (Section 5.A) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <SecurityMetric
          label="Repositories"
          value={projects.length}
          subtext="Active in workspace"
          trend="neutral"
        />
        <SecurityMetric
          label="Open Vulnerabilities"
          value={totalOpen}
          trend={totalOpen > 0 ? "danger" : "safe"}
          trendText={totalOpen > 0 ? "Needs action" : "Zero open"}
          subtext="Across all branches"
        />
        <SecurityMetric
          label="Critical & High"
          value={`${criticalCount + highCount}`}
          trend={criticalCount > 0 ? "danger" : "warning"}
          trendText={`${criticalCount} Crit / ${highCount} High`}
          subtext="Violating CI fail gate"
        />
        <SecurityMetric
          label="Vulnerabilities Fixed"
          value={fixedCount}
          trend="safe"
          trendText="+14 this sprint"
          subtext="Verified via rescan"
        />
        <SecurityMetric
          label="Latest Scan"
          value="12m ago"
          subtext="SCAN-2026-089 (CI)"
          trend="neutral"
        />
      </div>

      {/* 3. Main Content Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2 cols wide): Priority Actions + Severity Dist + Projects */}
        <div className="lg:col-span-2 space-y-6">
          {/* E. Priority Actions (Section 5.E) */}
          <div className="bg-bg-secondary border border-border rounded overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between bg-bg-elevated/30">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-severity-high" />
                <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                  Priority Actions (Needs Immediate Developer Attention)
                </h2>
              </div>
              <button
                onClick={onNavigateToFindings}
                className="text-xs font-mono text-accent-secondary hover:underline flex items-center gap-1"
              >
                <span>View all ({totalOpen})</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="divide-y divide-border">
              {priorityFindings.map(finding => (
                <div
                  key={finding.id}
                  className="p-4 hover:bg-bg-elevated/40 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <span className="font-mono text-xs font-semibold text-text-primary truncate">
                        {finding.name}
                      </span>
                      <span className="font-mono text-[11px] text-text-muted">
                        [{finding.cwe}]
                      </span>
                    </div>

                    <div className="font-mono text-xs text-text-secondary truncate flex items-center gap-2">
                      <span className="text-text-primary">{finding.file}</span>
                      <span className="text-text-muted">:{finding.line}</span>
                    </div>

                    <p className="text-xs text-text-muted line-clamp-1">
                      {finding.description}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0 self-start md:self-center">
                    <button
                      onClick={() => onSelectFinding(finding)}
                      className="px-3 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs font-mono text-accent-primary font-medium transition-colors"
                    >
                      Review & Fix
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* C. Severity Distribution (Section 5.C) */}
          <div className="bg-bg-secondary border border-border rounded p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                Severity Distribution
              </span>
              <span className="text-xs font-mono text-text-muted">
                {totalOpen} Active Findings
              </span>
            </div>

            {/* Compact bar visualizer */}
            <div className="h-3.5 w-full bg-bg-elevated rounded-sm overflow-hidden flex border border-border/80">
              {criticalCount > 0 && (
                <div 
                  style={{ width: `${(criticalCount / totalOpen) * 100}%` }}
                  className="bg-severity-critical hover:opacity-85 transition-opacity"
                  title={`Critical: ${criticalCount}`}
                />
              )}
              {highCount > 0 && (
                <div 
                  style={{ width: `${(highCount / totalOpen) * 100}%` }}
                  className="bg-severity-high hover:opacity-85 transition-opacity"
                  title={`High: ${highCount}`}
                />
              )}
              {mediumCount > 0 && (
                <div 
                  style={{ width: `${(mediumCount / totalOpen) * 100}%` }}
                  className="bg-severity-medium hover:opacity-85 transition-opacity"
                  title={`Medium: ${mediumCount}`}
                />
              )}
              {lowCount > 0 && (
                <div 
                  style={{ width: `${(lowCount / totalOpen) * 100}%` }}
                  className="bg-severity-low hover:opacity-85 transition-opacity"
                  title={`Low: ${lowCount}`}
                />
              )}
            </div>

            {/* Severity Legend counts */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-1 font-mono text-xs">
              <div className="flex items-center justify-between p-2 rounded bg-bg-elevated/40 border border-border">
                <span className="text-severity-critical flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-severity-critical" />
                  Critical
                </span>
                <span className="font-bold text-text-primary">{criticalCount}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-bg-elevated/40 border border-border">
                <span className="text-severity-high flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-severity-high" />
                  High
                </span>
                <span className="font-bold text-text-primary">{highCount}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-bg-elevated/40 border border-border">
                <span className="text-severity-medium flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-severity-medium" />
                  Medium
                </span>
                <span className="font-bold text-text-primary">{mediumCount}</span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-bg-elevated/40 border border-border">
                <span className="text-severity-low flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-severity-low" />
                  Low
                </span>
                <span className="font-bold text-text-primary">{lowCount}</span>
              </div>
            </div>
          </div>

          {/* D. Recent Projects (Section 5.D) */}
          <div className="bg-bg-secondary border border-border rounded overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between bg-bg-elevated/30">
              <div className="flex items-center gap-2">
                <FolderGit2 className="w-4 h-4 text-accent-secondary" />
                <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                  Monitored Repositories
                </h2>
              </div>
              <button
                onClick={onNavigateToProjects}
                className="text-xs font-mono text-accent-secondary hover:underline flex items-center gap-1"
              >
                <span>Manage all ({projects.length})</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-bg-elevated/40 border-b border-border text-text-muted uppercase text-[10px]">
                  <tr>
                    <th className="py-2.5 px-4 font-medium">Repository</th>
                    <th className="py-2.5 px-4 font-medium">Language</th>
                    <th className="py-2.5 px-4 font-medium">Last Scan</th>
                    <th className="py-2.5 px-4 font-medium">Security Status</th>
                    <th className="py-2.5 px-4 font-medium text-right">Findings</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {projects.map(proj => (
                    <tr key={proj.id} className="hover:bg-bg-elevated/40 transition-colors">
                      <td className="py-3 px-4 font-medium text-text-primary flex items-center gap-2">
                        <FolderGit2 className="w-3.5 h-3.5 text-text-muted" />
                        <span>{proj.name}</span>
                        <span className="text-[10px] text-text-muted font-normal">
                          ({proj.branch})
                        </span>
                      </td>
                      <td className="py-3 px-4 text-text-secondary">
                        <span className="px-1.5 py-0.5 rounded bg-bg-elevated border border-border text-[11px]">
                          {proj.language}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-text-muted">
                        {proj.lastScanned}
                      </td>
                      <td className="py-3 px-4">
                        {proj.status === 'SAFE' && (
                          <span className="inline-flex items-center gap-1 text-accent-primary text-[11px] font-semibold">
                            <CheckCircle2 className="w-3 h-3" /> Clean
                          </span>
                        )}
                        {proj.status === 'AT_RISK' && (
                          <span className="inline-flex items-center gap-1 text-severity-high text-[11px] font-semibold">
                            <AlertTriangle className="w-3 h-3" /> Warnings
                          </span>
                        )}
                        {proj.status === 'BLOCKED' && (
                          <span className="inline-flex items-center gap-1 text-severity-critical text-[11px] font-semibold">
                            <ShieldAlert className="w-3 h-3" /> Blocked CI
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
                          proj.totalFindings > 0 
                            ? 'bg-severity-critical/10 text-severity-critical border-severity-critical/30' 
                            : 'bg-accent-primary/10 text-accent-primary border-accent-primary/30'
                        }`}>
                          {proj.totalFindings}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column (1 col wide): B. Security Activity Timeline (Section 5.B) */}
        <div className="space-y-6">
          <div className="bg-bg-secondary border border-border rounded overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-bg-elevated/30 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-accent-secondary" />
                <h2 className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                  Security Activity Timeline
                </h2>
              </div>
              <span className="font-mono text-[10px] text-text-muted">Live Stream</span>
            </div>

            <div className="p-4 space-y-4">
              {activities.map((act, index) => {
                const isBlocked = act.type === 'COMMIT_BLOCKED';
                const isFixed = act.type === 'FIX_APPLIED';
                const isVuln = act.type === 'VULNERABILITY_FOUND';

                return (
                  <div key={act.id} className="relative pl-6 pb-2 last:pb-0">
                    {/* Vertical timeline line */}
                    {index < activities.length - 1 && (
                      <div className="absolute left-2.5 top-5 bottom-0 w-px bg-border" />
                    )}

                    {/* Timeline bullet */}
                    <div className={`absolute left-1 top-1 w-3 h-3 rounded-full border-2 border-bg-secondary ${
                      isBlocked ? 'bg-severity-critical' : isFixed ? 'bg-accent-primary' : isVuln ? 'bg-severity-high' : 'bg-accent-secondary'
                    }`} />

                    <div className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-text-primary">
                          {act.title}
                        </span>
                        <span className="font-mono text-[10px] text-text-muted">
                          {act.timestamp}
                        </span>
                      </div>
                      <p className="text-xs text-text-secondary leading-relaxed">
                        {act.description}
                      </p>
                      <div className="flex items-center gap-2 text-[10px] font-mono text-text-muted pt-0.5">
                        <span className="text-accent-secondary">{act.repository}</span>
                        <span>•</span>
                        <span>{act.actor}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Security Tip Card */}
          <div className="p-4 rounded border border-border bg-bg-secondary/60 space-y-2 text-xs">
            <div className="flex items-center gap-1.5 font-semibold text-text-primary font-mono">
              <Lock className="w-3.5 h-3.5 text-accent-primary" />
              <span>Deterministic Enforcement</span>
            </div>
            <p className="text-text-secondary leading-relaxed text-[11px]">
              ShipSafe uses zero-hallucination deterministic AST rules and entropy analysis to detect secrets and injection sinks. The LLM is invoked solely to explain verified vulnerabilities and craft Git-style patch diffs.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
