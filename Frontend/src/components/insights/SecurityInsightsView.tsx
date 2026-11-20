import React, { useState, useEffect } from 'react';
import { 
  TrendingUp, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  CheckCircle2, 
  RotateCw, 
  FileCode, 
  Lightbulb, 
  BarChart3, 
  ArrowRight,
  Code2,
  Calendar
} from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface SecurityInsightsViewProps {
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const SecurityInsightsView: React.FC<SecurityInsightsViewProps> = ({ onShowToast }) => {
  const [timeRange, setTimeRange] = useState<number>(30); // 7, 30, 90 days
  const [loading, setLoading] = useState(false);

  // Fallback / Demonstration state
  const [overview, setOverview] = useState({
    securityScore: 84,
    gateStatus: 'BLOCKED_IN_CI',
    criticalFindings: 2,
    highFindings: 4,
    resolvedFindings: 38,
    reopenedFindings: 3,
    fixRatePercentage: 86.4,
    avgRemediationTimeHours: 4.8
  });

  const [recurringMistakes, setRecurringMistakes] = useState([
    {
      rule_id: 'INJ-001',
      name: 'SQL Injection via String Interpolation',
      cwe: 'CWE-89',
      count: 14,
      reopened_count: 2,
      affected_files: ['backend/api/user_controller.py', 'backend/reports/query.py'],
      observation: 'Dynamic SQL query constructed with Python f-strings without query parameterization.',
      recommendation: 'Adopt parameterized queries (cursor.execute("SELECT ... %s", (val,))) and introduce ORM abstraction.',
      action_item: 'Add lint rule prohibiting raw SQL string formatting in backend routes.'
    },
    {
      rule_id: 'SEC-001',
      name: 'Hardcoded AWS Access Key',
      cwe: 'CWE-798',
      count: 9,
      reopened_count: 0,
      affected_files: ['backend/auth/aws_client.py', 'scripts/deploy_s3.py'],
      observation: 'AWS Access Key IDs committed directly into version control.',
      recommendation: 'Migrate static credentials to AWS IAM roles or AWS Secrets Manager.',
      action_item: 'Configure pre-commit secret scanning hooks for all repository contributors.'
    },
    {
      rule_id: 'DOM-001',
      name: 'Cross-Site Scripting via dangerouslySetInnerHTML',
      cwe: 'CWE-79',
      count: 6,
      reopened_count: 1,
      affected_files: ['frontend/src/components/MarkdownRenderer.tsx'],
      observation: 'Raw unescaped markup rendered directly into React DOM without DOMPurify.',
      recommendation: 'Wrap all raw HTML properties in DOMPurify.sanitize().',
      action_item: 'Introduce shared SafeHTMLComponent to eliminate raw dangerouslySetInnerHTML calls.'
    }
  ]);

  const trends = [
    { date: 'Nov 01', discovered: 4, resolved: 6, critical: 1, high: 2 },
    { date: 'Nov 05', discovered: 8, resolved: 7, critical: 2, high: 3 },
    { date: 'Nov 10', discovered: 3, resolved: 9, critical: 0, high: 1 },
    { date: 'Nov 15', discovered: 6, resolved: 8, critical: 1, high: 2 },
    { date: 'Nov 20', discovered: 2, resolved: 8, critical: 1, high: 1 }
  ];

  useEffect(() => {
    // Attempt to fetch live analytics from API
    const fetchAnalytics = async () => {
      try {
        const res = await fetch(`/api/analytics/overview?days=${timeRange}`);
        if (res.ok) {
          const data = await res.json();
          setOverview({
            securityScore: data.security_score,
            gateStatus: data.gate_status,
            criticalFindings: data.critical_findings,
            highFindings: data.high_findings,
            resolvedFindings: data.resolved_findings,
            reopenedFindings: data.reopened_findings,
            fixRatePercentage: data.fix_rate_percentage,
            avgRemediationTimeHours: data.avg_remediation_time_hours
          });
        }
        const recRes = await fetch('/api/analytics/recurring');
        if (recRes.ok) {
          const recData = await recRes.json();
          if (recData.length > 0) {
            setRecurringMistakes(recData);
          }
        }
      } catch {
        // Fallback to demonstration insights
      }
    };
    fetchAnalytics();
  }, [timeRange]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header & Time Filter */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs uppercase tracking-wider text-text-muted">
              Security Intelligence
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
              Recurrence Analytics
            </span>
          </div>
          <h1 className="text-xl font-bold text-text-primary mt-1">
            Security Insights & Insecure Pattern Detection
          </h1>
          <p className="text-xs text-text-secondary mt-1 max-w-3xl leading-relaxed">
            Synthesizes historical findings across repositories to detect recurring insecure coding mistakes, calculate remediation velocity, and generate actionable engineering remedies.
          </p>
        </div>

        {/* Time-Range Selector */}
        <div className="flex items-center gap-1.5 p-1 rounded bg-bg-secondary border border-border font-mono text-xs">
          {[7, 30, 90].map(d => (
            <button
              key={d}
              onClick={() => {
                setTimeRange(d);
                onShowToast("Filter Updated", `Analyzing last ${d} days of security records`, "info");
              }}
              className={`px-3 py-1.5 rounded transition-colors ${
                timeRange === d
                  ? 'bg-bg-elevated text-text-primary font-semibold shadow-sm border border-border'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Last {d}d
            </button>
          ))}
        </div>
      </div>

      {/* KPI Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
        <div className="p-4 rounded bg-bg-secondary border border-border">
          <div className="text-[10px] uppercase text-text-muted">Posture Health Score</div>
          <div className="text-2xl font-bold text-accent-primary mt-1 flex items-baseline gap-1">
            <span>{overview.securityScore}</span>
            <span className="text-xs text-text-muted">/ 100</span>
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            Gate: {overview.gateStatus === 'SAFE_TO_SHIP' ? 'Pass (Unblocked)' : 'Blocked in CI'}
          </div>
        </div>

        <div className="p-4 rounded bg-bg-secondary border border-border">
          <div className="text-[10px] uppercase text-text-muted">Fix Velocity (MTTR)</div>
          <div className="text-2xl font-bold text-accent-secondary mt-1 flex items-baseline gap-1">
            <span>{overview.avgRemediationTimeHours}</span>
            <span className="text-xs text-text-muted">hours</span>
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            Avg time to verify and close finding
          </div>
        </div>

        <div className="p-4 rounded bg-bg-secondary border border-border">
          <div className="text-[10px] uppercase text-text-muted">Overall Resolution Rate</div>
          <div className="text-2xl font-bold text-text-primary mt-1">
            {overview.fixRatePercentage}%
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            {overview.resolvedFindings} resolved findings
          </div>
        </div>

        <div className="p-4 rounded bg-bg-secondary border border-border">
          <div className="text-[10px] uppercase text-text-muted">Reopened Regressions</div>
          <div className="text-2xl font-bold text-severity-high mt-1">
            {overview.reopenedFindings}
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            Findings re-detected after fix
          </div>
        </div>
      </div>

      {/* Trend Visualizer */}
      <div className="p-5 rounded bg-bg-secondary border border-border space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-bold text-text-primary uppercase tracking-wider flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-accent-primary" />
            <span>Vulnerability Discovery vs. Resolution Velocity</span>
          </h2>
          <span className="text-[10px] font-mono text-text-muted">Normalized Timeline</span>
        </div>

        <div className="grid grid-cols-5 gap-2 pt-2">
          {trends.map(t => (
            <div key={t.date} className="p-3 rounded bg-bg-main border border-border text-center space-y-2">
              <div className="font-mono text-xs text-text-muted">{t.date}</div>
              <div className="flex items-center justify-center gap-3 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-text-muted block">Found</span>
                  <span className="font-bold text-severity-critical">+{t.discovered}</span>
                </div>
                <div className="h-6 w-px bg-border" />
                <div>
                  <span className="text-[10px] text-text-muted block">Fixed</span>
                  <span className="font-bold text-accent-primary">-{t.resolved}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recurring Mistakes & Actionable Recommendations */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-mono font-bold text-text-primary uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-severity-high" />
            <span>Top Recurring Insecure Coding Patterns & Root Causes</span>
          </h2>
          <span className="text-[10px] font-mono text-text-muted">
            Aggregated from historical scan occurrences
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {recurringMistakes.map(m => (
            <div key={m.rule_id} className="p-4 rounded bg-bg-secondary border border-border flex flex-col justify-between space-y-3">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-text-primary">
                    {m.rule_id}
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-severity-critical/10 text-severity-critical border border-severity-critical/20">
                    {m.count} Occurrences
                  </span>
                </div>

                <div className="font-semibold text-text-primary text-xs">
                  {m.name}
                </div>

                <p className="text-xs text-text-secondary leading-relaxed">
                  {m.observation}
                </p>
              </div>

              {/* Actionable Recommendation Box */}
              <div className="p-3 rounded bg-bg-main border border-border text-[11px] font-mono space-y-1.5">
                <div className="flex items-center gap-1.5 text-accent-primary font-bold">
                  <Lightbulb className="w-3.5 h-3.5" />
                  <span>Actionable Recommendation:</span>
                </div>
                <p className="text-text-muted leading-relaxed">
                  {m.recommendation}
                </p>
                <div className="pt-1.5 border-t border-border/60 text-accent-secondary">
                  <strong>Action item:</strong> {m.action_item}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Team Language Exposure */}
      <div className="p-5 rounded bg-bg-secondary border border-border space-y-3">
        <h3 className="text-xs font-mono font-bold text-text-primary uppercase tracking-wider flex items-center gap-2">
          <Code2 className="w-4 h-4 text-accent-secondary" />
          <span>Ecosystem & Language Vulnerability Distribution</span>
        </h3>
        <p className="text-xs text-text-secondary leading-relaxed">
          Aggregates risks by tech stack without individual developer blame leaderboards.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 font-mono text-xs">
          <div className="p-3 rounded bg-bg-main border border-border space-y-1">
            <div className="text-text-primary font-bold">Python Stack (58% of repo files)</div>
            <div className="text-text-muted text-[11px]">2 Criticals • 3.8 hrs avg MTTR</div>
            <div className="text-accent-primary text-[10px]">Primary risk: SQL interpolation & subprocess</div>
          </div>

          <div className="p-3 rounded bg-bg-main border border-border space-y-1">
            <div className="text-text-primary font-bold">TypeScript / React (34% of files)</div>
            <div className="text-text-muted text-[11px]">1 Critical • 4.5 hrs avg MTTR</div>
            <div className="text-accent-primary text-[10px]">Primary risk: DOM sinks without DOMPurify</div>
          </div>

          <div className="p-3 rounded bg-bg-main border border-border space-y-1">
            <div className="text-text-primary font-bold">Package Manifests (8% of files)</div>
            <div className="text-text-muted text-[11px]">0 Criticals • 1.2 hrs avg MTTR</div>
            <div className="text-accent-primary text-[10px]">Primary risk: Outdated CVE dependencies</div>
          </div>
        </div>
      </div>
    </div>
  );
};
