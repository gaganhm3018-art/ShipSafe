import React, { useState, useEffect } from 'react';
import { 
  CVEScanResponse, 
  CVEDependencyFinding,
  Severity 
} from '../../types/security';
import { DependencyRiskTable } from './DependencyRiskTable';
import { CVEDetailModal } from './CVEDetailModal';
import { 
  Radio, 
  RefreshCw, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Clock, 
  DatabaseZap, 
  AlertOctagon,
  Layers,
  Sparkles
} from 'lucide-react';

interface CVEIntelligenceViewProps {
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const CVEIntelligenceView: React.FC<CVEIntelligenceViewProps> = ({ onShowToast }) => {
  const [data, setData] = useState<CVEScanResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedVuln, setSelectedVuln] = useState<CVEDependencyFinding | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  // Fetch initial CVE findings
  const fetchCVEData = async (force: boolean = false) => {
    try {
      if (force) setRefreshing(true);
      else setLoading(true);
      setError(null);

      const endpoint = force ? '/api/cve/refresh' : '/api/cve/findings';
      const method = force ? 'POST' : 'GET';
      const options: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json' },
        ...(force ? { body: JSON.stringify({ target_path: '.', force_refresh: true }) } : {})
      };

      const res = await fetch(endpoint, options);
      if (!res.ok) {
        throw new Error(`Failed to query CVE Intelligence service: HTTP ${res.status}`);
      }

      const json: CVEScanResponse = await res.json();
      setData(json);

      if (force) {
        onShowToast(
          'Intelligence Refreshed',
          `Scanned ${json.summary.totalDependencies} dependencies. Found ${json.summary.vulnerableDependencies} vulnerable packages.`,
          json.summary.vulnerableDependencies > 0 ? 'info' : 'success'
        );
      }
    } catch (err: any) {
      setError(err.message || 'Could not connect to CVE intelligence service');
      onShowToast('CVE Service Error', err.message, 'error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchCVEData(false);
  }, []);

  const handleSelectVulnerability = (vuln: CVEDependencyFinding) => {
    setSelectedVuln(vuln);
    setIsModalOpen(true);
  };

  const summary = data?.summary || {
    totalDependencies: 0,
    vulnerableDependencies: 0,
    safeDependencies: 0,
    unknownDependencies: 0,
    totalVulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold font-mono tracking-tight text-text-primary flex items-center gap-2">
              Real-Time CVE Intelligence
            </h1>
            <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-primary animate-pulse" />
              OSV.dev Live Feed
            </span>
            {data?.isCached && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-bg-elevated text-text-muted border border-border">
                Cached ({data.cacheAgeSeconds}s ago)
              </span>
            )}
          </div>
          <p className="text-xs text-text-muted mt-1">
            Continuous real-time dependency vulnerability stream across Python (PyPI) and JavaScript (npm) lockfiles.
          </p>
        </div>

        {/* Refresh Action */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchCVEData(true)}
            disabled={loading || refreshing}
            className="flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono font-medium bg-bg-elevated hover:bg-bg-hover text-text-primary border border-border hover:border-border-active transition-colors disabled:opacity-50 shadow-subtle"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-accent-primary ${refreshing ? 'animate-spin' : ''}`} />
            <span>{refreshing ? 'Querying OSV.dev...' : 'Refresh Intelligence'}</span>
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-lg bg-severity-critical/10 border border-severity-critical/30 flex items-center justify-between text-xs text-severity-critical">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => fetchCVEData(true)}
            className="px-2.5 py-1 rounded bg-severity-critical/20 hover:bg-severity-critical/30 font-mono text-[11px] underline"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Dependencies */}
        <div className="p-3.5 rounded-lg bg-bg-secondary border border-border space-y-1">
          <div className="flex items-center justify-between text-text-muted">
            <span className="text-[10px] uppercase font-mono tracking-wider">Dependencies</span>
            <Layers className="w-3.5 h-3.5 text-text-muted" />
          </div>
          <div className="text-2xl font-mono font-bold text-text-primary">
            {loading ? '—' : summary.totalDependencies}
          </div>
          <div className="text-[10px] text-text-muted font-mono truncate">
            {data?.ecosystemsFound?.join(', ') || 'PyPI & npm'}
          </div>
        </div>

        {/* Vulnerable Dependencies */}
        <div className="p-3.5 rounded-lg bg-bg-secondary border border-severity-critical/30 space-y-1">
          <div className="flex items-center justify-between text-severity-critical">
            <span className="text-[10px] uppercase font-mono tracking-wider">Vulnerable</span>
            <AlertOctagon className="w-3.5 h-3.5 text-severity-critical" />
          </div>
          <div className="text-2xl font-mono font-bold text-severity-critical">
            {loading ? '—' : summary.vulnerableDependencies}
          </div>
          <div className="text-[10px] text-text-muted font-mono">
            {summary.totalVulnerabilities} total advisories
          </div>
        </div>

        {/* Critical CVEs */}
        <div className="p-3.5 rounded-lg bg-bg-secondary border border-border space-y-1">
          <div className="flex items-center justify-between text-severity-critical">
            <span className="text-[10px] uppercase font-mono tracking-wider">Critical CVEs</span>
            <span className="w-2 h-2 rounded-full bg-severity-critical" />
          </div>
          <div className="text-2xl font-mono font-bold text-severity-critical">
            {loading ? '—' : summary.critical}
          </div>
          <div className="text-[10px] text-text-muted font-mono">
            CVSS 9.0 – 10.0
          </div>
        </div>

        {/* High CVEs */}
        <div className="p-3.5 rounded-lg bg-bg-secondary border border-border space-y-1">
          <div className="flex items-center justify-between text-severity-high">
            <span className="text-[10px] uppercase font-mono tracking-wider">High CVEs</span>
            <span className="w-2 h-2 rounded-full bg-severity-high" />
          </div>
          <div className="text-2xl font-mono font-bold text-severity-high">
            {loading ? '—' : summary.high}
          </div>
          <div className="text-[10px] text-text-muted font-mono">
            CVSS 7.0 – 8.9
          </div>
        </div>

        {/* Medium & Low */}
        <div className="p-3.5 rounded-lg bg-bg-secondary border border-border space-y-1">
          <div className="flex items-center justify-between text-severity-medium">
            <span className="text-[10px] uppercase font-mono tracking-wider">Medium / Low</span>
            <span className="w-2 h-2 rounded-full bg-severity-medium" />
          </div>
          <div className="text-2xl font-mono font-bold text-severity-medium">
            {loading ? '—' : (summary.medium + summary.low)}
          </div>
          <div className="text-[10px] text-text-muted font-mono">
            {summary.medium} Med, {summary.low} Low
          </div>
        </div>

        {/* Clean Dependencies */}
        <div className="p-3.5 rounded-lg bg-bg-secondary border border-accent-primary/20 space-y-1">
          <div className="flex items-center justify-between text-accent-primary">
            <span className="text-[10px] uppercase font-mono tracking-wider">Safe Packages</span>
            <ShieldCheck className="w-3.5 h-3.5 text-accent-primary" />
          </div>
          <div className="text-2xl font-mono font-bold text-accent-primary">
            {loading ? '—' : summary.safeDependencies}
          </div>
          <div className="text-[10px] text-text-muted font-mono">
            0 known advisories
          </div>
        </div>
      </div>

      {/* Main Table View */}
      {loading ? (
        <div className="p-12 rounded-lg bg-bg-secondary border border-border flex flex-col items-center justify-center gap-3 text-text-muted">
          <RefreshCw className="w-6 h-6 text-accent-primary animate-spin" />
          <div className="text-xs font-mono">Querying OSV.dev vulnerability database across lockfiles...</div>
        </div>
      ) : (
        <DependencyRiskTable
          findings={data?.findings || []}
          dependencies={data?.dependencies || []}
          onSelectVulnerability={handleSelectVulnerability}
        />
      )}

      {/* CVE Detail Inspection Modal */}
      <CVEDetailModal
        vulnerability={selectedVuln}
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setSelectedVuln(null);
        }}
      />
    </div>
  );
};
