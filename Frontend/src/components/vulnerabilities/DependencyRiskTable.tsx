import React, { useState, useMemo } from 'react';
import { 
  CVEDependencyFinding, 
  CVEDependencyItem, 
  Severity 
} from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { 
  Search, 
  Filter, 
  AlertTriangle, 
  CheckCircle2, 
  HelpCircle, 
  ExternalLink, 
  ShieldAlert,
  FileCode,
  PackageCheck
} from 'lucide-react';

interface DependencyRiskTableProps {
  findings: CVEDependencyFinding[];
  dependencies: CVEDependencyItem[];
  onSelectVulnerability: (vuln: CVEDependencyFinding) => void;
}

export const DependencyRiskTable: React.FC<DependencyRiskTableProps> = ({
  findings,
  dependencies,
  onSelectVulnerability
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [ecosystemFilter, setEcosystemFilter] = useState<'ALL' | 'PyPI' | 'npm'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'VULNERABLE' | 'SAFE' | 'UNKNOWN'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Map each dependency to its primary or first finding if vulnerable
  const combinedRows = useMemo(() => {
    // If user filtered by specific vulnerability severity, prioritize showing findings list directly
    if (statusFilter === 'VULNERABLE' || severityFilter !== 'ALL') {
      return findings.map(f => ({
        type: 'finding' as const,
        id: f.id,
        name: f.packageName,
        version: f.installedVersion,
        ecosystem: f.ecosystem,
        manifestFile: f.manifestFile,
        isDirect: f.isDirect,
        status: f.status,
        vulnerabilityId: f.vulnerabilityId,
        cveId: f.cveId,
        severity: f.severity,
        fixedVersion: f.fixedVersion,
        findingData: f
      }));
    }

    // Default view: list all scanned dependencies with their vulnerability status
    return dependencies.map(dep => {
      // Find matching finding if any
      const matchingFinding = findings.find(
        f => f.packageName.toLowerCase() === dep.name.toLowerCase() && f.installedVersion === dep.version
      );

      return {
        type: (matchingFinding ? 'finding' : 'dep') as 'finding' | 'dep',
        id: `${dep.ecosystem}-${dep.name}-${dep.version}`,
        name: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        manifestFile: dep.manifestFile,
        isDirect: dep.isDirect,
        status: dep.status,
        vulnerabilityId: matchingFinding ? matchingFinding.vulnerabilityId : null,
        cveId: matchingFinding?.cveId,
        severity: matchingFinding?.severity || dep.highestSeverity || null,
        fixedVersion: matchingFinding?.fixedVersion || null,
        findingData: matchingFinding || null
      };
    });
  }, [findings, dependencies, statusFilter, severityFilter]);

  // Filtering
  const filteredRows = useMemo(() => {
    return combinedRows.filter(row => {
      // Ecosystem filter
      if (ecosystemFilter !== 'ALL' && row.ecosystem !== ecosystemFilter) {
        return false;
      }
      // Status filter
      if (statusFilter !== 'ALL' && row.status !== statusFilter) {
        return false;
      }
      // Severity filter
      if (severityFilter !== 'ALL' && row.severity !== severityFilter) {
        return false;
      }
      // Search
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const matchesName = row.name.toLowerCase().includes(q);
        const matchesVuln = row.vulnerabilityId?.toLowerCase().includes(q);
        const matchesCve = row.cveId?.toLowerCase().includes(q);
        const matchesManifest = row.manifestFile.toLowerCase().includes(q);
        if (!matchesName && !matchesVuln && !matchesCve && !matchesManifest) {
          return false;
        }
      }
      return true;
    });
  }, [combinedRows, ecosystemFilter, statusFilter, severityFilter, searchTerm]);

  return (
    <div className="bg-bg-secondary border border-border rounded-lg overflow-hidden flex flex-col shadow-subtle">
      {/* Controls Bar */}
      <div className="p-4 border-b border-border flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between bg-bg-elevated/40">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search package, CVE-ID, or manifest..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-bg-secondary border border-border rounded pl-9 pr-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-primary"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          <div className="flex items-center rounded bg-bg-secondary border border-border p-0.5 text-xs font-mono">
            {(['ALL', 'VULNERABLE', 'SAFE', 'UNKNOWN'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                  statusFilter === s
                    ? 'bg-bg-elevated text-text-primary font-medium shadow-subtle'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {s === 'ALL' ? 'All' : s.charAt(0) + s.slice(1).toLowerCase()}
              </button>
            ))}
          </div>

          {/* Ecosystem Filter */}
          <select
            value={ecosystemFilter}
            onChange={(e) => setEcosystemFilter(e.target.value as any)}
            className="bg-bg-secondary border border-border rounded px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-accent-primary font-mono"
          >
            <option value="ALL">All Ecosystems</option>
            <option value="PyPI">PyPI (Python)</option>
            <option value="npm">npm (Node.js)</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-bg-secondary border border-border rounded px-2.5 py-1.5 text-xs text-text-primary focus:outline-none focus:border-accent-primary font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-border bg-bg-sidebar/80 text-[11px] uppercase font-mono tracking-wider text-text-muted">
              <th className="py-2.5 px-4 font-medium">Package</th>
              <th className="py-2.5 px-3 font-medium">Ecosystem</th>
              <th className="py-2.5 px-3 font-medium">Installed Version</th>
              <th className="py-2.5 px-3 font-medium">Vulnerability Identifier</th>
              <th className="py-2.5 px-3 font-medium">Severity</th>
              <th className="py-2.5 px-3 font-medium">Fixed In</th>
              <th className="py-2.5 px-3 font-medium">Status</th>
              <th className="py-2.5 px-4 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {filteredRows.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-text-muted">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <PackageCheck className="w-8 h-8 text-accent-primary/60" />
                    <p className="font-medium text-text-secondary">No dependencies matching current filters</p>
                    <p className="text-[11px] font-mono">Try adjusting your search criteria or resetting filters.</p>
                  </div>
                </td>
              </tr>
            ) : (
              filteredRows.map((row) => {
                const isVuln = row.status === 'VULNERABLE';
                const isSafe = row.status === 'SAFE';

                return (
                  <tr
                    key={row.id}
                    className={`hover:bg-bg-hover/50 transition-colors ${
                      isVuln ? 'bg-severity-critical/5' : ''
                    }`}
                  >
                    {/* Package */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono font-medium text-text-primary truncate">
                          {row.name}
                        </span>
                        {row.isDirect ? (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-accent-secondary/10 text-accent-secondary border border-accent-secondary/20">
                            direct
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-bg-elevated text-text-muted border border-border">
                            transitive
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] font-mono text-text-muted flex items-center gap-1 mt-0.5 truncate">
                        <FileCode className="w-3 h-3 text-text-muted flex-shrink-0" />
                        <span className="truncate">{row.manifestFile}</span>
                      </div>
                    </td>

                    {/* Ecosystem */}
                    <td className="py-3 px-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono border ${
                        row.ecosystem === 'PyPI'
                          ? 'bg-accent-secondary/10 text-accent-secondary border-accent-secondary/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {row.ecosystem}
                      </span>
                    </td>

                    {/* Installed Version */}
                    <td className="py-3 px-3">
                      <span className="font-mono text-xs text-text-secondary bg-bg-elevated px-2 py-0.5 rounded border border-border">
                        {row.version}
                      </span>
                    </td>

                    {/* Vulnerability Identifier */}
                    <td className="py-3 px-3">
                      {row.vulnerabilityId ? (
                        <div className="flex flex-col">
                          <button
                            onClick={() => row.findingData && onSelectVulnerability(row.findingData)}
                            className="font-mono font-semibold text-accent-secondary hover:underline flex items-center gap-1 text-left"
                          >
                            <span>{row.vulnerabilityId}</span>
                            <ExternalLink className="w-3 h-3 text-accent-secondary/70 inline" />
                          </button>
                          {row.cveId && row.cveId !== row.vulnerabilityId && (
                            <span className="text-[10px] font-mono text-text-muted">
                              Alias: {row.cveId}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-text-muted font-mono text-[11px]">—</span>
                      )}
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-3">
                      {row.severity ? (
                        <SeverityBadge severity={row.severity as Severity} size="sm" />
                      ) : (
                        <span className="text-text-muted font-mono text-[11px]">None</span>
                      )}
                    </td>

                    {/* Fixed Version */}
                    <td className="py-3 px-3">
                      {row.fixedVersion ? (
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] px-1.5 py-0.5 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
                          &gt;= {row.fixedVersion}
                        </span>
                      ) : (
                        <span className="text-text-muted font-mono text-[11px]">
                          {isVuln ? 'No fix advisory' : '—'}
                        </span>
                      )}
                    </td>

                    {/* Status */}
                    <td className="py-3 px-3">
                      {isVuln ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium text-severity-critical">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Vulnerable
                        </span>
                      ) : isSafe ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium text-accent-primary">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Safe
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono text-text-muted">
                          <HelpCircle className="w-3.5 h-3.5" />
                          Unknown
                        </span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      {row.findingData ? (
                        <button
                          onClick={() => onSelectVulnerability(row.findingData!)}
                          className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-bg-elevated hover:bg-bg-hover text-text-primary border border-border hover:border-border-active transition-colors shadow-subtle"
                        >
                          Inspect
                        </button>
                      ) : (
                        <span className="text-text-muted font-mono text-[11px]">—</span>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Footer status counter */}
      <div className="p-3 border-t border-border flex items-center justify-between text-[11px] font-mono text-text-muted bg-bg-sidebar/50">
        <div>
          Showing {filteredRows.length} of {combinedRows.length} total package dependencies
        </div>
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-severity-critical" />
            Vulnerable: {dependencies.filter(d => d.status === 'VULNERABLE').length}
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-accent-primary" />
            Safe: {dependencies.filter(d => d.status === 'SAFE').length}
          </span>
        </div>
      </div>
    </div>
  );
};
