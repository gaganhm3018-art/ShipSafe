import React, { useState } from 'react';
import { 
  SecurityFinding, 
  Severity, 
  VulnerabilityType, 
  FindingStatus, 
  ProgrammingLanguage 
} from '../../types/security';
import { SeverityBadge } from '../common/SeverityBadge';
import { 
  Search, 
  Filter, 
  X, 
  FileCode, 
  CheckCircle2, 
  AlertCircle, 
  ShieldCheck,
  ChevronRight
} from 'lucide-react';

interface FindingListProps {
  findings: SecurityFinding[];
  selectedFindingId: string | null;
  onSelectFinding: (finding: SecurityFinding) => void;
}

export const FindingList: React.FC<FindingListProps> = ({
  findings,
  selectedFindingId,
  onSelectFinding
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'ALL'>('ALL');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<FindingStatus | 'ALL'>('ALL');

  // Multi-facet filtering
  const filteredFindings = findings.filter(f => {
    if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
    if (selectedType !== 'ALL' && f.type !== selectedType) return false;
    if (selectedLanguage !== 'ALL' && f.language !== selectedLanguage) return false;
    if (selectedStatus !== 'ALL' && f.status !== selectedStatus) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = f.name.toLowerCase().includes(q);
      const matchFile = f.file.toLowerCase().includes(q);
      const matchCwe = f.cwe.toLowerCase().includes(q);
      const matchId = f.id.toLowerCase().includes(q);
      const matchRule = f.ruleId.toLowerCase().includes(q);
      if (!matchName && !matchFile && !matchCwe && !matchId && !matchRule) return false;
    }

    return true;
  });

  const clearFilters = () => {
    setSearchQuery('');
    setSelectedSeverity('ALL');
    setSelectedType('ALL');
    setSelectedLanguage('ALL');
    setSelectedStatus('ALL');
  };

  const hasActiveFilters = 
    searchQuery !== '' || 
    selectedSeverity !== 'ALL' || 
    selectedType !== 'ALL' || 
    selectedLanguage !== 'ALL' || 
    selectedStatus !== 'ALL';

  // Distinct types for filter dropdown
  const uniqueTypes = Array.from(new Set(findings.map(f => f.type)));

  return (
    <div className="flex flex-col h-full bg-bg-secondary border-r border-border select-none">
      {/* Top filter bar */}
      <div className="p-3 border-b border-border space-y-2 bg-bg-sidebar/50">
        {/* Search input */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search findings by ID, path, rule, CWE..."
            className="w-full pl-8 pr-7 py-1.5 bg-bg-main border border-border rounded text-xs font-mono text-text-primary focus:outline-none focus:border-accent-secondary"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Facet filter dropdowns */}
        <div className="grid grid-cols-2 gap-1.5 text-xs font-mono">
          {/* Severity filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value as any)}
            className="bg-bg-main border border-border rounded px-2 py-1 text-text-secondary focus:outline-none focus:border-border-active"
          >
            <option value="ALL">Severity: All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Info</option>
          </select>

          {/* Vulnerability type filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-bg-main border border-border rounded px-2 py-1 text-text-secondary focus:outline-none focus:border-border-active truncate"
          >
            <option value="ALL">Type: All</option>
            {uniqueTypes.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>

          {/* Language filter */}
          <select
            value={selectedLanguage}
            onChange={(e) => setSelectedLanguage(e.target.value)}
            className="bg-bg-main border border-border rounded px-2 py-1 text-text-secondary focus:outline-none focus:border-border-active"
          >
            <option value="ALL">Language: All</option>
            <option value="python">Python</option>
            <option value="typescript">TypeScript</option>
            <option value="javascript">JavaScript</option>
            <option value="manifest">Manifest / Config</option>
          </select>

          {/* Status filter */}
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value as any)}
            className="bg-bg-main border border-border rounded px-2 py-1 text-text-secondary focus:outline-none focus:border-border-active"
          >
            <option value="ALL">Status: All</option>
            <option value="OPEN">Open</option>
            <option value="REMEDIATED">Remediated</option>
            <option value="IGNORED">False Positive</option>
          </select>
        </div>

        {/* Results count & Clear filters */}
        <div className="flex items-center justify-between text-[11px] font-mono text-text-muted pt-1">
          <span>Showing {filteredFindings.length} of {findings.length} findings</span>
          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-accent-secondary hover:underline flex items-center gap-1"
            >
              <span>Reset</span>
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Findings List Rows */}
      <div className="flex-1 overflow-y-auto divide-y divide-border">
        {filteredFindings.length === 0 ? (
          <div className="p-8 text-center text-xs text-text-muted space-y-2">
            <ShieldCheck className="w-8 h-8 mx-auto text-text-muted opacity-40" />
            <div>No security findings match your filter criteria.</div>
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="text-accent-primary hover:underline font-mono text-[11px]"
              >
                Clear all filters
              </button>
            )}
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const isSelected = finding.id === selectedFindingId;
            const isRemediated = finding.status === 'REMEDIATED';
            const isIgnored = finding.status === 'IGNORED';

            return (
              <div
                key={finding.id}
                onClick={() => onSelectFinding(finding)}
                className={`p-3 cursor-pointer transition-colors relative ${
                  isSelected
                    ? 'bg-bg-elevated border-l-2 border-accent-primary'
                    : 'hover:bg-bg-elevated/40'
                }`}
              >
                <div className="space-y-1.5">
                  {/* Top row: Severity + Status + CWE */}
                  <div className="flex items-center justify-between gap-2">
                    <SeverityBadge severity={finding.severity} size="sm" />
                    
                    <div className="flex items-center gap-1.5 font-mono text-[10px]">
                      <span className="px-1.5 py-0.2 rounded bg-bg-main border border-border text-text-muted">
                        {finding.cwe}
                      </span>
                      {isRemediated && (
                        <span className="px-1.5 py-0.2 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20 font-semibold">
                          REMEDIATED
                        </span>
                      )}
                      {isIgnored && (
                        <span className="px-1.5 py-0.2 rounded bg-bg-elevated text-text-muted border border-border">
                          IGNORED
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Finding Title */}
                  <div className="text-xs font-semibold text-text-primary leading-snug truncate">
                    {finding.name}
                  </div>

                  {/* File & Line metadata */}
                  <div className="flex items-center justify-between font-mono text-[11px] text-text-muted">
                    <div className="flex items-center gap-1.5 truncate max-w-[240px]">
                      <FileCode className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                      <span className="text-text-secondary truncate">{finding.file}</span>
                      <span className="text-text-muted">:{finding.line}</span>
                    </div>
                    <ChevronRight className={`w-3.5 h-3.5 transition-transform ${isSelected ? 'text-accent-primary translate-x-0.5' : 'text-text-muted opacity-40'}`} />
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
