import React, { useState } from 'react';
import { ScanRecord } from '../../types/security';
import { 
  History, 
  GitBranch, 
  GitCommit, 
  CheckCircle2, 
  ShieldAlert, 
  AlertTriangle, 
  ArrowRight, 
  ArrowUpDown,
  Filter,
  Terminal,
  Clock
} from 'lucide-react';

interface ScanHistoryViewProps {
  scans: ScanRecord[];
  onOpenScanModal: () => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({ scans, onOpenScanModal }) => {
  const [selectedScanA, setSelectedScanA] = useState<string>(scans[0]?.id || '');
  const [selectedScanB, setSelectedScanB] = useState<string>(scans[1]?.id || '');
  const [isComparing, setIsComparing] = useState(false);

  const scanA = scans.find(s => s.id === selectedScanA) || scans[0];
  const scanB = scans.find(s => s.id === selectedScanB) || scans[1];

  // Calculate delta
  const diffFindings = (scanA?.totalFindings || 0) - (scanB?.totalFindings || 0);
  const diffCritical = (scanA?.critical || 0) - (scanB?.critical || 0);
  const diffHigh = (scanA?.high || 0) - (scanB?.high || 0);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-base font-bold text-text-primary flex items-center gap-2">
            <History className="w-5 h-5 text-accent-secondary" />
            Security Scan History & Posture Comparison
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Deterministic audit logs across commits, pre-commit runs, and pull request CI checks
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsComparing(!isComparing)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs font-mono transition-colors ${
              isComparing 
                ? 'bg-accent-secondary/10 border-accent-secondary/30 text-accent-secondary' 
                : 'bg-bg-secondary hover:bg-bg-elevated border-border text-text-secondary hover:text-text-primary'
            }`}
          >
            <ArrowUpDown className="w-3.5 h-3.5" />
            <span>{isComparing ? 'Close Comparison' : 'Compare Two Scans'}</span>
          </button>
        </div>
      </div>

      {/* Comparison Drawer / Panel */}
      {isComparing && scanA && scanB && (
        <div className="p-5 rounded bg-bg-secondary border border-accent-secondary/30 space-y-4 animate-in fade-in duration-150">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <div className="font-mono text-xs font-semibold text-text-primary flex items-center gap-2">
              <ArrowUpDown className="w-4 h-4 text-accent-secondary" />
              <span>Posture Delta Comparison</span>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="text-text-muted">Base (Newer):</span>
                <select
                  value={selectedScanA}
                  onChange={(e) => setSelectedScanA(e.target.value)}
                  className="bg-bg-main border border-border rounded px-2 py-1 text-text-primary"
                >
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>{s.id} ({s.commit.substring(0, 7)})</option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-text-muted">vs Target (Older):</span>
                <select
                  value={selectedScanB}
                  onChange={(e) => setSelectedScanB(e.target.value)}
                  className="bg-bg-main border border-border rounded px-2 py-1 text-text-primary"
                >
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>{s.id} ({s.commit.substring(0, 7)})</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* Comparison Delta Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 rounded bg-bg-main border border-border">
              <span className="text-[10px] text-text-muted uppercase">Total Findings Delta</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold text-text-primary">
                  {diffFindings > 0 ? `+${diffFindings}` : diffFindings}
                </span>
                <span className={`text-[11px] ${diffFindings <= 0 ? 'text-accent-primary' : 'text-severity-critical'}`}>
                  {diffFindings < 0 ? 'Posture Improved' : diffFindings === 0 ? 'No Change' : 'Regressed'}
                </span>
              </div>
              <div className="text-[10px] text-text-muted mt-1">
                {scanA.totalFindings} in {scanA.id} vs {scanB.totalFindings} in {scanB.id}
              </div>
            </div>

            <div className="p-3 rounded bg-bg-main border border-border">
              <span className="text-[10px] text-text-muted uppercase">Critical Severity Delta</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold text-text-primary">
                  {diffCritical > 0 ? `+${diffCritical}` : diffCritical}
                </span>
                <span className={`text-[11px] ${diffCritical <= 0 ? 'text-accent-primary' : 'text-severity-critical'}`}>
                  {diffCritical <= 0 ? 'Controlled' : 'Urgent'}
                </span>
              </div>
              <div className="text-[10px] text-text-muted mt-1">
                {scanA.critical} vs {scanB.critical} critical findings
              </div>
            </div>

            <div className="p-3 rounded bg-bg-main border border-border">
              <span className="text-[10px] text-text-muted uppercase">Deployment Policy</span>
              <div className="mt-1 font-semibold text-text-primary">
                {scanA.status === 'PASSED' ? (
                  <span className="text-accent-primary flex items-center gap-1">
                    <CheckCircle2 className="w-4 h-4" /> Ready to Ship
                  </span>
                ) : (
                  <span className="text-severity-critical flex items-center gap-1">
                    <ShieldAlert className="w-4 h-4" /> Policy Failing
                  </span>
                )}
              </div>
              <div className="text-[10px] text-text-muted mt-1 truncate">
                {scanA.policyViolation || "All deterministic security checks passing"}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Scans Table */}
      <div className="bg-bg-secondary border border-border rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-bg-elevated/40 border-b border-border text-text-muted uppercase text-[10px]">
              <tr>
                <th className="py-3 px-4 font-medium">Scan ID</th>
                <th className="py-3 px-4 font-medium">Repository / Branch</th>
                <th className="py-3 px-4 font-medium">Commit</th>
                <th className="py-3 px-4 font-medium">Trigger Source</th>
                <th className="py-3 px-4 font-medium">Timestamp</th>
                <th className="py-3 px-4 font-medium">Status</th>
                <th className="py-3 px-4 font-medium text-center">Findings (Crit/High)</th>
                <th className="py-3 px-4 font-medium text-right">Resolved</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {scans.map(scan => (
                <tr key={scan.id} className="hover:bg-bg-elevated/40 transition-colors">
                  <td className="py-3.5 px-4 font-semibold text-accent-secondary">
                    {scan.id}
                  </td>
                  <td className="py-3.5 px-4 text-text-primary">
                    <div className="font-medium">{scan.repository}</div>
                    <div className="text-[11px] text-text-muted flex items-center gap-1">
                      <GitBranch className="w-3 h-3" />
                      <span>{scan.branch}</span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-text-muted">
                    <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-bg-main border border-border text-[11px]">
                      <GitCommit className="w-3 h-3 text-text-muted" />
                      {scan.commit}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-text-secondary">
                    <span className="flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-text-muted" />
                      {scan.trigger}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-text-muted">
                    {new Date(scan.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3.5 px-4">
                    {scan.status === 'PASSED' && (
                      <span className="inline-flex items-center gap-1 text-accent-primary font-bold text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                      </span>
                    )}
                    {scan.status === 'FAILED' && (
                      <span className="inline-flex items-center gap-1 text-severity-critical font-bold text-[11px]">
                        <ShieldAlert className="w-3.5 h-3.5" /> BLOCKED
                      </span>
                    )}
                    {scan.status === 'WARNING' && (
                      <span className="inline-flex items-center gap-1 text-severity-high font-bold text-[11px]">
                        <AlertTriangle className="w-3.5 h-3.5" /> WARNING
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
                      scan.critical > 0 
                        ? 'bg-severity-critical/10 text-severity-critical border-severity-critical/30'
                        : scan.high > 0 
                        ? 'bg-severity-high/10 text-severity-high border-severity-high/30'
                        : 'bg-accent-primary/10 text-accent-primary border-accent-primary/30'
                    }`}>
                      {scan.totalFindings} ({scan.critical}C / {scan.high}H)
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right text-accent-primary font-bold">
                    +{scan.resolved}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
