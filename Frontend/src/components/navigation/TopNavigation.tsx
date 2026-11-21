import React, { useState } from 'react';
import { 
  GitBranch, 
  Play, 
  Download, 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  ChevronDown,
  FolderGit2,
  Check
} from 'lucide-react';
import { ProjectRepo, SecurityFinding } from '../../types/security';
import { ScannerService } from '../../services/scannerService';

interface TopNavigationProps {
  currentProject: ProjectRepo;
  projects: ProjectRepo[];
  onSelectProject: (p: ProjectRepo) => void;
  onOpenScanModal: () => void;
  findings: SecurityFinding[];
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const TopNavigation: React.FC<TopNavigationProps> = ({
  currentProject,
  projects,
  onSelectProject,
  onOpenScanModal,
  findings,
  onShowToast
}) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const criticals = findings.filter(f => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
  const highs = findings.filter(f => f.severity === 'HIGH' && f.status === 'OPEN').length;
  const isBlocked = criticals > 0 || highs > 0;

  const handleExportSARIF = () => {
    const jsonStr = ScannerService.exportToSARIF(findings);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shipsafe-report-${currentProject.name}.sarif`;
    a.click();
    URL.revokeObjectURL(url);
    onShowToast("SARIF Report Exported", `Saved ${findings.length} findings conforming to OASIS SARIF 2.1.0 specification.`, "success");
  };

  return (
    <header className="h-14 bg-bg-secondary border-b border-border px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Project Selector & Branch */}
      <div className="flex items-center gap-4">
        {/* Repo Dropdown */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-bg-elevated/70 border border-border hover:border-border-active transition-colors text-xs font-mono"
          >
            <FolderGit2 className="w-3.5 h-3.5 text-accent-secondary" />
            <span className="text-text-muted">{currentProject.owner}/</span>
            <span className="font-semibold text-text-primary">{currentProject.name}</span>
            <ChevronDown className="w-3 h-3 text-text-muted ml-1" />
          </button>

          {dropdownOpen && (
            <div className="absolute top-full left-0 mt-1.5 w-64 bg-bg-secondary border border-border rounded shadow-elevated py-1 z-30 font-mono text-xs">
              <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-text-muted border-b border-border/60">
                Switch Target Repository
              </div>
              {projects.map(p => (
                <button
                  key={p.id}
                  onClick={() => {
                    onSelectProject(p);
                    setDropdownOpen(false);
                  }}
                  className={`w-full px-3 py-2 flex items-center justify-between text-left hover:bg-bg-elevated transition-colors ${
                    p.id === currentProject.id ? 'bg-bg-elevated text-accent-primary font-medium' : 'text-text-secondary'
                  }`}
                >
                  <div className="truncate">
                    <div className="text-text-primary truncate">{p.name}</div>
                    <div className="text-[10px] text-text-muted">{p.language} • {p.branch}</div>
                  </div>
                  {p.id === currentProject.id && <Check className="w-3.5 h-3.5 text-accent-primary flex-shrink-0" />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Branch indicator */}
        <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-bg-main border border-border text-[11px] font-mono text-text-muted">
          <GitBranch className="w-3 h-3 text-text-muted" />
          <span>{currentProject.branch}</span>
        </div>

        {/* CI Policy Gate Status Pill */}
        <div className={`hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded border text-xs font-mono ${
          isBlocked 
            ? 'bg-severity-critical/10 border-severity-critical/30 text-severity-critical' 
            : 'bg-accent-primary/10 border-accent-primary/30 text-accent-primary'
        }`}>
          {isBlocked ? (
            <>
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>CI Gate Blocked: {criticals} Critical, {highs} High (fail-on: high)</span>
            </>
          ) : (
            <>
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>CI Gate Passed: 0 Blocking Vulnerabilities</span>
            </>
          )}
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2.5">
        {/* Export SARIF */}
        <button
          onClick={handleExportSARIF}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-xs text-text-secondary hover:text-text-primary transition-colors font-mono"
          title="Export report in SARIF 2.1.0 standard for GitHub Security"
        >
          <Download className="w-3.5 h-3.5 text-accent-secondary" />
          <span>SARIF</span>
        </button>

        {/* Start Scan Button */}
        <button
          onClick={onOpenScanModal}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-semibold font-mono transition-colors shadow-subtle"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>New Scan</span>
        </button>
      </div>
    </header>
  );
};
