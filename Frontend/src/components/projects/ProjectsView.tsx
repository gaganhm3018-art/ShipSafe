import React from 'react';
import { ProjectRepo, SecurityFinding } from '../../types/security';
import { 
  FolderGit2, 
  GitBranch, 
  Star, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Play, 
  ExternalLink,
  Plus
} from 'lucide-react';

interface ProjectsViewProps {
  projects: ProjectRepo[];
  currentProject: ProjectRepo;
  onSelectProject: (p: ProjectRepo) => void;
  onOpenScanModal: () => void;
  onNavigateToFindings: () => void;
}

export const ProjectsView: React.FC<ProjectsViewProps> = ({
  projects,
  currentProject,
  onSelectProject,
  onOpenScanModal,
  onNavigateToFindings
}) => {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <h1 className="text-base font-bold text-text-primary flex items-center gap-2">
            <FolderGit2 className="w-5 h-5 text-accent-secondary" />
            Monitored Code Repositories
          </h1>
          <p className="text-xs text-text-muted mt-0.5">
            Continuous vulnerability inspection across Python, JavaScript, and TypeScript services
          </p>
        </div>

        <button
          onClick={onOpenScanModal}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-bold font-mono transition-colors shadow-subtle"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Repository</span>
        </button>
      </div>

      {/* Repositories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {projects.map((proj) => {
          const isSelected = proj.id === currentProject.id;
          const isBlocked = proj.status === 'BLOCKED';
          const isAtRisk = proj.status === 'AT_RISK';
          const isSafe = proj.status === 'SAFE';

          return (
            <div
              key={proj.id}
              className={`p-5 rounded bg-bg-secondary border transition-all ${
                isSelected 
                  ? 'border-accent-primary/50 shadow-subtle' 
                  : 'border-border hover:border-border-active'
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <FolderGit2 className="w-4 h-4 text-accent-secondary" />
                    <span className="text-xs font-mono text-text-muted">{proj.owner}/</span>
                    <h3 className="text-sm font-bold text-text-primary font-mono">
                      {proj.name}
                    </h3>
                    {isSelected && (
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20 font-semibold">
                        ACTIVE SCOPE
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 font-mono text-xs text-text-muted pt-1">
                    <span className="flex items-center gap-1 text-text-secondary">
                      <GitBranch className="w-3 h-3 text-text-muted" />
                      {proj.branch}
                    </span>
                    <span>•</span>
                    <span className="text-accent-secondary">{proj.language}</span>
                    {proj.stars && (
                      <>
                        <span>•</span>
                        <span className="flex items-center gap-1">
                          <Star className="w-3 h-3 text-[#E9BD55]" />
                          {proj.stars}
                        </span>
                      </>
                    )}
                  </div>
                </div>

                {/* Status Badge */}
                <div>
                  {isSafe && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-accent-primary/10 border border-accent-primary/30 text-accent-primary text-xs font-mono font-semibold">
                      <ShieldCheck className="w-3.5 h-3.5" /> Clean
                    </span>
                  )}
                  {isAtRisk && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-severity-high/10 border border-severity-high/30 text-severity-high text-xs font-mono font-semibold">
                      <AlertTriangle className="w-3.5 h-3.5" /> At Risk
                    </span>
                  )}
                  {isBlocked && (
                    <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-severity-critical/10 border border-severity-critical/30 text-severity-critical text-xs font-mono font-semibold">
                      <ShieldAlert className="w-3.5 h-3.5" /> Blocked CI
                    </span>
                  )}
                </div>
              </div>

              {/* Metrics */}
              <div className="grid grid-cols-3 gap-2 p-3 my-4 rounded bg-bg-main border border-border text-center font-mono text-xs">
                <div>
                  <div className="text-[10px] uppercase text-text-muted">Total Findings</div>
                  <div className="font-bold text-text-primary mt-0.5">{proj.totalFindings}</div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-text-muted">Critical Vulns</div>
                  <div className={`font-bold mt-0.5 ${proj.criticalCount > 0 ? 'text-severity-critical' : 'text-text-primary'}`}>
                    {proj.criticalCount}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] uppercase text-text-muted">Last Audit</div>
                  <div className="text-text-secondary mt-0.5 truncate text-[11px]">{proj.lastScanned}</div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="flex items-center justify-between pt-1 font-mono text-xs">
                <button
                  onClick={() => {
                    onSelectProject(proj);
                    onNavigateToFindings();
                  }}
                  className="text-accent-secondary hover:underline flex items-center gap-1"
                >
                  <span>Inspect findings ({proj.totalFindings})</span>
                </button>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      onSelectProject(proj);
                      onOpenScanModal();
                    }}
                    className="flex items-center gap-1 px-3 py-1 rounded bg-bg-elevated hover:bg-bg-hover border border-border text-text-primary transition-colors"
                  >
                    <Play className="w-3 h-3 text-accent-primary" />
                    <span>Run Scan</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
