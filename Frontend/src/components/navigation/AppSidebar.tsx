import React from 'react';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  FolderGit2, 
  ShieldAlert, 
  History, 
  Cpu, 
  Sliders, 
  Terminal, 
  ChevronDown,
  Keyboard,
  ExternalLink
} from 'lucide-react';
import { ProjectRepo } from '../../types/security';

export type NavTab = 'overview' | 'projects' | 'findings' | 'history' | 'integrations' | 'policies';

interface AppSidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  openFindingsCount: number;
  currentProject: ProjectRepo;
  onOpenShortcuts: () => void;
}

export const AppSidebar: React.FC<AppSidebarProps> = ({
  currentTab,
  onTabChange,
  openFindingsCount,
  currentProject,
  onOpenShortcuts
}) => {
  const navItems = [
    { id: 'overview' as NavTab, label: 'Overview', icon: LayoutDashboard },
    { id: 'projects' as NavTab, label: 'Projects', icon: FolderGit2, count: 4 },
    { id: 'findings' as NavTab, label: 'Security Findings', icon: ShieldAlert, count: openFindingsCount, badgeColor: 'bg-severity-critical/20 text-severity-critical border-severity-critical/30' },
    { id: 'history' as NavTab, label: 'Scan History', icon: History },
    { id: 'integrations' as NavTab, label: 'Integrations', icon: Cpu, subtext: 'CI/CD & CLI' },
    { id: 'policies' as NavTab, label: 'Policies & Settings', icon: Sliders }
  ];

  return (
    <aside className="w-64 flex-shrink-0 bg-bg-sidebar border-r border-border flex flex-col justify-between select-none h-screen sticky top-0">
      {/* Top Brand & Workspace */}
      <div>
        {/* Logo brand bar */}
        <div className="h-14 px-4 flex items-center justify-between border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-bg-elevated border border-border flex items-center justify-center text-accent-primary shadow-subtle">
              <ShieldCheck className="w-5 h-5 text-accent-primary" />
            </div>
            <div>
              <div className="font-mono font-bold text-sm tracking-tight text-text-primary flex items-center gap-1.5">
                ShipSafe
                <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-accent-primary/10 text-accent-primary border border-accent-primary/20">
                  v2.4
                </span>
              </div>
              <div className="text-[10px] font-mono text-text-muted">
                AppSec Engine
              </div>
            </div>
          </div>
        </div>

        {/* Workspace Selector */}
        <div className="p-3 border-b border-border/80">
          <div className="flex items-center justify-between px-2.5 py-1.5 rounded bg-bg-secondary border border-border text-xs cursor-pointer hover:border-border-active transition-colors">
            <div className="truncate">
              <div className="text-[10px] uppercase font-mono tracking-wider text-text-muted">
                Workspace
              </div>
              <div className="font-medium text-text-primary text-xs truncate">
                Acme Production Core
              </div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
          </div>
        </div>

        {/* Navigation list */}
        <nav className="p-3 space-y-1">
          {navItems.map(item => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs transition-colors group ${
                  isActive
                    ? 'bg-bg-elevated text-text-primary font-medium border-l-2 border-accent-primary shadow-subtle'
                    : 'text-text-secondary hover:text-text-primary hover:bg-bg-secondary'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 transition-colors ${
                    isActive ? 'text-accent-primary' : 'text-text-muted group-hover:text-text-secondary'
                  }`} />
                  <span>{item.label}</span>
                </div>

                {item.count !== undefined && (
                  <span className={`font-mono text-[11px] px-1.5 py-0.2 rounded border ${
                    item.badgeColor || 'bg-bg-secondary text-text-muted border-border'
                  }`}>
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Section: Active Project, CLI Status, & User */}
      <div className="p-3 border-t border-border space-y-3 bg-bg-sidebar">
        {/* Active Project Card */}
        <div className="p-2.5 rounded bg-bg-secondary/70 border border-border text-[11px] space-y-1">
          <div className="flex items-center justify-between text-text-muted">
            <span className="uppercase font-mono text-[9px] tracking-wider">Active Scope</span>
            <span className="flex items-center gap-1 text-accent-primary">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-primary animate-pulse" />
              Synced
            </span>
          </div>
          <div className="font-mono font-medium text-text-primary truncate">
            {currentProject.name}
          </div>
          <div className="text-[10px] text-text-muted flex items-center justify-between">
            <span>Branch: {currentProject.branch}</span>
            <span className="text-accent-secondary">{currentProject.language}</span>
          </div>
        </div>

        {/* CLI Daemon Status */}
        <div className="flex items-center justify-between px-2 text-[11px] text-text-muted font-mono">
          <div className="flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-accent-primary" />
            <span>CLI daemon: active</span>
          </div>
          <button 
            onClick={onOpenShortcuts}
            title="Keyboard shortcuts (or press ?)"
            className="hover:text-text-primary p-1 hover:bg-bg-elevated rounded transition-colors"
          >
            <Keyboard className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* User profile */}
        <div className="pt-2 border-t border-border/60 flex items-center justify-between">
          <div className="flex items-center gap-2 min-w-0">
            <div className="w-7 h-7 rounded bg-bg-elevated border border-border flex items-center justify-center font-mono text-xs font-semibold text-accent-secondary">
              AD
            </div>
            <div className="min-w-0 truncate">
              <div className="text-xs font-medium text-text-primary truncate">alex@acme.dev</div>
              <div className="text-[10px] text-text-muted font-mono">AppSec Lead</div>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};
