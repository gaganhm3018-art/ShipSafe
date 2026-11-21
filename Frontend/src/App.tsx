import React, { useState, useEffect } from 'react';
import { 
  SecurityFinding, 
  ScanRecord, 
  ProjectRepo, 
  SecurityActivity 
} from './types/security';
import { 
  INITIAL_FINDINGS, 
  MOCK_PROJECTS, 
  MOCK_SCANS, 
  MOCK_ACTIVITIES 
} from './data/mockSecurityData';
import { AppSidebar, NavTab } from './components/navigation/AppSidebar';
import { TopNavigation } from './components/navigation/TopNavigation';
import { OverviewDashboard } from './components/overview/OverviewDashboard';
import { SecurityFindingsView } from './components/findings/SecurityFindingsView';
import { ScanHistoryView } from './components/history/ScanHistoryView';
import { IntegrationsView } from './components/integrations/IntegrationsView';
import { PoliciesSettingsView } from './components/policies/PoliciesSettingsView';
import { ProjectsView } from './components/projects/ProjectsView';
import { RepositoryScanningModal } from './components/scanner/RepositoryScanningModal';
import { AIRemediationModal } from './components/remediation/AIRemediationModal';
import { KeyboardShortcutsModal } from './components/common/KeyboardShortcutsModal';
import { ToastNotification, ToastMessage } from './components/common/ToastNotification';

export const App: React.FC = () => {
  // Navigation
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [projects, setProjects] = useState<ProjectRepo[]>(MOCK_PROJECTS);
  const [currentProject, setCurrentProject] = useState<ProjectRepo>(MOCK_PROJECTS[0]);

  // Core Data
  const [findings, setFindings] = useState<SecurityFinding[]>(INITIAL_FINDINGS);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(INITIAL_FINDINGS[0] || null);
  const [scans, setScans] = useState<ScanRecord[]>(MOCK_SCANS);
  const [activities, setActivities] = useState<SecurityActivity[]>(MOCK_ACTIVITIES);

  // Modals & Drawers
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isRemediationModalOpen, setIsRemediationModalOpen] = useState(false);
  const [remediatingFinding, setRemediatingFinding] = useState<SecurityFinding | null>(null);
  const [isShortcutsModalOpen, setIsShortcutsModalOpen] = useState(false);

  // Toasts
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const showToast = (title: string, message?: string, type: 'success' | 'info' | 'error' = 'info') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts(prev => [...prev, { id, title, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  const dismissToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  // Keyboard shortcut listener for ? and S
  useEffect(() => {
    const handleGlobalKeys = (e: KeyboardEvent) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement)?.tagName)) {
        return;
      }
      if (e.key === '?') {
        e.preventDefault();
        setIsShortcutsModalOpen(true);
      } else if (e.key === 's' || e.key === 'S') {
        e.preventDefault();
        setIsScanModalOpen(true);
      }
    };
    window.addEventListener('keydown', handleGlobalKeys);
    return () => window.removeEventListener('keydown', handleGlobalKeys);
  }, []);

  // Handlers
  const handleOpenRemediation = (finding: SecurityFinding) => {
    setRemediatingFinding(finding);
    setIsRemediationModalOpen(true);
  };

  const handleApplyFix = (findingId: string, patchedCode: string) => {
    // 1. Update finding status to REMEDIATED
    setFindings(prev => prev.map(f => {
      if (f.id === findingId) {
        return {
          ...f,
          status: 'REMEDIATED',
          snippet: {
            ...f.snippet,
            lines: f.snippet.lines.map(l => {
              if (l.isTarget || l.line === f.line) {
                return { ...l, code: patchedCode.split('\n')[0], isTarget: false };
              }
              return l;
            })
          }
        };
      }
      return f;
    }));

    // If currently selected finding was modified, keep it in sync
    if (selectedFinding && selectedFinding.id === findingId) {
      setSelectedFinding(prev => prev ? { ...prev, status: 'REMEDIATED' } : null);
    }

    // 2. Add activity log
    const newActivity: SecurityActivity = {
      id: `act-${Date.now()}`,
      type: 'FIX_APPLIED',
      title: 'Vulnerability Remediated & Rescanned',
      description: `Atomic patch applied to ${selectedFinding?.file || 'target file'}. 0 regressions.`,
      timestamp: 'Just now',
      severity: selectedFinding?.severity || 'HIGH',
      repository: currentProject.name,
      actor: 'alex@acme.dev'
    };
    setActivities(prev => [newActivity, ...prev]);
  };

  const handleMarkStatus = (findingId: string, newStatus: 'OPEN' | 'REMEDIATED' | 'IGNORED') => {
    setFindings(prev => prev.map(f => f.id === findingId ? { ...f, status: newStatus } : f));
    if (selectedFinding?.id === findingId) {
      setSelectedFinding(prev => prev ? { ...prev, status: newStatus } : null);
    }
    showToast(
      `Finding Marked as ${newStatus}`,
      `Status for ${findingId} updated.`,
      newStatus === 'REMEDIATED' ? 'success' : 'info'
    );
  };

  const handleRescanFile = (filePath: string) => {
    showToast("File Rescan Completed", `Deterministic rules evaluated for ${filePath}. No regressions found.`, "success");
  };

  const handleScanComplete = (newFindings: SecurityFinding[], newRecord: ScanRecord) => {
    setFindings(newFindings);
    if (newFindings.length > 0) {
      setSelectedFinding(newFindings[0]);
    }
    setScans(prev => [newRecord, ...prev]);

    // Update project status based on findings
    const crits = newFindings.filter(f => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
    const highs = newFindings.filter(f => f.severity === 'HIGH' && f.status === 'OPEN').length;
    const newStatus = (crits > 0 || highs > 0) ? 'BLOCKED' : 'SAFE';

    setProjects(prev => prev.map(p => {
      if (p.id === currentProject.id) {
        return {
          ...p,
          status: newStatus,
          totalFindings: newFindings.length,
          criticalCount: crits,
          highCount: highs,
          lastScanned: 'Just now'
        };
      }
      return p;
    }));

    // Update current project
    setCurrentProject(prev => ({
      ...prev,
      status: newStatus,
      totalFindings: newFindings.length,
      criticalCount: crits,
      highCount: highs,
      lastScanned: 'Just now'
    }));

    // Log activity
    const newAct: SecurityActivity = {
      id: `act-${Date.now()}`,
      type: newStatus === 'BLOCKED' ? 'COMMIT_BLOCKED' : 'SCAN_COMPLETED',
      title: newStatus === 'BLOCKED' ? 'Scan Completed with Violations' : 'Scan Passed Clean',
      description: `${newFindings.length} findings identified across 64 files. Status: ${newStatus}`,
      timestamp: 'Just now',
      severity: crits > 0 ? 'CRITICAL' : 'HIGH',
      repository: currentProject.name,
      actor: 'ShipSafe Engine'
    };
    setActivities(prev => [newAct, ...prev]);

    showToast("Audit Complete", `Scan finished with ${newFindings.length} findings detected.`, newStatus === 'BLOCKED' ? 'error' : 'success');
  };

  const openFindingsCount = findings.filter(f => f.status === 'OPEN').length;

  return (
    <div className="flex min-h-screen bg-bg-main text-text-primary antialiased">
      {/* 1. Persistent Left Sidebar (Section 4 Requirement) */}
      <AppSidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        openFindingsCount={openFindingsCount}
        currentProject={currentProject}
        onOpenShortcuts={() => setIsShortcutsModalOpen(true)}
      />

      {/* Main View Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Compact Top Navigation Bar (Section 4 Requirement) */}
        <TopNavigation
          currentProject={currentProject}
          projects={projects}
          onSelectProject={setCurrentProject}
          onOpenScanModal={() => setIsScanModalOpen(true)}
          findings={findings}
          onShowToast={showToast}
        />

        {/* Dynamic Route View */}
        <main className="flex-1">
          {currentTab === 'overview' && (
            <OverviewDashboard
              findings={findings}
              projects={projects}
              activities={activities}
              onSelectFinding={(f) => {
                setSelectedFinding(f);
                setCurrentTab('findings');
              }}
              onNavigateToFindings={() => setCurrentTab('findings')}
              onNavigateToProjects={() => setCurrentTab('projects')}
              onStartScan={() => setIsScanModalOpen(true)}
            />
          )}

          {currentTab === 'findings' && (
            <SecurityFindingsView
              findings={findings}
              selectedFinding={selectedFinding}
              onSelectFinding={setSelectedFinding}
              onOpenRemediation={handleOpenRemediation}
              onMarkStatus={handleMarkStatus}
              onRescanFile={handleRescanFile}
              onShowToast={showToast}
            />
          )}

          {currentTab === 'projects' && (
            <ProjectsView
              projects={projects}
              currentProject={currentProject}
              onSelectProject={setCurrentProject}
              onOpenScanModal={() => setIsScanModalOpen(true)}
              onNavigateToFindings={() => setCurrentTab('findings')}
            />
          )}

          {currentTab === 'history' && (
            <ScanHistoryView
              scans={scans}
              onOpenScanModal={() => setIsScanModalOpen(true)}
            />
          )}

          {currentTab === 'integrations' && (
            <IntegrationsView onShowToast={showToast} />
          )}

          {currentTab === 'policies' && (
            <PoliciesSettingsView onShowToast={showToast} />
          )}
        </main>
      </div>

      {/* Modals & Dialogs */}
      <RepositoryScanningModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={handleScanComplete}
      />

      <AIRemediationModal
        finding={remediatingFinding}
        isOpen={isRemediationModalOpen}
        onClose={() => setIsRemediationModalOpen(false)}
        onApplyFix={handleApplyFix}
        onShowToast={showToast}
      />

      <KeyboardShortcutsModal
        isOpen={isShortcutsModalOpen}
        onClose={() => setIsShortcutsModalOpen(false)}
      />

      {/* Non-intrusive Toast Notifications */}
      <ToastNotification
        toasts={toasts}
        onDismiss={dismissToast}
      />
    </div>
  );
};
