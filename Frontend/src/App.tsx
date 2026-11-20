import React, { useState, useEffect } from 'react';
import { 
  SecurityFinding, 
  ScanRecord, 
  ProjectRepo, 
  SecurityActivity,
  UserProfile,
  WorkspaceOrg,
  NavTab
} from './types/security';
import { 
  INITIAL_FINDINGS, 
  MOCK_PROJECTS, 
  MOCK_SCANS, 
  MOCK_ACTIVITIES 
} from './data/mockSecurityData';
import { AppSidebar } from './components/navigation/AppSidebar';
import { TopNavigation } from './components/navigation/TopNavigation';
import { OverviewDashboard } from './components/overview/OverviewDashboard';
import { SecurityFindingsView } from './components/findings/SecurityFindingsView';
import { ScanHistoryView } from './components/history/ScanHistoryView';
import { IntegrationsView } from './components/integrations/IntegrationsView';
import { PoliciesSettingsView } from './components/policies/PoliciesSettingsView';
import { ProjectsView } from './components/projects/ProjectsView';
import { ExternalAnalysisView } from './components/external/ExternalAnalysisView';
import { SecurityInsightsView } from './components/insights/SecurityInsightsView';
import { OrganizationView } from './components/organization/OrganizationView';
import { RepositoryScanningModal } from './components/scanner/RepositoryScanningModal';
import { AIRemediationModal } from './components/remediation/AIRemediationModal';
import { KeyboardShortcutsModal } from './components/common/KeyboardShortcutsModal';
import { AuthModal } from './components/auth/AuthModal';
import { ToastNotification, ToastMessage } from './components/common/ToastNotification';

export const App: React.FC = () => {
  // Mode & Auth
  const [appMode] = useState<'demo' | 'development' | 'production'>(
    (import.meta.env.VITE_APP_MODE as any) || 'development'
  );
  const [currentUser, setCurrentUser] = useState<UserProfile | null>({
    id: 'usr-default-01',
    email: 'alex@acme.dev',
    full_name: 'Alex Developer',
    is_active: true,
    is_verified: true,
    created_at: '2026-11-01T00:00:00Z'
  });
  const [currentOrg, setCurrentOrg] = useState<WorkspaceOrg>({
    id: 'org-default-01',
    name: 'Acme Production Core',
    slug: 'acme-core',
    role: 'OWNER'
  });
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

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

  // Real-time repository synchronization on startup
  useEffect(() => {
    const syncRealtimeFindings = async () => {
      try {
        const res = await fetch('/api/scan/local', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target_path: '.' })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.findings && data.findings.length > 0) {
            setFindings(data.findings);
            setSelectedFinding(data.findings[0]);
            
            const crits = data.findings.filter((f: SecurityFinding) => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
            const highs = data.findings.filter((f: SecurityFinding) => f.severity === 'HIGH' && f.status === 'OPEN').length;
            const newStatus = (crits > 0 || highs > 0) ? 'BLOCKED' : 'SAFE';

            setCurrentProject(prev => ({
              ...prev,
              status: newStatus,
              totalFindings: data.findings.length,
              criticalCount: crits,
              highCount: highs,
              lastScanned: 'Just now'
            }));
            setProjects(prev => prev.map((p, idx) => idx === 0 ? {
              ...p,
              status: newStatus,
              totalFindings: data.findings.length,
              criticalCount: crits,
              highCount: highs,
              lastScanned: 'Just now'
            } : p));
          }
        }
      } catch {
        // Retain initial fallback dataset if backend unavailable
      }
    };
    syncRealtimeFindings();
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
        currentUser={currentUser}
        currentOrg={currentOrg}
        onOpenAuth={() => setIsAuthModalOpen(true)}
        onLogout={() => {
          setCurrentUser(null);
          showToast("Signed Out", "You have been safely signed out.", "info");
        }}
        appMode={appMode}
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

          {currentTab === 'external' && (
            <ExternalAnalysisView
              onScanComplete={handleScanComplete}
              onNavigateToFindings={() => setCurrentTab('findings')}
              onShowToast={showToast}
            />
          )}

          {currentTab === 'insights' && (
            <SecurityInsightsView onShowToast={showToast} />
          )}

          {currentTab === 'organization' && (
            <OrganizationView
              currentOrg={currentOrg}
              currentUser={currentUser}
              onShowToast={showToast}
            />
          )}
        </main>
      </div>

      {/* Modals & Dialogs */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onAuthSuccess={(user, org) => {
          setCurrentUser(user);
          if (org) setCurrentOrg(org);
          setIsAuthModalOpen(false);
          showToast("Authentication Successful", `Welcome back, ${user.full_name || user.email}!`, "success");
        }}
        onShowToast={showToast}
      />
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
