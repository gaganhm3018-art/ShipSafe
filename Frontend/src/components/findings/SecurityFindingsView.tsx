import React, { useEffect } from 'react';
import { SecurityFinding } from '../../types/security';
import { FindingList } from './FindingList';
import { FindingInspector } from './FindingInspector';

interface SecurityFindingsViewProps {
  findings: SecurityFinding[];
  selectedFinding: SecurityFinding | null;
  onSelectFinding: (f: SecurityFinding) => void;
  onOpenRemediation: (f: SecurityFinding) => void;
  onMarkStatus: (findingId: string, newStatus: 'OPEN' | 'REMEDIATED' | 'IGNORED') => void;
  onRescanFile: (filePath: string) => void;
  onShowToast: (title: string, message?: string, type?: 'success' | 'info' | 'error') => void;
}

export const SecurityFindingsView: React.FC<SecurityFindingsViewProps> = ({
  findings,
  selectedFinding,
  onSelectFinding,
  onOpenRemediation,
  onMarkStatus,
  onRescanFile,
  onShowToast
}) => {
  // Developer Keyboard shortcuts: J (next), K (prev), R (remediate)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if user is typing in an input
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement)?.tagName)) {
        return;
      }

      if (e.key === 'j' || e.key === 'J') {
        e.preventDefault();
        if (!selectedFinding) {
          if (findings.length > 0) onSelectFinding(findings[0]);
        } else {
          const currentIndex = findings.findIndex(f => f.id === selectedFinding.id);
          if (currentIndex < findings.length - 1) {
            onSelectFinding(findings[currentIndex + 1]);
          }
        }
      } else if (e.key === 'k' || e.key === 'K') {
        e.preventDefault();
        if (!selectedFinding) {
          if (findings.length > 0) onSelectFinding(findings[0]);
        } else {
          const currentIndex = findings.findIndex(f => f.id === selectedFinding.id);
          if (currentIndex > 0) {
            onSelectFinding(findings[currentIndex - 1]);
          }
        }
      } else if (e.key === 'r' || e.key === 'R') {
        if (selectedFinding) {
          e.preventDefault();
          onOpenRemediation(selectedFinding);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [findings, selectedFinding, onSelectFinding, onOpenRemediation]);

  return (
    <div className="h-[calc(100vh-3.5rem)] grid grid-cols-1 md:grid-cols-12 overflow-hidden">
      {/* LEFT PANEL: 5 cols on desktop */}
      <div className="md:col-span-5 h-full overflow-hidden">
        <FindingList
          findings={findings}
          selectedFindingId={selectedFinding?.id || null}
          onSelectFinding={onSelectFinding}
        />
      </div>

      {/* RIGHT PANEL: 7 cols on desktop */}
      <div className="md:col-span-7 h-full overflow-hidden border-l border-border">
        <FindingInspector
          finding={selectedFinding}
          onOpenRemediation={onOpenRemediation}
          onMarkStatus={onMarkStatus}
          onRescanFile={onRescanFile}
          onShowToast={onShowToast}
        />
      </div>
    </div>
  );
};
