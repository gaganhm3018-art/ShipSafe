import React, { useState } from 'react';
import { 
  X, 
  HardDrive, 
  FileCode, 
  ShieldAlert, 
  Play, 
  FolderSearch, 
  Check, 
  AlertCircle,
  HelpCircle,
  GitBranch
} from 'lucide-react';
import { GithubIcon } from '../common/Icons';
import { ScanStage, SecurityFinding, ScanRecord } from '../../types/security';
import { ScanProgress } from './ScanProgress';
import { ScannerService, SCAN_STAGES_CONFIG } from '../../services/scannerService';

interface RepositoryScanningModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: (findings: SecurityFinding[], record: ScanRecord) => void;
}

export const RepositoryScanningModal: React.FC<RepositoryScanningModalProps> = ({
  isOpen,
  onClose,
  onScanComplete
}) => {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState<'local' | 'github'>('local');
  const [localPath, setLocalPath] = useState('./backend');
  const [selectedGithubRepo, setSelectedGithubRepo] = useState('ShipSafe-Core/api-service');
  const [selectedBranch, setSelectedBranch] = useState('main');

  // Scanning execution state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStages, setScanStages] = useState<ScanStage[]>([]);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [progressPct, setProgressPct] = useState(0);
  const [completedResults, setCompletedResults] = useState<{ findings: SecurityFinding[]; scanRecord: ScanRecord } | null>(null);

  const startScan = async () => {
    setIsScanning(true);
    setProgressPct(0);
    const targetName = activeTab === 'local' ? localPath : selectedGithubRepo;

    try {
      const results = await ScannerService.runStageScan(
        targetName,
        (stages, idx, pct) => {
          setScanStages(stages);
          setCurrentStageIdx(idx);
          setProgressPct(pct);
        }
      );
      setCompletedResults(results);
      setIsScanning(false);
    } catch (err) {
      setIsScanning(false);
    }
  };

  const handleFinish = () => {
    if (completedResults) {
      onScanComplete(completedResults.findings, completedResults.scanRecord);
      onClose();
    }
  };

  const githubRepos = [
    { name: 'ShipSafe-Core/api-service', branch: 'main', lang: 'Python', stars: 34 },
    { name: 'ShipSafe-Core/web-frontend', branch: 'main', lang: 'TypeScript', stars: 58 },
    { name: 'ShipSafe-Core/auth-gateway', branch: 'feature/oauth2-pkce', lang: 'Python', stars: 19 },
    { name: 'ShipSafe-Core/data-pipeline', branch: 'main', lang: 'Python', stars: 12 }
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-2xl bg-bg-secondary border border-border rounded-lg shadow-elevated overflow-hidden animate-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-bg-elevated/40">
          <div>
            <h3 className="text-sm font-bold text-text-primary flex items-center gap-2">
              <FolderSearch className="w-4 h-4 text-accent-primary" />
              Repository Security Audit
            </h3>
            <p className="text-xs text-text-muted mt-0.5">
              Deterministic AST rules, credential pattern matching, and dependency CVE checks
            </p>
          </div>
          <button
            onClick={onClose}
            disabled={isScanning}
            className="text-text-muted hover:text-text-primary transition-colors p-1 rounded hover:bg-bg-elevated disabled:opacity-50"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6">
          {isScanning || completedResults ? (
            /* Active / Completed Scanning Stage View */
            <ScanProgress
              stages={scanStages}
              currentStageIndex={currentStageIdx}
              progressPct={progressPct}
              targetName={activeTab === 'local' ? localPath : selectedGithubRepo}
              isScanning={isScanning}
              onFinishScan={handleFinish}
            />
          ) : (
            /* Onboarding Options */
            <div className="space-y-5">
              {/* Tabs: Local vs GitHub */}
              <div className="grid grid-cols-2 gap-2 p-1 rounded bg-bg-main border border-border font-mono text-xs">
                <button
                  onClick={() => setActiveTab('local')}
                  className={`flex items-center justify-center gap-2 py-2 rounded transition-colors ${
                    activeTab === 'local'
                      ? 'bg-bg-elevated text-text-primary font-semibold shadow-sm'
                      : 'text-text-secondary hover:text-text-primary'
                  }`}
                >
                  <HardDrive className="w-4 h-4" />
                  <span>Option A: Local Repository</span>
                </button>
                <button
                  onClick={() => setActiveTab('github')}
                  className={`flex items-center justify-center gap-2 py-2 rounded transition-colors ${
                    activeTab === 'github'
                      ? 'bg-bg-elevated text-text-primary font-semibold shadow-sm'
                      : 'text-text-secondary hover:text-text-primary'
                  }`}
                >
                  <GithubIcon className="w-4 h-4" />
                  <span>Option B: GitHub Repository</span>
                </button>
              </div>

              {/* Tab 1: Local repository */}
              {activeTab === 'local' && (
                <div className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-mono font-medium text-text-secondary">
                      Directory / Workspace Path:
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={localPath}
                        onChange={(e) => setLocalPath(e.target.value)}
                        placeholder="./my-service or /path/to/repo"
                        className="flex-1 bg-bg-main border border-border rounded px-3 py-2 text-xs font-mono text-text-primary focus:outline-none focus:border-accent-secondary"
                      />
                    </div>
                  </div>

                  {/* Supported file types */}
                  <div className="p-3 rounded bg-bg-elevated/40 border border-border space-y-2">
                    <div className="text-[11px] font-mono font-semibold text-text-primary flex items-center justify-between">
                      <span>Supported File Types</span>
                      <span className="text-accent-primary text-[10px]">Deterministic Engine</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                      {['.py (Python)', '.js / .ts (Node/React)', '.jsx / .tsx', 'package.json', 'requirements.txt', '.env / .conf'].map(ext => (
                        <span key={ext} className="px-2 py-0.5 rounded bg-bg-main border border-border text-text-secondary">
                          {ext}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Scanning Scope */}
                  <div className="p-3 rounded bg-bg-elevated/20 border border-border/80 text-xs text-text-secondary space-y-1">
                    <div className="font-semibold text-text-primary">Scanning Scope & Privacy:</div>
                    <p className="text-[11px] leading-relaxed">
                      All deterministic security rules run locally in-memory. Code is never uploaded to external servers or used to train public models. Only selected findings are sent to the LLM when you request remediation diffs.
                    </p>
                  </div>
                </div>
              )}

              {/* Tab 2: GitHub repository */}
              {activeTab === 'github' && (
                <div className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="text-xs font-mono font-medium text-text-secondary">
                      Select Connected GitHub Repository:
                    </label>
                    <div className="border border-border rounded divide-y divide-border bg-bg-main">
                      {githubRepos.map(repo => (
                        <div
                          key={repo.name}
                          onClick={() => {
                            setSelectedGithubRepo(repo.name);
                            setSelectedBranch(repo.branch);
                          }}
                          className={`p-3 flex items-center justify-between cursor-pointer transition-colors ${
                            selectedGithubRepo === repo.name ? 'bg-bg-elevated text-accent-primary' : 'hover:bg-bg-secondary'
                          }`}
                        >
                          <div className="space-y-0.5 font-mono text-xs">
                            <div className="font-semibold text-text-primary">{repo.name}</div>
                            <div className="text-[11px] text-text-muted flex items-center gap-2">
                              <span className="flex items-center gap-1">
                                <GitBranch className="w-3 h-3" />
                                {repo.branch}
                              </span>
                              <span>•</span>
                              <span>{repo.lang}</span>
                            </div>
                          </div>
                          {selectedGithubRepo === repo.name && (
                            <Check className="w-4 h-4 text-accent-primary" />
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="p-3 rounded bg-bg-elevated/40 border border-border text-xs text-text-secondary flex items-center justify-between">
                    <span className="font-mono text-[11px]">GitHub App Integration: Connected as AcmeOrg</span>
                    <span className="text-accent-primary font-mono text-[10px] font-semibold">Webhooks Active</span>
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="pt-2 flex items-center justify-end gap-2 border-t border-border">
                <button
                  onClick={onClose}
                  className="px-4 py-2 text-xs text-text-secondary hover:text-text-primary rounded border border-border hover:bg-bg-elevated transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={startScan}
                  className="px-5 py-2 rounded bg-accent-primary hover:bg-accent-primary-hover text-[#0B0F14] text-xs font-bold font-mono transition-colors shadow-subtle flex items-center gap-2"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Start Deterministic Scan</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
