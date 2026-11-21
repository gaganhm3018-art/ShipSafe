export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type VulnerabilityType = 
  | 'Hardcoded Secret'
  | 'SQL Injection'
  | 'Command Injection'
  | 'Unsafe Code Execution'
  | 'DOM Manipulation (XSS)'
  | 'Missing Authentication'
  | 'Broken Object Level Authorization'
  | 'Vulnerable Dependency'
  | 'Insecure CORS Policy';

export type FindingStatus = 'OPEN' | 'IN_REVIEW' | 'REMEDIATED' | 'IGNORED';

export type ProgrammingLanguage = 'python' | 'javascript' | 'typescript' | 'manifest' | 'config';

export interface CodeLine {
  line: number;
  code: string;
  isTarget?: boolean;
}

export interface CodeSnippet {
  startLine: number;
  endLine: number;
  targetLine: number;
  lines: CodeLine[];
  raw?: string;
}

export interface SecurityFinding {
  id: string;
  ruleId: string;
  name: string;
  type: VulnerabilityType;
  severity: Severity;
  file: string;
  line: number;
  cwe: string;
  cweName?: string;
  cvss?: number;
  description: string;
  whyDangerous?: string;
  impact: string;
  remediation: string;
  evidence: string;
  status: FindingStatus;
  detectedAt: string;
  language: ProgrammingLanguage;
  snippet: CodeSnippet;
  remediationPatch?: {
    analysis: string;
    exploitScenario: string;
    whatChanged: string;
    originalCode: string;
    patchedCode: string;
    diffHunk: string;
  };
}

export interface ScanStage {
  id: number;
  name: string;
  description: string;
  status: 'PENDING' | 'ACTIVE' | 'COMPLETED' | 'FAILED';
  filesChecked?: number;
  findingsFound?: number;
  durationMs?: number;
}

export interface ScanRecord {
  id: string;
  repository: string;
  branch: string;
  commit: string;
  timestamp: string;
  status: 'PASSED' | 'FAILED' | 'WARNING';
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolved: number;
  policyViolation?: string | null;
  trigger: 'Pre-commit Hook' | 'GitHub Action (PR)' | 'CLI Scan' | 'Scheduled Scan';
  durationMs: number;
  filesScanned: number;
  findings?: SecurityFinding[];
}

export interface ProjectRepo {
  id: string;
  name: string;
  owner: string;
  language: 'Python' | 'TypeScript' | 'JavaScript' | 'Multi-language';
  lastScanned: string;
  status: 'SAFE' | 'AT_RISK' | 'BLOCKED';
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  branch: string;
  stars?: number;
  isDefault?: boolean;
}

export interface SecurityActivity {
  id: string;
  type: 'SCAN_COMPLETED' | 'VULNERABILITY_FOUND' | 'FIX_APPLIED' | 'COMMIT_BLOCKED';
  title: string;
  description: string;
  timestamp: string;
  severity?: Severity;
  repository: string;
  actor: string;
}

export interface SecurityPolicy {
  failOnSeverity: Severity;
  blockPRsOnCritical: boolean;
  blockPRsOnHigh: boolean;
  enableSecretEntropy: boolean;
  entropyThreshold: number;
  enableASTInjections: boolean;
  enableXSSChecks: boolean;
  enableAuthChecks: boolean;
  enableDependencyAudit: boolean;
  ignoredPaths: string[];
}
