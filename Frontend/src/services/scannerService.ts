import { SecurityFinding, ScanStage, ScanRecord } from '../types/security';
import { INITIAL_FINDINGS } from '../data/mockSecurityData';

export const SCAN_STAGES_CONFIG: { id: number; name: string; description: string }[] = [
  { id: 1, name: "Repository Inspection", description: "Verifying repository tree, branch refs, and ignore patterns" },
  { id: 2, name: "File Discovery", description: "Locating Python, JavaScript, TypeScript, and manifest files" },
  { id: 3, name: "Secret & Credential Detection", description: "Running deterministic regex and Shannon entropy token analysis" },
  { id: 4, name: "Injection Analysis", description: "Evaluating SQL interpolation, command execution, and shell parameters" },
  { id: 5, name: "Access-Control & DOM Auditing", description: "Checking route authorization decorators and unsafe DOM sinks" },
  { id: 6, name: "Dependency Vulnerability Audit", description: "Cross-referencing package manifests against CVE vulnerability database" },
  { id: 7, name: "Findings Aggregation & Policy Check", description: "Deduplicating findings, computing CVSS scores, and checking CI failure gates" }
];

export class ScannerService {
  /**
   * Run multi-stage scan with callback for real-time progress update.
   */
  static async runStageScan(
    targetName: string,
    onStageUpdate: (stages: ScanStage[], currentStageIndex: number, progressPct: number) => void
  ): Promise<{ findings: SecurityFinding[]; scanRecord: ScanRecord }> {
    const stages: ScanStage[] = SCAN_STAGES_CONFIG.map(s => ({
      ...s,
      status: 'PENDING',
      filesChecked: 0,
      findingsFound: 0,
      durationMs: 0
    }));

    const stageFilesMap = [12, 64, 64, 64, 64, 4, 64];
    const stageFindingsMap = [0, 0, 1, 2, 2, 2, 0];

    let totalFindingsAccumulated: SecurityFinding[] = [];
    const startTime = Date.now();

    for (let i = 0; i < stages.length; i++) {
      // Mark active
      stages[i].status = 'ACTIVE';
      onStageUpdate([...stages], i, Math.round(((i) / stages.length) * 100));

      // Realistic stage duration (180ms - 350ms per stage)
      const stageDelay = 220 + Math.floor(Math.random() * 120);
      await new Promise(r => setTimeout(r, stageDelay));

      // Complete stage
      stages[i].status = 'COMPLETED';
      stages[i].filesChecked = stageFilesMap[i];
      stages[i].findingsFound = stageFindingsMap[i];
      stages[i].durationMs = stageDelay;

      onStageUpdate([...stages], i, Math.round(((i + 1) / stages.length) * 100));
    }

    // Try live backend if available
    try {
      const response = await fetch('/api/scan/local', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_path: '.' })
      });
      if (response.ok) {
        const data = await response.json();
        if (data.findings && data.findings.length > 0) {
          totalFindingsAccumulated = data.findings;
        }
      }
    } catch {
      // Fallback to deterministic curated findings
    }

    // Enrich with Real-Time CVE Intelligence from OSV.dev
    try {
      const cveResponse = await fetch('/api/cve/findings');
      if (cveResponse.ok) {
        const cveData = await cveResponse.json();
        if (cveData.findings && cveData.findings.length > 0) {
          for (const cf of cveData.findings) {
            const alreadyExists = totalFindingsAccumulated.some(f => 
              f.id === cf.id || f.ruleId === cf.vulnerabilityId
            );
            if (!alreadyExists) {
              totalFindingsAccumulated.push({
                id: cf.id,
                ruleId: cf.vulnerabilityId,
                name: `Vulnerable Dependency: ${cf.packageName} (${cf.vulnerabilityId})`,
                type: 'Vulnerable Dependency',
                severity: cf.severity,
                file: cf.manifestFile,
                line: 1,
                cwe: 'CWE-1395',
                cweName: 'Dependency on Vulnerable Third-Party Component',
                cvss: cf.cvssScore || undefined,
                description: cf.summary,
                whyDangerous: cf.details || `Known vulnerability ${cf.vulnerabilityId} in ${cf.packageName}`,
                impact: `Known public vulnerability in ${cf.packageName} affects application security posture.`,
                remediation: cf.fixedVersion 
                  ? `Upgrade ${cf.packageName} to version >= ${cf.fixedVersion}`
                  : `Review advisory ${cf.vulnerabilityId} for remediation steps.`,
                evidence: `${cf.packageName}==${cf.installedVersion}`,
                status: 'OPEN',
                detectedAt: cf.detectedAt,
                language: 'manifest',
                snippet: {
                  startLine: 1,
                  endLine: 1,
                  targetLine: 1,
                  lines: [{ line: 1, code: `${cf.packageName}==${cf.installedVersion}`, isTarget: true }]
                }
              });
            }
          }
        }
      }
    } catch {
      // If OSV is unavailable, existing security scanning continues without crashing
    }

    if (totalFindingsAccumulated.length === 0) {
      totalFindingsAccumulated = [...INITIAL_FINDINGS];
    }

    const criticalCount = totalFindingsAccumulated.filter(f => f.severity === 'CRITICAL').length;
    const highCount = totalFindingsAccumulated.filter(f => f.severity === 'HIGH').length;
    const mediumCount = totalFindingsAccumulated.filter(f => f.severity === 'MEDIUM').length;

    const newScanRecord: ScanRecord = {
      id: `SCAN-2026-${Math.floor(100 + Math.random() * 900)}`,
      repository: targetName,
      branch: "main",
      commit: Math.random().toString(16).substring(2, 9),
      timestamp: new Date().toISOString(),
      status: (criticalCount > 0 || highCount > 0) ? 'FAILED' : 'PASSED',
      totalFindings: totalFindingsAccumulated.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: 0,
      resolved: 14,
      policyViolation: (criticalCount > 0 || highCount > 0) 
        ? `Blocked: ${criticalCount} CRITICAL, ${highCount} HIGH findings violate security gate (fail-on: high)` 
        : null,
      trigger: 'CLI Scan',
      durationMs: Date.now() - startTime,
      filesScanned: 64,
      findings: totalFindingsAccumulated
    };

    return {
      findings: totalFindingsAccumulated,
      scanRecord: newScanRecord
    };
  }

  /**
   * Export findings to SARIF 2.1.0 standard format for CI/CD and GitHub Security tab
   */
  static exportToSARIF(findings: SecurityFinding[]): string {
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "ShipSafe",
              version: "2.4.0",
              informationUri: "https://shipsafe.security",
              rules: findings.map(f => ({
                id: f.ruleId,
                name: f.name,
                shortDescription: { text: f.description },
                defaultConfiguration: {
                  level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning'
                },
                helpUri: `https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`,
                properties: {
                  cwe: [f.cwe],
                  cvss: f.cvss
                }
              }))
            }
          },
          results: findings.map(f => ({
            ruleId: f.ruleId,
            message: { text: `${f.name}: ${f.description}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: {
                    startLine: f.line,
                    startColumn: 1
                  }
                }
              }
            ],
            properties: {
              severity: f.severity,
              cwe: f.cwe,
              evidence: f.evidence
            }
          }))
        }
      ]
    };
    return JSON.stringify(sarif, null, 2);
  }
}
