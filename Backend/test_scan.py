from Scanner.engine import SecurityScannerEngine

sample_code = '''
import os
import subprocess

AWS_ACCESS_KEY_ID = "AKIA5T7V9EXAMPLE8391"
user_id = input()
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
subprocess.run(f"ping -c 1 {host}", shell=True)
'''

engine = SecurityScannerEngine()
findings = engine.scan_file_content("test_service.py", sample_code)
print(f"Total findings: {len(findings)}")
for f in findings:
    print(f"[{f['severity']}] {f['ruleId']} ({f['cwe']}): {f['name']} at line {f['line']}")
