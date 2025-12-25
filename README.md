# AWS WAF Security Testing Framework

A framework for developing, deploying, and testing AWS WAF rules with 500+ real-world attack scenarios.

## Features

- 36 custom WAF rules for different security threats
- 100+ attack payloads (SQLi, XSS, Command Injection, Path Traversal, SSRF, etc.)
- Automated rule validation and AWS deployment
- Detailed security reports and metrics
- CI/CD ready

## Installation

```bash
# Clone the repository
git clone https://github.com/bcfmtolgahan/aws-waf-tester.git
cd aws-waf-tester

# Install dependencies
pip install boto3 requests aiohttp

# Configure AWS credentials
aws configure
```

## Quick Start

### 1. Validate WAF Rules

```bash
python3 validate-rules.py
```

Output:
```
✅ SQLInjectionAdvanced.json
✅ XSSAdvanced.json
✅ CommandInjectionAdvanced.json
...

VALIDATION SUMMARY
Total Files: 36
Valid: 36
Invalid: 0
✅ No priority conflicts
```

### 2. Deploy to AWS WAF

```bash
# Test with dry-run first
python3 apply-waf-rules.py MyWebACL --dry-run

# Deploy to production
python3 apply-waf-rules.py MyWebACL --scope REGIONAL --region us-east-1

# For CloudFront
python3 apply-waf-rules.py MyWebACL --scope CLOUDFRONT
```

**Options:**
- `--scope`: `REGIONAL` or `CLOUDFRONT` (default: REGIONAL)
- `--region`: AWS region (default: us-east-1)
- `--rules-dir`: Rules directory (default: waf-rules)
- `--dry-run`: Validate only, don't deploy
- `--list`: List current rules

### 3. Run Penetration Tests

```bash
# Basic test
python3 waf-tester.py https://your-app.com

# With advanced options
python3 waf-tester.py https://your-app.com \
  --threads 20 \
  --timeout 10 \
  --proxy http://127.0.0.1:8080
```

**Options:**
- `--threads N`: Number of parallel threads (default: 10)
- `--timeout N`: Request timeout in seconds (default: 15)
- `--proxy URL`: Use HTTP/HTTPS proxy

## Test Categories

The framework includes 500+ attack scenarios:

| Category | Tests | Bypass Techniques |
|----------|-------|-------------------|
| SQL Injection | 100+ | Union-based, Blind, Time-based, Comment obfuscation, Encoding |
| XSS | 150+ | SVG, Event handlers, Template injection, Unicode bypass |
| Command Injection | 80+ | Wildcard, IFS manipulation, Quote escaping, Reverse shells |
| Path Traversal | 50+ | URL encoding, Double encoding, Null byte, UNC paths |
| SSRF | 40+ | Cloud metadata, Protocol smuggling, IP bypass |
| Other | 80+ | XXE, LDAP, NoSQL, SSTI, RCE, Log4Shell |

## Test Results

After testing, a detailed report is generated:

```
COMPREHENSIVE TEST SUMMARY
================================================================================

Total Tests: 520
Duration: 152.34s
✅ Blocked (GOOD): 478
❌ Allowed (BAD): 42
⚠️  Suspicious: 8

Security Score: 91.9%
Rating: EXCELLENT 🛡️🛡️🛡️

📄 Detailed report saved to: waf_test_report_20241225_143022.json
```

### JSON Report Format

```json
{
  "timestamp": "2024-12-25T14:30:22.123456",
  "target": "https://your-app.com",
  "summary": {
    "total": 520,
    "blocked": 478,
    "allowed": 42,
    "security_score": "91.9%",
    "risk_score": "15.3%"
  },
  "severity_breakdown": {
    "critical": 5,
    "high": 12,
    "medium": 18,
    "low": 7
  },
  "details": {
    "blocked": [...],
    "allowed": [...],
    "suspicious": [...]
  }
}
```

## WAF Rules

The `waf-rules/` directory contains 36 rules for different threats:

**Core Threats:**
- `SQLInjectionAdvanced.json` - SQL injection attacks
- `XSSAdvanced.json` - Cross-Site Scripting
- `CommandInjectionAdvanced.json` - Command injection
- `PathTraversal.json` - Directory traversal
- `SSRFAdvanced.json` - Server-Side Request Forgery

**Advanced Threats:**
- `Log4ShellProtection.json` - Log4j vulnerability
- `PrototypePollutionProtection.json` - JavaScript prototype pollution
- `XXEProtection.json` - XML External Entity
- `SSTIProtection.json` - Server-Side Template Injection
- `DeserializationProtection.json` - Unsafe deserialization

**Other Rules:**
- NoSQL Injection, LDAP Injection, CRLF Injection
- File Upload Protection, Directory Listing
- Malicious User Agents, Rate Limiting
- Cloud metadata SSRF, Internal CIDR blocking

## Rule Example

### SQL Injection Rule

```json
{
  "Name": "SQLInjectionAdvanced",
  "Priority": 100,
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "RegexMatchStatement": {
            "RegexString": "(union|select|insert).*\\s*(from|into|where)",
            "FieldToMatch": {"AllQueryArguments": {}},
            "TextTransformations": [
              {"Priority": 0, "Type": "URL_DECODE"},
              {"Priority": 1, "Type": "HTML_ENTITY_DECODE"},
              {"Priority": 2, "Type": "LOWERCASE"}
            ]
          }
        }
      ]
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "CloudWatchMetricsEnabled": true,
    "MetricName": "SQLInjectionAdvanced"
  }
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: WAF Security Test
on:
  schedule:
    - cron: '0 2 * * 1'  # Every Monday at 02:00

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: pip install boto3 requests aiohttp

      - name: Validate Rules
        run: python3 validate-rules.py

      - name: Deploy to Staging
        run: python3 apply-waf-rules.py StagingWebACL
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

      - name: Run Security Tests
        run: python3 waf-tester.py https://staging.example.com

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: waf-test-report
          path: waf_test_report_*.json
```

## Requirements

- Python 3.7+
- boto3 (AWS SDK)
- requests
- aiohttp
- AWS account with credentials
- AWS WAF Web ACL (REGIONAL or CLOUDFRONT)

## AWS IAM Permissions

Required AWS IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "wafv2:GetWebACL",
        "wafv2:ListWebACLs",
        "wafv2:UpdateWebACL"
      ],
      "Resource": "*"
    }
  ]
}
```

## Security Warning

⚠️ **IMPORTANT**: Use this tool only on:

- Systems you own
- Applications you have written permission to test
- Authorized penetration testing engagements
- Development and staging environments

Unauthorized use is **illegal** and may result in serious legal consequences.

## Performance Tips

- **Threads**: Higher threads (20+) speed up tests but may trigger rate limiting
- **Timeout**: Increase timeout (20-30s) for slow networks
- **Proxy**: Use `--proxy` with Burp Suite for detailed analysis
- **Target**: Test on staging first, be careful with production

## Troubleshooting

### Rate Limiting

```
⏱️ RATE LIMITED
```

**Solution**: Reduce thread count or increase `time.sleep()` delay.

### Capacity Error

```
❌ Error: WCU capacity exceeded
```

**Solution**: Disable some rules or simplify regex patterns. AWS WAF limit is 5000 WCU.

### Connection Timeout

```
⏱️ TIMEOUT
```

**Solution**: Increase `--timeout` or check if target is accessible.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Commit your changes (`git commit -am 'Add new rule'`)
4. Push to the branch (`git push origin feature/new-rule`)
5. Create a Pull Request

