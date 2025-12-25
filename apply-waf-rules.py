#!/usr/bin/env python3
"""
AWS WAF Rules Apply Script
Applies custom WAF rules to AWS WAF Web ACL
"""

import boto3
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class WAFRuleApplier:
    def __init__(self, web_acl_name: str, scope: str = 'REGIONAL', region: str = 'us-east-1'):
        """
        Initialize WAF Rule Applier

        Args:
            web_acl_name: Name of the Web ACL
            scope: CLOUDFRONT or REGIONAL
            region: AWS region (for REGIONAL scope)
        """
        self.web_acl_name = web_acl_name
        self.scope = scope
        self.region = region

        # Initialize boto3 client
        if scope == 'CLOUDFRONT':
            self.wafv2 = boto3.client('wafv2', region_name='us-east-1')
        else:
            self.wafv2 = boto3.client('wafv2', region_name=region)

        self.web_acl_id = None
        self.lock_token = None

    def get_web_acl(self):
        """Get Web ACL details"""
        try:
            print(f"\n{Colors.CYAN}[INFO]{Colors.RESET} Fetching Web ACL: {Colors.YELLOW}{self.web_acl_name}{Colors.RESET}")

            # List all Web ACLs
            response = self.wafv2.list_web_acls(Scope=self.scope)

            for acl in response.get('WebACLs', []):
                if acl['Name'] == self.web_acl_name:
                    self.web_acl_id = acl['Id']

                    # Get detailed Web ACL info
                    acl_details = self.wafv2.get_web_acl(
                        Name=self.web_acl_name,
                        Scope=self.scope,
                        Id=self.web_acl_id
                    )

                    self.lock_token = acl_details['LockToken']

                    print(f"{Colors.GREEN}✅ Found Web ACL{Colors.RESET}")
                    print(f"   ID: {self.web_acl_id}")
                    print(f"   Capacity: {acl_details['WebACL']['Capacity']} WCU")
                    print(f"   Current Rules: {len(acl_details['WebACL']['Rules'])}")

                    return acl_details['WebACL']

            print(f"{Colors.RED}❌ Web ACL '{self.web_acl_name}' not found!{Colors.RESET}")
            return None

        except Exception as e:
            print(f"{Colors.RED}❌ Error fetching Web ACL: {e}{Colors.RESET}")
            return None

    def load_rule_files(self, rules_dir: str = 'waf-rules') -> List[Dict[str, Any]]:
        """Load all rule JSON files from directory"""
        rules = []
        rules_path = Path(rules_dir)

        if not rules_path.exists():
            print(f"{Colors.RED}❌ Rules directory not found: {rules_dir}{Colors.RESET}")
            return rules

        print(f"\n{Colors.CYAN}[INFO]{Colors.RESET} Loading rule files from: {Colors.YELLOW}{rules_dir}{Colors.RESET}")

        for rule_file in sorted(rules_path.glob('*.json')):
            try:
                with open(rule_file, 'r') as f:
                    rule = json.load(f)
                    rules.append(rule)
                    print(f"{Colors.GREEN}✅{Colors.RESET} Loaded: {rule_file.name} - {rule.get('Name', 'Unknown')}")
            except Exception as e:
                print(f"{Colors.RED}❌{Colors.RESET} Error loading {rule_file.name}: {e}")

        print(f"\n{Colors.BOLD}Total rules loaded: {len(rules)}{Colors.RESET}")
        return rules

    def validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate rule structure"""
        required_fields = ['Name', 'Priority', 'Statement', 'Action', 'VisibilityConfig']

        for field in required_fields:
            if field not in rule:
                print(f"{Colors.RED}❌ Rule missing field: {field}{Colors.RESET}")
                return False

        return True

    def calculate_rule_capacity(self, rule: Dict[str, Any]) -> int:
        """
        Estimate rule capacity (WCU - Web ACL Capacity Unit)
        This is a rough estimate, actual capacity is calculated by AWS
        """
        base_capacity = 1

        # Check statement type
        statement = rule.get('Statement', {})

        # OrStatement increases capacity
        if 'OrStatement' in statement:
            sub_statements = len(statement['OrStatement'].get('Statements', []))
            base_capacity += sub_statements

        # AndStatement increases capacity
        if 'AndStatement' in statement:
            sub_statements = len(statement['AndStatement'].get('Statements', []))
            base_capacity += sub_statements

        # RegexMatchStatement is more expensive
        if 'RegexMatchStatement' in statement or any(
            'RegexMatchStatement' in s for s in statement.get('OrStatement', {}).get('Statements', [])
        ):
            base_capacity += 3

        # Text transformations add capacity
        for key in statement:
            if isinstance(statement[key], dict):
                transformations = statement[key].get('TextTransformations', [])
                base_capacity += len(transformations) * 0.5

        return int(base_capacity)

    def apply_rules(self, rules: List[Dict[str, Any]], dry_run: bool = False):
        """Apply rules to Web ACL"""

        # Get current Web ACL
        web_acl = self.get_web_acl()
        if not web_acl:
            return False

        # Validate all rules
        print(f"\n{Colors.CYAN}[INFO]{Colors.RESET} Validating rules...")
        valid_rules = []
        total_capacity = 0

        for rule in rules:
            if self.validate_rule(rule):
                valid_rules.append(rule)
                capacity = self.calculate_rule_capacity(rule)
                total_capacity += capacity
                print(f"{Colors.GREEN}✅{Colors.RESET} Valid: {rule['Name']} (est. ~{capacity} WCU)")
            else:
                print(f"{Colors.RED}❌{Colors.RESET} Invalid: {rule.get('Name', 'Unknown')}")

        print(f"\n{Colors.BOLD}Valid rules: {len(valid_rules)}/{len(rules)}{Colors.RESET}")
        print(f"{Colors.BOLD}Estimated total capacity: ~{total_capacity} WCU{Colors.RESET}")
        print(f"{Colors.YELLOW}Note: AWS Web ACL limit is 5000 WCU{Colors.RESET}")

        if total_capacity > 5000:
            print(f"{Colors.RED}⚠️  WARNING: Estimated capacity exceeds AWS limit!{Colors.RESET}")

        if dry_run:
            print(f"\n{Colors.YELLOW}[DRY RUN]{Colors.RESET} Rules validated but not applied")
            return True

        # Confirm before applying
        print(f"\n{Colors.YELLOW}⚠️  This will update the Web ACL: {self.web_acl_name}{Colors.RESET}")
        confirmation = input(f"{Colors.CYAN}Continue? (yes/no): {Colors.RESET}")

        if confirmation.lower() != 'yes':
            print(f"{Colors.YELLOW}Operation cancelled{Colors.RESET}")
            return False

        # Apply rules
        try:
            print(f"\n{Colors.CYAN}[INFO]{Colors.RESET} Applying rules to Web ACL...")

            # Merge with existing rules (keep non-custom rules)
            existing_rules = web_acl.get('Rules', [])
            custom_rule_names = {rule['Name'] for rule in valid_rules}

            # Keep existing rules that are not being replaced
            final_rules = [r for r in existing_rules if r['Name'] not in custom_rule_names]

            # Add new rules
            final_rules.extend(valid_rules)

            # Sort by priority
            final_rules.sort(key=lambda x: x.get('Priority', 0))

            # Update Web ACL
            response = self.wafv2.update_web_acl(
                Name=self.web_acl_name,
                Scope=self.scope,
                Id=self.web_acl_id,
                DefaultAction=web_acl['DefaultAction'],
                Rules=final_rules,
                VisibilityConfig=web_acl['VisibilityConfig'],
                LockToken=self.lock_token
            )

            print(f"\n{Colors.GREEN}✅ Successfully applied {len(valid_rules)} rules to Web ACL!{Colors.RESET}")
            print(f"{Colors.GREEN}✅ New Lock Token: {response['NextLockToken']}{Colors.RESET}")

            return True

        except Exception as e:
            print(f"\n{Colors.RED}❌ Error applying rules: {e}{Colors.RESET}")

            # Check if it's a capacity error
            if 'WCU' in str(e) or 'capacity' in str(e).lower():
                print(f"{Colors.YELLOW}💡 Tip: Try reducing the number of rules or simplify regex patterns{Colors.RESET}")

            return False

    def list_current_rules(self):
        """List current rules in Web ACL"""
        web_acl = self.get_web_acl()
        if not web_acl:
            return

        rules = web_acl.get('Rules', [])

        print(f"\n{Colors.BOLD}Current Rules in Web ACL:{Colors.RESET}")
        print(f"{'='*80}")

        for i, rule in enumerate(rules, 1):
            print(f"\n{i}. {Colors.CYAN}{rule['Name']}{Colors.RESET}")
            print(f"   Priority: {rule.get('Priority', 'N/A')}")
            print(f"   Action: {list(rule.get('Action', {}).keys())[0] if rule.get('Action') else 'N/A'}")

            metric_name = rule.get('VisibilityConfig', {}).get('MetricName', 'N/A')
            print(f"   Metric: {metric_name}")

def main():
    print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}AWS WAF RULES APPLY SCRIPT{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")

    # Parse arguments
    if len(sys.argv) < 2:
        print(f"\n{Colors.RED}Usage: python3 apply-waf-rules.py <WEB_ACL_NAME> [options]{Colors.RESET}")
        print(f"\nOptions:")
        print(f"  --scope SCOPE       CLOUDFRONT or REGIONAL (default: REGIONAL)")
        print(f"  --region REGION     AWS region (default: us-east-1)")
        print(f"  --rules-dir DIR     Rules directory (default: waf-rules)")
        print(f"  --dry-run           Validate only, don't apply")
        print(f"  --list              List current rules")
        print(f"\nExamples:")
        print(f"  python3 apply-waf-rules.py MyWebACL")
        print(f"  python3 apply-waf-rules.py MyWebACL --scope CLOUDFRONT")
        print(f"  python3 apply-waf-rules.py MyWebACL --dry-run")
        print(f"  python3 apply-waf-rules.py MyWebACL --list")
        sys.exit(1)

    web_acl_name = sys.argv[1]
    scope = 'REGIONAL'
    region = 'us-east-1'
    rules_dir = 'waf-rules'
    dry_run = False
    list_only = False

    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--scope' and i + 1 < len(sys.argv):
            scope = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--region' and i + 1 < len(sys.argv):
            region = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--rules-dir' and i + 1 < len(sys.argv):
            rules_dir = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--dry-run':
            dry_run = True
            i += 1
        elif sys.argv[i] == '--list':
            list_only = True
            i += 1
        else:
            i += 1

    # Initialize applier
    applier = WAFRuleApplier(web_acl_name, scope, region)

    # List current rules if requested
    if list_only:
        applier.list_current_rules()
        return

    # Load and apply rules
    rules = applier.load_rule_files(rules_dir)

    if not rules:
        print(f"\n{Colors.RED}❌ No rules loaded. Exiting.{Colors.RESET}")
        sys.exit(1)

    success = applier.apply_rules(rules, dry_run=dry_run)

    if success:
        print(f"\n{Colors.GREEN}{Colors.BOLD}✅ SUCCESS!{Colors.RESET}")
        sys.exit(0)
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ FAILED!{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
