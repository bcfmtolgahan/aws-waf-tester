#!/usr/bin/env python3
"""
WAF Rules Validator
Validates JSON structure, AWS WAF syntax, and checks for common issues
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class WAFRuleValidator:
    VALID_ACTIONS = ['Block', 'Allow', 'Count']
    VALID_TRANSFORMATIONS = [
        'NONE', 'COMPRESS_WHITE_SPACE', 'HTML_ENTITY_DECODE',
        'LOWERCASE', 'CMD_LINE', 'URL_DECODE', 'BASE64_DECODE',
        'HEX_DECODE', 'MD5', 'REPLACE_COMMENTS', 'ESCAPE_SEQ_DECODE',
        'SQL_HEX_DECODE', 'CSS_DECODE', 'JS_DECODE', 'NORMALIZE_PATH',
        'NORMALIZE_PATH_WIN', 'REMOVE_NULLS', 'REPLACE_NULLS',
        'BASE64_DECODE_EXT', 'URL_DECODE_UNI', 'UTF8_TO_UNICODE'
    ]

    VALID_FIELD_MATCHES = [
        'UriPath', 'QueryString', 'Body', 'Method', 'AllQueryArguments',
        'SingleHeader', 'SingleQueryArgument', 'Cookies', 'JsonBody'
    ]

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.info = []

    def validate_file(self, file_path: Path) -> Dict[str, Any]:
        """Validate a single rule file"""
        result = {
            'file': file_path.name,
            'valid': True,
            'errors': [],
            'warnings': [],
            'info': []
        }

        try:
            # Load JSON
            with open(file_path, 'r') as f:
                rule = json.load(f)

            # Required fields
            if 'Name' not in rule:
                result['errors'].append("Missing 'Name' field")
                result['valid'] = False

            if 'Priority' not in rule:
                result['errors'].append("Missing 'Priority' field")
                result['valid'] = False
            elif not isinstance(rule['Priority'], int):
                result['errors'].append("Priority must be an integer")
                result['valid'] = False

            if 'Statement' not in rule:
                result['errors'].append("Missing 'Statement' field")
                result['valid'] = False
            else:
                # Validate statement
                stmt_errors, stmt_warnings = self.validate_statement(rule['Statement'])
                result['errors'].extend(stmt_errors)
                result['warnings'].extend(stmt_warnings)

            if 'Action' not in rule:
                result['errors'].append("Missing 'Action' field")
                result['valid'] = False
            else:
                # Validate action
                action_keys = list(rule['Action'].keys())
                if not action_keys:
                    result['errors'].append("Action must have at least one key")
                    result['valid'] = False
                elif action_keys[0] not in self.VALID_ACTIONS:
                    result['warnings'].append(f"Unusual action: {action_keys[0]}")

            if 'VisibilityConfig' not in rule:
                result['warnings'].append("Missing 'VisibilityConfig' (recommended)")

            # Additional checks
            if 'Name' in rule:
                result['info'].append(f"Rule name: {rule['Name']}")
            if 'Priority' in rule:
                result['info'].append(f"Priority: {rule['Priority']}")

            # Check for common regex issues
            if 'Statement' in rule:
                regex_warnings = self.check_regex_patterns(rule['Statement'])
                result['warnings'].extend(regex_warnings)

        except json.JSONDecodeError as e:
            result['errors'].append(f"JSON parse error: {e}")
            result['valid'] = False
        except Exception as e:
            result['errors'].append(f"Unexpected error: {e}")
            result['valid'] = False

        if result['errors']:
            result['valid'] = False

        return result

    def validate_statement(self, statement: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """Validate statement structure"""
        errors = []
        warnings = []

        # Check statement types
        valid_statement_types = [
            'ByteMatchStatement', 'SqliMatchStatement', 'XssMatchStatement',
            'SizeConstraintStatement', 'GeoMatchStatement', 'RuleGroupReferenceStatement',
            'IPSetReferenceStatement', 'RegexMatchStatement', 'RegexPatternSetReferenceStatement',
            'ManagedRuleGroupStatement', 'LabelMatchStatement', 'NotStatement',
            'AndStatement', 'OrStatement', 'RateBasedStatement'
        ]

        statement_keys = [k for k in statement.keys() if k.endswith('Statement')]

        if not statement_keys:
            errors.append("Statement must contain at least one *Statement key")
            return errors, warnings

        # Validate specific statement types
        for stmt_type in statement_keys:
            if stmt_type not in valid_statement_types:
                warnings.append(f"Unknown statement type: {stmt_type}")

            stmt_content = statement[stmt_type]

            # RegexMatchStatement validation
            if stmt_type == 'RegexMatchStatement':
                if 'RegexString' not in stmt_content:
                    errors.append("RegexMatchStatement missing 'RegexString'")
                if 'FieldToMatch' not in stmt_content:
                    errors.append("RegexMatchStatement missing 'FieldToMatch'")
                if 'TextTransformations' not in stmt_content:
                    warnings.append("RegexMatchStatement missing TextTransformations")

                # Validate transformations
                if 'TextTransformations' in stmt_content:
                    for transform in stmt_content['TextTransformations']:
                        if 'Type' in transform and transform['Type'] not in self.VALID_TRANSFORMATIONS:
                            warnings.append(f"Unknown transformation type: {transform['Type']}")

            # ByteMatchStatement validation
            elif stmt_type == 'ByteMatchStatement':
                if 'SearchString' not in stmt_content:
                    errors.append("ByteMatchStatement missing 'SearchString'")
                if 'FieldToMatch' not in stmt_content:
                    errors.append("ByteMatchStatement missing 'FieldToMatch'")
                if 'PositionalConstraint' not in stmt_content:
                    errors.append("ByteMatchStatement missing 'PositionalConstraint'")

            # OrStatement / AndStatement validation
            elif stmt_type in ['OrStatement', 'AndStatement']:
                if 'Statements' not in stmt_content:
                    errors.append(f"{stmt_type} missing 'Statements' array")
                else:
                    # Recursively validate sub-statements
                    for sub_stmt in stmt_content['Statements']:
                        sub_errors, sub_warnings = self.validate_statement(sub_stmt)
                        errors.extend(sub_errors)
                        warnings.extend(sub_warnings)

        return errors, warnings

    def check_regex_patterns(self, statement: Dict[str, Any]) -> List[str]:
        """Check for common regex issues"""
        warnings = []

        def check_regex(regex_str: str):
            # Check for unescaped special characters that might cause issues
            if '\\' in regex_str:
                # Check for proper escaping
                if regex_str.count('\\') != regex_str.count('\\\\') // 2 + regex_str.count('\\\\') % 2:
                    warnings.append(f"Potential escaping issue in regex: {regex_str[:50]}...")

            # Check for overly broad patterns
            if regex_str == '.*':
                warnings.append("Very broad regex pattern '.*' detected")

            # Check for complex patterns that might be expensive
            if regex_str.count('.*') > 3:
                warnings.append(f"Complex regex with multiple '.*': {regex_str[:50]}...")

        # Recursively find all regex patterns
        def find_regex_patterns(obj):
            if isinstance(obj, dict):
                if 'RegexString' in obj:
                    check_regex(obj['RegexString'])
                for value in obj.values():
                    find_regex_patterns(value)
            elif isinstance(obj, list):
                for item in obj:
                    find_regex_patterns(item)

        find_regex_patterns(statement)
        return warnings

def main():
    print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}AWS WAF RULES VALIDATOR{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")

    validator = WAFRuleValidator()
    rules_dir = Path('waf-rules')

    if not rules_dir.exists():
        print(f"{Colors.RED}❌ Rules directory not found: {rules_dir}{Colors.RESET}")
        return 1

    # Collect all JSON files
    rule_files = sorted(rules_dir.glob('*.json'))

    if not rule_files:
        print(f"{Colors.RED}❌ No rule files found in {rules_dir}{Colors.RESET}")
        return 1

    print(f"{Colors.CYAN}Found {len(rule_files)} rule files{Colors.RESET}\n")

    # Validate each file
    results = []
    for rule_file in rule_files:
        result = validator.validate_file(rule_file)
        results.append(result)

        # Print result
        if result['valid']:
            print(f"{Colors.GREEN}✅ {result['file']}{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ {result['file']}{Colors.RESET}")

        for info in result['info']:
            print(f"   {Colors.CYAN}ℹ️  {info}{Colors.RESET}")

        for error in result['errors']:
            print(f"   {Colors.RED}❌ {error}{Colors.RESET}")

        for warning in result['warnings']:
            print(f"   {Colors.YELLOW}⚠️  {warning}{Colors.RESET}")

        print()

    # Summary
    valid_count = sum(1 for r in results if r['valid'])
    invalid_count = len(results) - valid_count
    total_errors = sum(len(r['errors']) for r in results)
    total_warnings = sum(len(r['warnings']) for r in results)

    print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}VALIDATION SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")

    print(f"Total Files: {len(results)}")
    print(f"{Colors.GREEN}Valid: {valid_count}{Colors.RESET}")
    print(f"{Colors.RED}Invalid: {invalid_count}{Colors.RESET}")
    print(f"{Colors.RED}Total Errors: {total_errors}{Colors.RESET}")
    print(f"{Colors.YELLOW}Total Warnings: {total_warnings}{Colors.RESET}\n")

    # Check for priority conflicts
    print(f"{Colors.BOLD}Priority Check:{Colors.RESET}")
    priorities = {}
    for result in results:
        if result['valid']:
            # Re-read file to get priority
            file_path = rules_dir / result['file']
            with open(file_path, 'r') as f:
                rule = json.load(f)
                priority = rule.get('Priority')
                name = rule.get('Name')
                if priority in priorities:
                    priorities[priority].append(name)
                else:
                    priorities[priority] = [name]

    conflicts = {p: names for p, names in priorities.items() if len(names) > 1}

    if conflicts:
        print(f"{Colors.RED}❌ Priority conflicts found:{Colors.RESET}")
        for priority, names in conflicts.items():
            print(f"   Priority {priority}: {', '.join(names)}")
    else:
        print(f"{Colors.GREEN}✅ No priority conflicts{Colors.RESET}")
        print(f"   Priority range: {min(priorities.keys())} - {max(priorities.keys())}")

    print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}\n")

    if invalid_count > 0 or total_errors > 0:
        print(f"{Colors.RED}{Colors.BOLD}❌ VALIDATION FAILED{Colors.RESET}")
        return 1
    elif total_warnings > 0:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  VALIDATION PASSED WITH WARNINGS{Colors.RESET}")
        return 0
    else:
        print(f"{Colors.GREEN}{Colors.BOLD}✅ VALIDATION PASSED{Colors.RESET}")
        return 0

if __name__ == "__main__":
    exit(main())
