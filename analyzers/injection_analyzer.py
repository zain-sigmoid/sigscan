# Flake8: noqa: E501
"""
Injection Attack Analyzer for detecting various injection vulnerabilities.
Analyzes SQL injection, XSS, command injection, and other injection attack vectors.
"""

import os
import re
import logging
import asyncio
import traceback
from utils.logs_service.logger import AppLogger
from typing import List, Dict, Any
from core.interfaces import SecurityAnalyzer
from core.file_utils import find_python_files
from core.models import (
    AnalysisConfiguration,
    AnalysisResult,
    AnalysisMetrics,
    UnifiedFinding,
    FindingCategory,
    SeverityLevel,
    ComplexityLevel,
    CodeLocation,
)

logger = AppLogger.get_logger(__name__)


class InjectionAnalyzer(SecurityAnalyzer):
    """
    Analyzer for detecting injection attack vulnerabilities in Python code.
    """

    def __init__(self):
        super().__init__("injection", "1.0.0")
        self.security_categories = [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "ldap_injection",
            "code_injection",
            "xpath_injection",
        ]
        self._initialize_injection_patterns()

    def get_supported_file_types(self) -> List[str]:
        """Return supported file types."""
        return [".py"]

    def get_security_categories(self) -> List[str]:
        """Get security categories this analyzer covers."""
        return self.security_categories

    def get_vulnerability_types(self) -> List[str]:
        """Get vulnerability types this analyzer can detect."""
        return [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "ldap_injection",
            "code_injection",
            "xpath_injection",
        ]

    def get_cwe_mappings(self) -> Dict[str, str]:
        """Get CWE ID mappings for vulnerabilities this analyzer detects."""
        return {
            "sql_injection": "CWE-89",
            "xss": "CWE-79",
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
            "ldap_injection": "CWE-90",
            "code_injection": "CWE-94",
            "xpath_injection": "CWE-643",
        }

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this analyzer."""
        return {
            "enable_sql_injection_detection": True,
            "enable_xss_detection": True,
            "enable_command_injection_detection": True,
            "enable_path_traversal_detection": True,
            "enable_ldap_injection_detection": True,
            "enable_code_injection_detection": True,
            "enable_xpath_injection_detection": True,
            "exclude_test_files": False,
            "min_severity_level": "low",
        }

    async def analyze(self, config: AnalysisConfiguration) -> AnalysisResult:
        """
        Perform injection vulnerability analysis on the target files.

        Args:
            config: Analysis configuration

        Returns:
            Analysis result with findings and metrics
        """
        findings = []
        error_count = 0
        start_time = asyncio.get_event_loop().time()

        try:
            logger.info(
                f"Starting injection analysis of {os.path.basename(config.target_path)}"
            )

            # Find Python files
            # python_files = self._find_python_files(config.target_path)
            if getattr(config, "files", None):
                # Use the explicit file list passed from CLI
                python_files = config.files
            else:
                # Fallback: discover files automatically
                python_files = self._find_python_files(config.target_path)

            if not python_files:
                logger.warning(
                    f"No Python files found in {os.path.basename(config.target_path)}"
                )
                return self._create_empty_result()

            logger.info(f"Found {len(python_files)} Python files to analyze")

            # Get analyzer configuration
            analyzer_config = config.analyzer_configs.get(
                self.name, self.get_default_config()
            )

            # Perform injection vulnerability analysis
            all_vulnerabilities = await self._perform_injection_analysis(
                python_files, analyzer_config
            )
            # Generate findings based on analysis
            findings = await self._generate_findings(
                all_vulnerabilities, config.target_path, analyzer_config
            )

            execution_time = asyncio.get_event_loop().time() - start_time

            metrics = AnalysisMetrics(
                analyzer_name=self.name,
                execution_time_seconds=execution_time,
                files_analyzed=len(python_files),
                findings_count=len(findings),
                error_count=error_count,
                success=True,
            )

            logger.info(
                f"Injection analysis completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return AnalysisResult(
                findings=findings,
                metrics=metrics,
                metadata={
                    "python_files_count": len(python_files),
                    "total_vulnerabilities": len(all_vulnerabilities),
                    "vulnerabilities_by_type": self._count_vulnerabilities_by_type(
                        all_vulnerabilities
                    ),
                    "vulnerabilities_by_severity": self._count_vulnerabilities_by_severity(
                        all_vulnerabilities
                    ),
                },
            )

        except Exception as e:
            traceback.print_exc()
            logger.error(f"Injection analysis failed: {str(e)}")
            error_count += 1
            execution_time = asyncio.get_event_loop().time() - start_time

            metrics = AnalysisMetrics(
                analyzer_name=self.name,
                execution_time_seconds=execution_time,
                files_analyzed=0,
                findings_count=0,
                error_count=error_count,
                success=False,
                error_message=str(e),
            )

            return AnalysisResult(
                findings=[], metrics=metrics, metadata={"error": str(e)}
            )

    def _initialize_injection_patterns(self):
        """Initialize injection vulnerability patterns."""

        # SQL Injection patterns
        self.sql_patterns = [
            r'(?:^|\s)(?:q|query|sql|cmd|statement|qry)\w*\s*=\s*f["\'](?=.*\bSELECT\b)(?=.*\{[^}]+\})[^"\']*["\']',
            r"f([\"'])(?:(?:(?!\1).)*?\{.+?\}(?:(?!\1).)*?\b(?:SELECT\b.*\bFROM\b|WHERE\b|INSERT\b|UPDATE\b|DELETE\b))(?:.(?!\1))*?\1",
            # percent-formatting combined with SQL keywords
            r'["\'](?:.*\%s.*)\b(?:WHERE|SELECT|INSERT|UPDATE|DELETE|FROM)\b["\']',
            # format(...) used on a string that contains SQL keywords
            r'format\(\s*["\'][^"\']{0,200}\b(?:WHERE|SELECT|INSERT|UPDATE|DELETE|FROM)\b',
            # direct execute/raw calls with string concatenation (checked in AST too, but keep regex)
            r'\b(?:execute|executemany|raw)\s*\(\s*["\'].*\+.*["\']',
            # ORM .extra or .raw without parameterization
            r"\.\s*extra\s*\(\s*.*where\s*=.*\+",
            r'\.\s*raw\s*\(\s*["\'].*\+.*["\']',
            ## new patterns =================================
            r'\b\w*\.(?:execute|executemany|raw)\s*\(\s*["\'][^"\']*["\'][\s]*\+[\s]*\w+',
        ]

        # XSS patterns
        self.xss_patterns = [
            r'\brender_template_string\s*\(\s*["\'].*\+.*["\']\s*\)',
            r'\bHttpResponse\s*\(\s*["\'].*\+.*["\']\s*\)',
            r'\bResponse\s*\(\s*["\'].*\+.*["\']\s*\)',
            r'\brender_template_string\s*\(\s*[^)]*["\'][^)]*\+[^)]*\)',
            r'\bResponse\s*\(\s*[^)]*["\'][^)]*\+[^)]*\)',
            r"^(?!\s*['\"]).*\brender_template_string\(\s*(?:f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]|['\"][\s\S]*\+[\s\S]*['\'])\s*\)",
            r"^(?!\s*['\"]).*\bHttpResponse\(\s*(?:f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]|['\"][\s\S]*\+[\s\S]*['\'])\s*\)",
            r"^(?!\s*['\"]).*\bResponse\(\s*(?:f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]|['\"][\s\S]*\+[\s\S]*['\'])\s*\)",
            r"^(?!\s*['\"]).*\bmark_safe\(\s*(?:f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]|['\"][\s\S]*\+[\s\S]*['\'])\s*\)",
            r"^(?!\s*['\"]).*\.innerHTML\s*=\s*[^;\n]*\b(?:user|input|req|request|query|param|payload|data|content)\b[^;\n]*\+[^;\n]*",
            r"^(?!\s*['\"]).*\bdocument\.write\(\s*[^;\n]*\b(?:user|input|req|request|query|param|payload|data|content)\b[^;\n]*\+[^;\n]*\)",
            r"^(?!\s*['\"]).*\.innerHTML\s*=\s*f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]",
            r"^(?!\s*['\"]).*\bdocument\.write\(\s*f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]\)",
        ]

        # Command Injection patterns
        self.command_patterns = [
            r"\bos\.system\s*\(\s*[^)]*\+[^)]*\)",  # "ls " + user
            r"\bos\.popen\s*\(\s*[^)]*\+[^)]*\)",
            r"\bcommands\.getoutput\s*\(\s*[^)]*\+[^)]*\)",
            r"\bsubprocess\.(?:call|run|Popen)\s*\(\s*[^)]*shell\s*=\s*True[^)]*\)",  # shell=True
            r"\bsubprocess\.(?:call|run|Popen)\s*\(\s*(?:f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]|['\"][\s\S]*\+[^)]*|['\"][\s\S]*['\"]\s*%\s*[^)]*|['\"][\s\S]*['\"]\s*\.?\s*format\s*\()[^)]*\)",
        ]

        # Path Traversal patterns
        self.path_traversal_patterns = [
            r'\bopen\s*\(\s*["\'][^"\']*["\']\s*\+\s*',  # open("..."+user)
            r"\bfile\s*\(\s*.*\+.*\)",
            r"os\.path\.join\s*\(.*input",
            r"\bPath\s*\(\s*.*\+.*\)",
            r"\.\./",
            r"\.\.\\\\",
        ]

        # LDAP Injection patterns
        self.ldap_patterns = [
            r"ldap.*search.*\+",
            r"LDAPConnection.*search.*\+",
            r"ldap_search.*\+",
            # compile with re.IGNORECASE | re.DOTALL
            r"\bldap_search\s*\([^)]*filter\s*=\s*(?!['\"]).+?\)",  # ldap_search(filter=<variable>)
            r"\b(?:\w+\.)?search\s*\(\s*[^)]*filter\s*=\s*[^)]*\+[^)]*\)",  # conn.search(filter=<variable>)
            r"\b(?:ldap_search|\w+\.search)\s*\([^)]*filter\s*=\s*f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"][^)]*\)",
            r"\b(?:ldap_search|\w+\.search)\s*\([^)]*filter\s*=\s*['\"][\s\S]*['\"]\s*%\s*[^)]*\)",
            r"\b(?:ldap_search|\w+\.search)\s*\([^)]*filter\s*=\s*['\"][\s\S]*['\"]\s*\.?\s*format\s*\(",
        ]

        # Code Injection patterns
        self.code_injection_patterns = [
            r"\b(?:eval|exec)\s*\([^)]*input\s*\([^)]*\)[^)]*\)",  # eval(input(...)) / exec(input(...))
            r"\b__import__\s*\(\s*input\s*\([^)]*\)",  # __import__(input(...))
            r"\bcompile\s*\(\s*input\s*\([^)]*\)\s*,\s*['\"][^'\"]*['\"]\s*,\s*['\"](?:exec|eval)['\"]\s*\)",  # compile(input(), "<str>", "exec|eval")
            r"\bcompile\s*\([^)]*input\s*\([^)]*\)[^)]*mode\s*=\s*['\"](?:exec|eval)['\"]",  # compile(..., mode="exec|eval")
        ]

        # XPATH Injection patterns
        self.xpath_patterns = [
            r"xpath\s*\(.*\+",
            r"selectNodes\s*\(.*\+",
            r"evaluate\s*\(.*\+.*xpath",
            r"\b(?:\w+\.)?evaluate\s*\(\s*[^)]*\+[^)]*\)",
            r"\b(?:\w+\.)?(?:xpath|selectNodes)\s*\(\s*[^)]*\+[^)]*\)",
            r"\b(?:\w+\.)?(?:xpath|selectNodes|evaluate)\s*\(\s*f['\"][\s\S]*\{[^}]+\}[\s\S]*['\"]\s*\)",
            r"\b(?:\w+\.)?(?:xpath|selectNodes|evaluate)\s*\(\s*['\"][\s\S]*['\"]\s*%\s*[^)]*\)",
            r"\b(?:\w+\.)?(?:xpath|selectNodes|evaluate)\s*\(\s*['\"][\s\S]*['\"]\s*\.?\s*format\s*\(",
        ]

        # Pattern groups with metadata
        self.pattern_groups = {
            "sql_injection": {
                "patterns": self.sql_patterns,
                "severity": SeverityLevel.HIGH,
                "description": "Potential SQL injection vulnerability detected",
                "cwe_id": "CWE-89",
            },
            "xss": {
                "patterns": self.xss_patterns,
                "severity": SeverityLevel.HIGH,
                "description": "Potential Cross-Site Scripting vulnerability detected",
                "cwe_id": "CWE-79",
            },
            "command_injection": {
                "patterns": self.command_patterns,
                "severity": SeverityLevel.CRITICAL,
                "description": "Potential command injection vulnerability detected",
                "cwe_id": "CWE-78",
            },
            "path_traversal": {
                "patterns": self.path_traversal_patterns,
                "severity": SeverityLevel.MEDIUM,
                "description": "Potential path traversal vulnerability detected",
                "cwe_id": "CWE-22",
            },
            "ldap_injection": {
                "patterns": self.ldap_patterns,
                "severity": SeverityLevel.HIGH,
                "description": "Potential LDAP injection vulnerability detected",
                "cwe_id": "CWE-90",
            },
            "code_injection": {
                "patterns": self.code_injection_patterns,
                "severity": SeverityLevel.CRITICAL,
                "description": "Potential code injection vulnerability detected",
                "cwe_id": "CWE-94",
            },
            "xpath_injection": {
                "patterns": self.xpath_patterns,
                "severity": SeverityLevel.HIGH,
                "description": "Potential XPATH injection vulnerability detected",
                "cwe_id": "CWE-643",
            },
        }

    def _find_python_files(self, path: str) -> List[str]:
        """Find all Python files under the given path, excluding virtual environments."""
        return find_python_files(path, exclude_test_files=False)

    async def _perform_injection_analysis(
        self, python_files: List[str], config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Perform comprehensive injection vulnerability analysis."""

        all_vulnerabilities = []

        for file_path in python_files:
            # Skip test files if configured
            if config.get("exclude_test_files", False) and self._is_test_file(
                file_path
            ):
                continue

            file_vulnerabilities = await self._scan_file_for_injections(
                file_path, config
            )
            # file_vulnerabilities = perform_ast_based_injection_analysis(file_path)
            all_vulnerabilities.extend(file_vulnerabilities)

        return all_vulnerabilities

    async def _scan_file_for_injections(
        self, file_path: str, config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Scan a single file for injection vulnerabilities."""
        vulnerabilities = []
        found_vulnerabilities = (
            set()
        )  # Track unique vulnerabilities to avoid duplicates

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

            # Check each line for patterns
            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("#"):
                    continue

                # Check each vulnerability type
                for vuln_type, pattern_info in self.pattern_groups.items():
                    # Check if this vulnerability type is enabled
                    config_key = f"enable_{vuln_type}_detection"
                    if not config.get(config_key, True):
                        continue

                    vuln_found = False
                    for pattern in pattern_info["patterns"]:
                        if re.search(pattern, line, re.IGNORECASE) and not vuln_found:
                            vuln_key = (file_path, line_num, vuln_type)
                            if vuln_key not in found_vulnerabilities:
                                vulnerability = {
                                    "file_path": file_path,
                                    "line_number": line_num,
                                    "vulnerability_type": vuln_type,
                                    "severity": pattern_info["severity"],
                                    "code_snippet": line.strip(),
                                    "description": pattern_info["description"],
                                    "cwe_id": pattern_info["cwe_id"],
                                    "pattern_matched": pattern,
                                }
                                vulnerabilities.append(vulnerability)
                                found_vulnerabilities.add(vuln_key)
                                vuln_found = True
                                break

        except Exception as e:
            logger.warning(f"Error scanning file {file_path}: {str(e)}")

        return vulnerabilities

    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        filename = os.path.basename(file_path).lower()
        return (
            filename.startswith("test_")
            or filename.endswith("_test.py")
            or "test" in filename
            or "/test" in file_path.lower()
        )

    def _count_vulnerabilities_by_type(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count vulnerabilities by type."""
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln["vulnerability_type"]
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        return type_counts

    def _count_vulnerabilities_by_severity(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln["severity"].value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts

    async def _generate_findings(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_path: str,
        config: Dict[str, Any],
    ) -> List[UnifiedFinding]:
        """Generate findings based on injection vulnerability analysis."""
        findings = []

        for vulnerability in vulnerabilities:
            # Check minimum severity level
            min_severity = config.get("min_severity_level", "low").lower()
            if not self._meets_severity_threshold(
                vulnerability["severity"], min_severity
            ):
                continue

            finding = UnifiedFinding(
                title=f"{vulnerability['vulnerability_type'].replace('_', ' ').title()}",
                description=vulnerability["description"],
                category=FindingCategory.SECURITY,
                severity=vulnerability["severity"],
                confidence_score=0.7,  # Static analysis confidence
                location=CodeLocation(
                    file_path="/".join(vulnerability["file_path"].split("/")[-2:]),
                    line_number=vulnerability["line_number"],
                ),
                rule_id=f"{vulnerability['vulnerability_type'].upper()}",
                cwe_id=vulnerability["cwe_id"],
                code_snippet=vulnerability["code_snippet"],
                remediation_guidance=self._get_remediation_guidance(
                    vulnerability["vulnerability_type"]
                ),
                remediation_complexity=self._get_remediation_complexity(
                    vulnerability["vulnerability_type"]
                ),
                source_analyzer=self.name,
                tags={"injection", vulnerability["vulnerability_type"], "security"},
                extra_data={
                    "pattern_matched": vulnerability["pattern_matched"],
                    "vulnerability_category": vulnerability["vulnerability_type"],
                },
            )
            findings.append(finding)

        return findings

    def _meets_severity_threshold(
        self, severity: SeverityLevel, min_level: str
    ) -> bool:
        """Check if severity meets minimum threshold."""
        severity_order = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        current_level = severity_order.get(severity.value.lower(), 0)
        min_threshold = severity_order.get(min_level.lower(), 0)

        return current_level >= min_threshold

    def _get_remediation_guidance(self, vulnerability_type: str) -> str:
        """Get specific remediation guidance for vulnerability types."""
        guidance_mapping = {
            "sql_injection": "Use parameterized queries or prepared statements instead of string concatenation",
            "xss": "Escape user input before rendering in HTML, use templating engines with auto-escaping",
            "command_injection": "Avoid shell execution with user input, use subprocess with argument lists",
            "path_traversal": "Validate and sanitize file paths, use Path.resolve() and check against allowed directories",
            "ldap_injection": "Use parameterized LDAP queries and escape special characters",
            "code_injection": "Never execute user-provided code, use safe alternatives like JSON parsing",
            "xpath_injection": "Use parameterized XPath queries and escape special characters",
        }

        return guidance_mapping.get(
            vulnerability_type, "Review and sanitize user input handling"
        )

    def _get_remediation_complexity(self, vulnerability_type: str) -> ComplexityLevel:
        """Get remediation complexity for vulnerability types."""
        complexity_mapping = {
            "sql_injection": ComplexityLevel.MODERATE,
            "xss": ComplexityLevel.MODERATE,
            "command_injection": ComplexityLevel.COMPLEX,
            "path_traversal": ComplexityLevel.MODERATE,
            "ldap_injection": ComplexityLevel.MODERATE,
            "code_injection": ComplexityLevel.COMPLEX,
            "xpath_injection": ComplexityLevel.MODERATE,
        }

        return complexity_mapping.get(vulnerability_type, ComplexityLevel.MODERATE)

    def _create_empty_result(self) -> AnalysisResult:
        """Create an empty analysis result."""
        metrics = AnalysisMetrics(
            analyzer_name=self.name,
            execution_time_seconds=0.0,
            files_analyzed=0,
            findings_count=0,
            error_count=0,
            success=True,
        )
        return AnalysisResult(findings=[], metrics=metrics, metadata={})
