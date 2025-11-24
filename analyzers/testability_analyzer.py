# Flake8: noqa: E501
"""
Testability Analyzer for evaluating unit test coverage and code testability.
Analyzes test structure, function coverage, and provides testability recommendations.
"""

import os
import ast
import re
import asyncio
from typing import List, Dict, Any, Set, Tuple
from utils.logs_service.logger import AppLogger
from core.interfaces import QualityAnalyzer
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


class TestabilityAnalyzer(QualityAnalyzer):
    """
    Analyzer for evaluating code testability, test coverage, and test structure.
    """

    def __init__(self):
        super().__init__("testability", "1.0.0")
        self.quality_categories = ["test_coverage", "test_structure", "testability"]
        self._initialize_patterns()

    def get_supported_file_types(self) -> List[str]:
        """Return supported file types."""
        return [".py"]

    def get_quality_categories(self) -> List[str]:
        """Get quality categories this analyzer covers."""
        return self.quality_categories

    def get_quality_metrics(self) -> List[str]:
        """Get quality metrics this analyzer can provide."""
        return [
            "test_coverage_percentage",
            "total_functions_count",
            "tested_functions_count",
            "untested_functions_count",
            "test_files_count",
            "has_test_structure",
            "testability_score",
        ]

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for this analyzer."""
        return {
            "minimum_coverage_threshold": 70.0,  # Percentage
            "check_test_structure": True,
            "check_function_coverage": True,
            "check_test_naming": True,
            "exclude_private_methods": True,
            "exclude_test_files_from_coverage": True,
        }

    async def analyze(self, config: AnalysisConfiguration) -> AnalysisResult:
        """
        Perform testability analysis on the target files.

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
                f"Starting testability analysis of {os.path.basename(config.target_path)}"
            )

            # Find Python files
            # python_files, test_files = self._find_python_files(config.target_path)
            if getattr(config, "files", None):
                # Use the explicit file list passed from CLI
                python_files = config.files
                _, test_files = self._find_python_files(config.target_path)
            else:
                # Fallback: discover files automatically
                python_files, test_files = self._find_python_files(config.target_path)

            if not python_files:
                logger.warning(
                    f"No Python files found in {os.path.basename(config.target_path)}"
                )
                return self._create_empty_result()

            logger.info(
                f"Found {len(python_files)} Python files and {len(test_files)} test files"
            )

            # Get analyzer configuration
            analyzer_config = config.analyzer_configs.get(
                self.name, self.get_default_config()
            )

            # Perform testability analysis
            analysis_results = await self._perform_testability_analysis(
                python_files, test_files, analyzer_config
            )

            # Generate findings based on analysis
            findings = await self._generate_findings(
                analysis_results, config.target_path, analyzer_config
            )

            execution_time = asyncio.get_event_loop().time() - start_time

            metrics = AnalysisMetrics(
                analyzer_name=self.name,
                execution_time_seconds=execution_time,
                files_analyzed=len(python_files) + len(test_files),
                findings_count=len(findings),
                error_count=error_count,
                success=True,
            )

            logger.info(
                f"Testability analysis completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return AnalysisResult(
                findings=findings,
                metrics=metrics,
                metadata={
                    "python_files_count": len(python_files),
                    "test_files_count": len(test_files),
                    "coverage_percentage": analysis_results.get(
                        "coverage_percentage", 0.0
                    ),
                    "total_functions": analysis_results.get("total_functions", 0),
                    "tested_functions": analysis_results.get("tested_functions", 0),
                    "has_test_structure": analysis_results.get(
                        "has_test_folder", False
                    ),
                },
            )

        except Exception as e:
            logger.error(f"Testability analysis failed: {str(e)}")
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

    def _initialize_patterns(self):
        """Initialize test file and function patterns."""
        self.test_file_patterns = [r"test_.*\.py$", r".*_test\.py$", r"tests\.py$"]
        self.test_folders = ["test", "tests", "__tests__"]
        self.test_function_prefix = "test_"

    def _find_python_files(self, path: str) -> Tuple[List[str], List[str]]:
        """Find all Python files and separate them into main code and test files, excluding virtual environments."""
        from core.file_utils import CodebaseFileFilter

        # Get all Python files, excluding virtual environments
        all_python_files = find_python_files(path, exclude_test_files=False)

        # Separate into main code and test files
        python_files = []
        test_files = []

        for file_path in all_python_files:
            if self._is_test_file(os.path.basename(file_path)):
                test_files.append(file_path)
            else:
                python_files.append(file_path)

        return python_files, test_files

    def _is_test_file(self, filename: str) -> bool:
        """Check if a file is a test file based on naming patterns."""
        for pattern in self.test_file_patterns:
            if re.match(pattern, filename):
                return True
        return False

    async def _perform_testability_analysis(
        self, python_files: List[str], test_files: List[str], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive testability analysis."""

        # Extract functions from main code files
        all_functions = {}
        total_functions = 0

        for py_file in python_files:
            functions = await self._extract_functions_from_file(py_file, config)
            if functions:
                all_functions[py_file] = functions
                total_functions += len(functions)

        # Extract test functions and their targets
        all_test_functions = {}
        tested_functions = set()

        for test_file in test_files:
            test_functions = await self._extract_test_functions_from_file(test_file)
            if test_functions:
                all_test_functions[test_file] = test_functions
                targets = self._extract_test_function_targets(test_functions)
                tested_functions.update(targets)

        # Calculate coverage
        main_function_names = set()
        for functions in all_functions.values():
            main_function_names.update(functions)

        tested_count = len(tested_functions.intersection(main_function_names))
        coverage_percentage = (
            (tested_count / total_functions * 100) if total_functions > 0 else 0
        )

        # Check for test folder structure
        has_test_folder = self._check_test_folder_structure(
            os.path.dirname(python_files[0]) if python_files else ""
        )

        return {
            "total_python_files": len(python_files),
            "total_test_files": len(test_files),
            "total_functions": total_functions,
            "tested_functions": tested_count,
            "untested_functions": total_functions - tested_count,
            "coverage_percentage": coverage_percentage,
            "has_test_folder": has_test_folder,
            "python_files": python_files,
            "test_files": test_files,
            "all_functions": all_functions,
            "all_test_functions": all_test_functions,
            "tested_function_names": list(
                tested_functions.intersection(main_function_names)
            ),
            "untested_function_names": list(main_function_names - tested_functions),
            "main_function_names": main_function_names,
        }

    async def _extract_functions_from_file(
        self, file_path: str, config: Dict[str, Any]
    ) -> List[str]:
        """Extract function names from a Python file."""
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            tree = ast.parse(content)
            functions = []

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Skip private methods if configured
                    if config.get(
                        "exclude_private_methods", True
                    ) and node.name.startswith("_"):
                        continue
                    functions.append(node.name)

            return functions
        except Exception as e:
            logger.warning(f"Could not parse {file_path}: {str(e)}")
            return []

    async def _extract_test_functions_from_file(self, file_path: str) -> List[str]:
        """Extract test function names from a test file."""
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            tree = ast.parse(content)
            test_functions = []

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if node.name.startswith(self.test_function_prefix):
                        test_functions.append(node.name)

            return test_functions
        except Exception as e:
            logger.warning(f"Could not parse test file {file_path}: {str(e)}")
            return []

    def _extract_test_function_targets(self, test_functions: List[str]) -> Set[str]:
        """Extract the target function names from test function names."""
        targets = set()
        for test_func in test_functions:
            if test_func.startswith(self.test_function_prefix):
                target = test_func[len(self.test_function_prefix) :]
                targets.add(target)
        return targets

    def _check_test_folder_structure(self, path: str) -> bool:
        """Check if there's a proper test folder structure."""
        if not os.path.isdir(path):
            return False

        for item in os.listdir(path):
            if (
                os.path.isdir(os.path.join(path, item))
                and item.lower() in self.test_folders
            ):
                return True
        return False

    async def _generate_findings(
        self, analysis_results: Dict[str, Any], target_path: str, config: Dict[str, Any]
    ) -> List[UnifiedFinding]:
        """Generate findings based on testability analysis results."""
        findings = []

        # Check overall test coverage
        coverage_percentage = analysis_results["coverage_percentage"]
        minimum_threshold = config.get("minimum_coverage_threshold", 70.0)

        if coverage_percentage < minimum_threshold:
            severity = (
                SeverityLevel.HIGH if coverage_percentage < 50 else SeverityLevel.MEDIUM
            )
            finding = UnifiedFinding(
                title="Low Test Coverage",
                description=f"Test coverage is {coverage_percentage:.1f}%, below recommended {minimum_threshold}%",
                category=FindingCategory.TESTABILITY,
                severity=severity,
                confidence_score=0.7,
                location=CodeLocation(
                    file_path="/".join(str(target_path).split("/")[-2:])
                ),
                rule_id="LOW_TEST_COVERAGE",
                remediation_guidance=f"Add unit tests for untested functions to reach {minimum_threshold}% coverage",
                remediation_complexity=ComplexityLevel.MODERATE,
                source_analyzer=self.name,
                tags={"test_coverage", "quality", "maintainability"},
                extra_data={
                    "coverage_percentage": coverage_percentage,
                    "minimum_threshold": minimum_threshold,
                    "untested_functions_count": analysis_results["untested_functions"],
                },
            )
            findings.append(finding)

        # Check for missing test structure
        if (
            config.get("check_test_structure", True)
            and not analysis_results["has_test_folder"]
        ):
            finding = UnifiedFinding(
                title="Missing Test Folder Structure",
                description="No dedicated test folder found in project structure",
                category=FindingCategory.TESTABILITY,
                severity=SeverityLevel.MEDIUM,
                confidence_score=0.8,
                location=CodeLocation(
                    file_path="/".join(str(target_path).split("/")[-2:])
                ),
                rule_id="MISSING_TEST_STRUCTURE",
                remediation_guidance="Create a 'tests' or 'test' folder for better test organization",
                remediation_complexity=ComplexityLevel.SIMPLE,
                source_analyzer=self.name,
                tags={"test_structure", "organization"},
                extra_data={"recommended_folders": self.test_folders},
            )
            findings.append(finding)

        # Check for missing test files
        if analysis_results["total_test_files"] == 0:
            finding = UnifiedFinding(
                title="No Test Files Found",
                description="No test files found in the project",
                category=FindingCategory.TESTABILITY,
                severity=SeverityLevel.HIGH,
                confidence_score=0.7,
                location=CodeLocation(
                    file_path="/".join(str(target_path).split("/")[-2:])
                ),
                rule_id="NO_TEST_FILES",
                remediation_guidance="Create test files with 'test_' prefix or '_test' suffix",
                remediation_complexity=ComplexityLevel.MODERATE,
                source_analyzer=self.name,
                tags={"test_files", "testing"},
                extra_data={"test_file_patterns": self.test_file_patterns},
            )
            findings.append(finding)

        # Generate findings for untested functions
        if config.get("check_function_coverage", True):
            untested_functions = analysis_results["untested_function_names"]
            if untested_functions:
                # Group by file for better reporting
                functions_by_file = {}
                for file_path, functions in analysis_results["all_functions"].items():
                    untested_in_file = [f for f in functions if f in untested_functions]
                    if untested_in_file:
                        functions_by_file[file_path] = untested_in_file

                # {', '.join(untested_funcs[:5])}{'...' if len(untested_funcs) > 5 else ''}

                for file_path, untested_funcs in functions_by_file.items():
                    clubbed = {
                        "untested_functions": untested_funcs,
                    }
                    finding = UnifiedFinding(
                        title="Untested Functions",
                        description=f"Functions without unit tests: **{len(untested_funcs)}**",
                        clubbed=clubbed,
                        category=FindingCategory.TESTABILITY,
                        severity=(
                            SeverityLevel.LOW
                            if len(untested_funcs) <= 2
                            else SeverityLevel.MEDIUM
                        ),
                        confidence_score=0.7,
                        location=CodeLocation(
                            file_path="/".join(str(file_path).split("/")[-2:])
                        ),
                        rule_id="UNTESTED_FUNCTIONS",
                        remediation_guidance=f"Add unit tests for {len(untested_funcs)} untested function(s)",
                        remediation_complexity=ComplexityLevel.MODERATE,
                        source_analyzer=self.name,
                        tags={"function_coverage", "unit_tests"},
                        extra_data={
                            "untested_functions": untested_funcs,
                            "untested_count": len(untested_funcs),
                        },
                    )
                    findings.append(finding)

        return findings

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
