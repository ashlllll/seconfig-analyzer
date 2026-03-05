"""
Blue Team Remediator
Main entry point for the Blue Team remediation engine.
Generates deterministic fixes for detected security issues.
"""
import uuid
from copy import deepcopy
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .template_engine import TemplateEngine
from .validator import FixValidator
from ...models.config_model import ConfigFile
from ...models.fix_model import SecurityFix
from ...models.issue_model import SecurityIssue


class BlueTeamRemediator:
    """
    Generates remediation fixes for detected security issues.

    For each SecurityIssue, it:
    1. Finds the matching fix template
    2. Renders the template with issue-specific variables
    3. Validates the generated fix
    4. Returns a SecurityFix object

    If no template is found, a manual guidance fix is created instead.

    This engine is fully deterministic — no AI is involved.
    """

    def __init__(self, templates_dir: str = None):
        """
        Initialize the remediator with template engine and validator.

        Args:
            templates_dir: Optional path to templates directory.
        """
        self.template_engine = TemplateEngine(templates_dir=templates_dir)
        self.validator = FixValidator()

    def remediate(self, issues: List[SecurityIssue]) -> List[SecurityFix]:
        """
        Generate fix recommendations for a list of security issues.

        Args:
            issues: List of SecurityIssue objects from Red Team analysis

        Returns:
            List of SecurityFix objects, one per issue
        """
        fixes = []

        for issue in issues:
            fix = self._generate_fix(issue)
            fixes.append(fix)

        return fixes

    def _generate_fix(self, issue: SecurityIssue) -> SecurityFix:
        """
        Generate a single fix for an issue.

        Tries to find a matching template. Falls back to manual guidance
        if no template is available.

        Args:
            issue: SecurityIssue to fix

        Returns:
            SecurityFix object
        """
        # Try to find template by template_id first
        template = None
        if issue.template_id:
            template = self.template_engine.get_template(issue.template_id)

        # Fallback: search by rule_id
        if template is None:
            template = self.template_engine.find_template_for_rule(issue.rule_id)

        if template is not None:
            return self._fix_from_template(issue, template)
        else:
            return self._manual_fix(issue)

    def _fix_from_template(
        self,
        issue: SecurityIssue,
        template: dict,
    ) -> SecurityFix:
        """
        Generate an automated or semi-automated fix using a template.

        Args:
            issue:    The security issue to fix
            template: The fix template dictionary

        Returns:
            SecurityFix object
        """
        # Extract variables from the vulnerable code
        variables = self.template_engine.extract_variables(
            template=template,
            vulnerable_code=issue.vulnerable_code,
        )

        # Render the fix template
        fixed_code = self.template_engine.render(template, variables)

        # If rendering produced nothing, fall back to example_fix
        if not fixed_code and issue.recommended_fix:
            fixed_code = issue.recommended_fix

        # Determine fix type
        auto_fixable = template.get("metadata", {}).get("auto_fixable", False)
        fix_type = "automated" if auto_fixable else "semi_automated"

        # Validate the fix
        is_valid, errors = self.validator.validate(
            original_code=issue.vulnerable_code,
            fixed_code=fixed_code,
            template=template,
            file_type=issue.file_name.rsplit(".", 1)[-1] if "." in issue.file_name else "env",
        )

        fix = SecurityFix(
            fix_id=self._generate_fix_id(),
            issue_id=issue.issue_id,
            issue_title=issue.title,
            fix_type=fix_type,
            template_id=template.get("id"),
            original_code=issue.vulnerable_code,
            fixed_code=fixed_code,
            explanation=template.get("explanation", issue.remediation_hint),
            strategy=template.get("fix_strategy", "template_replacement"),
            priority=issue.risk_profile.priority if issue.risk_profile else "medium",
            effort=template.get("metadata", {}).get("effort", "low"),
            risk_reduction=self._estimate_risk_reduction(issue, template),
            side_effects=template.get("side_effects", []),
            breaking_change=template.get("breaking_change", False),
        )

        if is_valid:
            fix.mark_validated()
        else:
            fix.mark_validation_failed(errors)

        return fix

    def _manual_fix(self, issue: SecurityIssue) -> SecurityFix:
        """
        Create a manual guidance fix when no template is available.

        Args:
            issue: The security issue to fix

        Returns:
            SecurityFix with manual guidance
        """
        fix = SecurityFix(
            fix_id=self._generate_fix_id(),
            issue_id=issue.issue_id,
            issue_title=issue.title,
            fix_type="manual",
            template_id=None,
            original_code=issue.vulnerable_code,
            fixed_code=issue.recommended_fix or "",
            explanation=issue.remediation_hint,
            strategy="manual_guidance",
            priority=issue.risk_profile.priority if issue.risk_profile else "medium",
            effort="medium",
            risk_reduction=30.0,  # conservative estimate for manual fixes
        )

        fix.mark_validated()
        return fix

    def apply_fixes(
        self,
        config: ConfigFile,
        fixes: List[SecurityFix],
    ) -> Tuple[ConfigFile, List[SecurityFix]]:
        """
        Apply selected fixes to a configuration file.

        Creates a modified copy of the config with fixes applied.
        Only applies validated, automated fixes.

        Args:
            config: Original ConfigFile object
            fixes:  List of SecurityFix objects to apply

        Returns:
            (modified_config, applied_fixes)
        """
        modified_content = config.raw_content
        applied_fixes = []

        for fix in fixes:
            # Only apply automated, validated fixes
            if fix.fix_type == "manual":
                continue
            if fix.validation_status != "validated":
                continue
            if not fix.original_code or not fix.fixed_code:
                continue

            # Replace the original vulnerable line with the fix
            if fix.original_code in modified_content:
                modified_content = modified_content.replace(
                    fix.original_code,
                    fix.fixed_code,
                    1  # replace only first occurrence
                )
                fix.mark_applied()
                applied_fixes.append(fix)

        # Build a new ConfigFile with the modified content
        from ...parsers.parser_factory import ParserFactory
        parser = ParserFactory.get_parser(config.file_type)
        modified_config = parser.parse(modified_content, config.file_name)

        return modified_config, applied_fixes

    def simulate_remediation(
        self,
        issues: List[SecurityIssue],
        fixes: List[SecurityFix],
    ) -> List[SecurityIssue]:
        """
        Return the list of issues that would remain after applying all fixes.

        Used for Monte Carlo simulation comparison (before vs after).

        Args:
            issues: All detected issues
            fixes:  All generated fixes

        Returns:
            Issues that are NOT covered by any fix
        """
        # Collect issue IDs that have a validated fix
        fixed_issue_ids = {
            fix.issue_id
            for fix in fixes
            if fix.validation_status == "validated"
        }

        remaining = [
            issue for issue in issues
            if issue.issue_id not in fixed_issue_ids
        ]

        return remaining

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _generate_fix_id(self) -> str:
        """Generate a unique fix ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        short_uuid = str(uuid.uuid4())[:6]
        return f"FIX-{timestamp}-{short_uuid}"

    def _estimate_risk_reduction(
        self,
        issue: SecurityIssue,
        template: dict,
    ) -> float:
        """
        Estimate percentage risk reduction after applying a fix.

        Args:
            issue:    The issue being fixed
            template: The fix template

        Returns:
            Estimated risk reduction as percentage (0-100)
        """
        confidence = template.get("metadata", {}).get("fix_confidence", 0.8)
        base_risk = issue.risk_score if issue.risk_score else 50.0
        return round(base_risk * confidence, 1)

    def get_summary(self, fixes: List[SecurityFix]) -> Dict:
        """
        Generate a summary of the fixes.

        Args:
            fixes: List of SecurityFix objects

        Returns:
            Summary dictionary
        """
        return {
            "total": len(fixes),
            "automated": sum(1 for f in fixes if f.fix_type == "automated"),
            "semi_automated": sum(1 for f in fixes if f.fix_type == "semi_automated"),
            "manual": sum(1 for f in fixes if f.fix_type == "manual"),
            "validated": sum(1 for f in fixes if f.validation_status == "validated"),
            "failed_validation": sum(1 for f in fixes if f.validation_status == "failed"),
            "applied": sum(1 for f in fixes if f.applied),
        }
