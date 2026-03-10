"""GitHygieneRule - checks .gitignore coverage and git configuration hygiene.

Uses: all_files + gitignore_patterns
"""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

# Files/dirs that should always be gitignored
SHOULD_BE_IGNORED: dict[str, tuple[Severity, str]] = {
    # Dependencies
    "node_modules": (Severity.MEDIUM, "Node.js dependencies directory"),
    ".venv": (Severity.MEDIUM, "Python virtual environment"),
    "venv": (Severity.MEDIUM, "Python virtual environment"),
    "vendor": (Severity.LOW, "Vendored dependencies directory"),
    # Build artifacts
    "build": (Severity.LOW, "Build output directory"),
    "dist": (Severity.LOW, "Distribution output directory"),
    "__pycache__": (Severity.LOW, "Python bytecode cache"),
    ".next": (Severity.LOW, "Next.js build output"),
    ".nuxt": (Severity.LOW, "Nuxt.js build output"),
    "coverage": (Severity.LOW, "Test coverage output"),
    # Environment
    ".env": (Severity.HIGH, "Environment variables file"),
}

# Patterns that should exist in .gitignore for a healthy project
RECOMMENDED_PATTERNS: dict[str, list[str]] = {
    "node_modules": ["node_modules", "node_modules/"],
    ".env": [".env", ".env*", ".env.*"],
    "__pycache__": ["__pycache__", "__pycache__/", "*.pyc"],
    ".venv": [".venv", ".venv/", "venv", "venv/"],
    "coverage": ["coverage", "coverage/", ".coverage"],
    ".DS_Store": [".DS_Store"],
    "*.log": ["*.log"],
}

# Extensions that should never be tracked
DANGEROUS_TRACKED_EXTENSIONS: dict[str, tuple[Severity, str]] = {
    ".pem": (Severity.CRITICAL, "Private key/certificate"),
    ".key": (Severity.CRITICAL, "Private key"),
    ".p12": (Severity.CRITICAL, "PKCS#12 certificate"),
    ".pfx": (Severity.CRITICAL, "PFX certificate"),
    ".keystore": (Severity.HIGH, "Java keystore"),
    ".jks": (Severity.HIGH, "Java keystore"),
    ".sqlite": (Severity.MEDIUM, "SQLite database"),
    ".db": (Severity.MEDIUM, "Database file"),
}


def _pattern_covers(patterns: list[str], name: str) -> bool:
    """Check if any gitignore pattern would cover the given name."""
    for p in patterns:
        cleaned = p.strip().rstrip("/")
        if cleaned == name:
            return True
        # Simple glob: *.ext
        if cleaned.startswith("*") and name.endswith(cleaned[1:]):
            return True
        # .env* style
        if cleaned.endswith("*") and name.startswith(cleaned[:-1]):
            return True
    return False


class GitHygieneRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        patterns = ctx.gitignore_patterns

        # 1. Check if .gitignore exists at all
        has_gitignore = any(
            f == ".gitignore" or f.endswith("/.gitignore")
            for f in ctx.all_files
        )
        if not has_gitignore:
            issues.append(Issue(
                rule_id="GIT-NO-GITIGNORE",
                severity=Severity.HIGH,
                file=".gitignore",
                line=None,
                message="No .gitignore file found in project",
                why="Without a .gitignore, all files including secrets, "
                    "build artifacts, and dependencies can be accidentally "
                    "committed to the repository.",
                fix="Create a .gitignore file. Use gitignore.io or GitHub's "
                    "template for your language/framework.",
            ))

        # 2. Check recommended patterns missing from .gitignore
        # Only check patterns relevant to files that exist in the project
        detected_ecosystems: set[str] = set()
        for f in ctx.all_files:
            name = PurePosixPath(f).name
            if name == "package.json":
                detected_ecosystems.add("node_modules")
            if name in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"):
                detected_ecosystems.update(("__pycache__", ".venv"))

        for key, acceptable in RECOMMENDED_PATTERNS.items():
            # Only suggest if ecosystem is relevant or it's universal (.env, .DS_Store, *.log)
            if key in ("node_modules", "__pycache__", ".venv", "coverage"):
                if key not in detected_ecosystems and \
                   not any(key in eco for eco in detected_ecosystems):
                    continue

            if not any(_pattern_covers(patterns, a.strip().rstrip("/")) or
                       a in patterns for a in acceptable):
                # Check the simple case: is the pattern literally present?
                if any(a in patterns for a in acceptable):
                    continue
                issues.append(Issue(
                    rule_id="GIT-MISSING-PATTERN",
                    severity=Severity.LOW,
                    file=".gitignore",
                    line=None,
                    message=f"Recommended .gitignore pattern missing: '{key}'",
                    why=f"Without ignoring '{key}', these files may be "
                        f"accidentally committed, bloating the repository "
                        f"or leaking sensitive data.",
                    fix=f"Add '{acceptable[0]}' to your .gitignore file.",
                ))

        # 3. Check for dangerous file extensions tracked in the repo
        for file_path in ctx.all_files:
            ext = PurePosixPath(file_path).suffix.lower()
            if ext in DANGEROUS_TRACKED_EXTENSIONS:
                sev, desc = DANGEROUS_TRACKED_EXTENSIONS[ext]
                name = PurePosixPath(file_path).name
                if not _pattern_covers(patterns, name) and \
                   not _pattern_covers(patterns, f"*{ext}"):
                    issues.append(Issue(
                        rule_id="GIT-DANGEROUS-TRACKED",
                        severity=sev,
                        file=file_path,
                        line=None,
                        message=f"{desc} file '{name}' is not gitignored",
                        why=f"Files with extension '{ext}' should be in "
                            f".gitignore. Tracking them exposes sensitive "
                            f"data in repository history permanently.",
                        fix=f"Add '*{ext}' to .gitignore and remove the "
                            f"file from tracking: git rm --cached {file_path}",
                    ))

        # 4. Check for large number of tracked files suggesting missing ignores
        LARGE_DIR_THRESHOLD = 100
        dir_counts: dict[str, int] = {}
        for f in ctx.all_files:
            parts = PurePosixPath(f).parts
            if len(parts) > 1:
                top_dir = parts[0]
                dir_counts[top_dir] = dir_counts.get(top_dir, 0) + 1

        for dirname, count in dir_counts.items():
            if dirname in SHOULD_BE_IGNORED and count > LARGE_DIR_THRESHOLD:
                sev, desc = SHOULD_BE_IGNORED[dirname]
                issues.append(Issue(
                    rule_id="GIT-BLOAT",
                    severity=sev,
                    file=dirname,
                    line=None,
                    message=f"Directory '{dirname}' has {count} files "
                            f"and appears to be tracked ({desc})",
                    why=f"Tracking '{dirname}' bloats the repository, "
                        f"slows cloning, and may contain sensitive data.",
                    fix=f"Add '{dirname}/' to .gitignore and remove from "
                        f"tracking: git rm -r --cached {dirname}/",
                ))

        return issues
