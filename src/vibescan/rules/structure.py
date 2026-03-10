"""StructureRule - checks project structure health and best practices.

Uses: all_files
"""

from __future__ import annotations

from pathlib import PurePosixPath

from vibescan.collector.context import ProjectContext
from vibescan.models.issue import Issue, Severity
from vibescan.rules.base import BaseRule

# Important project health files
HEALTH_FILES: dict[str, tuple[str, Severity, str]] = {
    "README.md": (
        "No README.md found",
        Severity.LOW,
        "Add a README.md describing the project, setup instructions, "
        "and usage examples.",
    ),
    ".gitignore": (
        "No .gitignore found",
        Severity.MEDIUM,
        "Create a .gitignore using a template for your language/framework "
        "(see gitignore.io).",
    ),
    "LICENSE": (
        "No LICENSE file found",
        Severity.LOW,
        "Add a LICENSE file to clarify usage rights. Without one, the "
        "code is under exclusive copyright by default.",
    ),
}

# Lockfile indicators - if a package manifest exists, a lockfile should too
LOCKFILE_MAP: dict[str, tuple[str, list[str]]] = {
    "package.json": ("npm/yarn/pnpm", [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "bun.lockb", "bun.lock",
    ]),
    "requirements.txt": ("pip", ["requirements.txt"]),  # itself is the lock
    "Pipfile": ("pipenv", ["Pipfile.lock"]),
    "pyproject.toml": ("Python", [
        "poetry.lock", "pdm.lock", "uv.lock",
        "requirements.txt", "requirements-lock.txt",
    ]),
    "Gemfile": ("bundler", ["Gemfile.lock"]),
    "composer.json": ("composer", ["composer.lock"]),
    "go.mod": ("Go modules", ["go.sum"]),
    "Cargo.toml": ("Cargo", ["Cargo.lock"]),
}

# Directories that suggest secrets or sensitive data if present at root
SUSPICIOUS_DIRS: dict[str, tuple[Severity, str, str]] = {
    ".ssh": (
        Severity.CRITICAL,
        "SSH directory '.ssh' found in project",
        "This directory likely contains private keys. Remove it and "
        "add '.ssh/' to .gitignore.",
    ),
    ".aws": (
        Severity.CRITICAL,
        "AWS config directory '.aws' found in project",
        "This directory contains AWS credentials. Remove it and "
        "add '.aws/' to .gitignore.",
    ),
    ".kube": (
        Severity.CRITICAL,
        "Kubernetes config directory '.kube' found in project",
        "This directory contains cluster access credentials. Remove it "
        "and add '.kube/' to .gitignore.",
    ),
}


class StructureRule(BaseRule):
    def run(self, ctx: ProjectContext) -> list[Issue]:
        issues: list[Issue] = []
        file_set = set(ctx.all_files)
        root_names = {PurePosixPath(f).parts[0] for f in ctx.all_files if f}

        # 1. Health files check
        for filename, (msg, sev, fix) in HEALTH_FILES.items():
            found = any(
                f == filename or f.lower() == filename.lower()
                for f in ctx.all_files
            )
            if not found:
                issues.append(Issue(
                    rule_id="STRUCTURE-HEALTH",
                    severity=sev,
                    file=filename,
                    line=None,
                    message=msg,
                    why="Essential project files help contributors understand "
                        "the project, ensure reproducible builds, and prevent "
                        "accidental exposure of sensitive files.",
                    fix=fix,
                ))

        # 2. Lockfile consistency
        for manifest, (ecosystem, lockfiles) in LOCKFILE_MAP.items():
            # Check if manifest exists
            has_manifest = any(
                PurePosixPath(f).name == manifest for f in ctx.all_files
            )
            if not has_manifest:
                continue

            # Skip self-referencing (requirements.txt)
            if manifest in lockfiles:
                continue

            has_lock = any(
                PurePosixPath(f).name in lockfiles for f in ctx.all_files
            )
            if not has_lock:
                issues.append(Issue(
                    rule_id="STRUCTURE-LOCKFILE",
                    severity=Severity.MEDIUM,
                    file=manifest,
                    line=None,
                    message=f"No lockfile found for {ecosystem} "
                            f"(has {manifest} but no lockfile)",
                    why="Without a lockfile, dependency versions are not "
                        "pinned. Different installs may get different versions, "
                        "causing 'works on my machine' bugs and potential "
                        "supply chain attacks via version drift.",
                    fix=f"Generate a lockfile: run the appropriate install "
                        f"command ({ecosystem}) and commit the resulting "
                        f"lockfile ({', '.join(lockfiles[:2])}).",
                ))

        # 3. Suspicious directories
        for dirname, (sev, msg, fix) in SUSPICIOUS_DIRS.items():
            if dirname in root_names:
                issues.append(Issue(
                    rule_id="STRUCTURE-SUSPICIOUS-DIR",
                    severity=sev,
                    file=dirname + "/",
                    line=None,
                    message=msg,
                    why="System credential directories should never exist "
                        "inside a project repository. They contain private "
                        "keys and access tokens for infrastructure.",
                    fix=fix,
                ))

        # 4. Overly flat structure (many files at root)
        root_files = [
            f for f in ctx.all_files
            if "/" not in f and not f.startswith(".")
        ]
        if len(root_files) > 20:
            issues.append(Issue(
                rule_id="STRUCTURE-FLAT",
                severity=Severity.INFO,
                file=".",
                line=None,
                message=f"Project root has {len(root_files)} non-hidden files",
                why="A flat project structure makes it harder to navigate "
                    "and maintain. Important files get lost among many others.",
                fix="Organize source files into directories: src/, lib/, "
                    "tests/, docs/, etc.",
            ))

        return issues
