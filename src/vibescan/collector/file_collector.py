"""File Collector - collects text files, all file paths, and .gitignore patterns."""

from __future__ import annotations

from pathlib import Path

from vibescan.collector.context import ProjectContext, TextFile
from vibescan.collector.gitignore_parser import parse_gitignore_files

EXCLUDED_DIRS: set[str] = {
    "node_modules", ".git", ".venv", "venv",
    "build", "dist", "coverage", "__pycache__",
    ".next", ".nuxt", ".output",
    "vendor", "target", ".gradle",
    ".tox", "eggs", ".mypy_cache", ".pytest_cache",
}

TEXT_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rs", ".rb", ".php", ".c", ".cpp", ".h",
    ".cs", ".swift", ".kt", ".kts", ".scala",
    ".html", ".htm", ".css", ".scss", ".less",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".xml", ".csv", ".sql", ".sh", ".bash", ".zsh",
    ".md", ".txt", ".rst", ".env", ".properties",
    ".gradle", ".sbt", ".pom",
    ".tf", ".hcl", ".vue", ".svelte",
}

TEXT_FILENAMES: set[str] = {
    "Dockerfile", "Makefile", "Jenkinsfile", "Procfile",
    "Caddyfile", "Gemfile", "Rakefile", "Fastfile",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".htaccess", ".npmrc", ".pypirc", ".netrc",
    ".pgpass", ".my.cnf", ".boto",
}

MAX_FILE_SIZE: int = 5 * 1024 * 1024  # 5MB


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_FILENAMES


def _should_skip_dir(name: str) -> bool:
    return name in EXCLUDED_DIRS or name.endswith(".egg-info")


def collect(root: Path) -> ProjectContext:
    root = root.resolve()
    ctx = ProjectContext(project_root=root)

    for item in _walk(root):
        rel = str(item.relative_to(root))
        ctx.all_files.append(rel)

        if not _is_text_file(item):
            continue

        if item.stat().st_size > MAX_FILE_SIZE:
            ctx.skipped_files.append(rel)
            continue

        try:
            content = item.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            ctx.skipped_files.append(rel)
            continue

        ctx.text_files.append(TextFile(path=rel, content=content))

    ctx.gitignore_patterns = parse_gitignore_files(root)
    return ctx


def _walk(root: Path):
    """Recursively yield files, skipping excluded dirs and symlinks."""
    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        return

    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.is_dir():
            if not _should_skip_dir(entry.name):
                yield from _walk(entry)
        elif entry.is_file():
            yield entry
