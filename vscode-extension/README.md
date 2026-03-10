# VibeScan for VS Code

Scan your vibe-coded project for leaked secrets and security issues — directly in VS Code.

## Features

- **Real-time Diagnostics** — Issues appear as underlines in the editor (red for CRITICAL/HIGH, yellow for MEDIUM)
- **Manual Scan** — Run `VibeScan: Scan Project` from the Command Palette (`Ctrl+Shift+P`)
- **Auto Scan on Save** — Enable `vibescan.scanOnSave` to scan automatically
- **Status Bar** — See scan status and issue count at a glance

## Requirements

- Python 3.10+
- `pip install vibescan-cli`

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `vibescan.scanOnSave` | `false` | Automatically scan on file save |
| `vibescan.pythonPath` | `"python"` | Path to Python executable |
| `vibescan.minSeverity` | `"low"` | Minimum severity level to show |

## How It Works

1. Runs `python -m vibescan <project> --format json` in the background
2. Parses the JSON output
3. Maps issues to VS Code Diagnostics (Problems panel)
4. Shows severity-colored underlines on the affected lines

Your code never leaves your machine. VibeScan runs entirely locally.
