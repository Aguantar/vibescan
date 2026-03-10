import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";

interface VibeScanIssue {
  rule_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  file: string;
  line: number | null;
  message: string;
  why: string;
  fix: string;
}

interface VibeScanResult {
  project_root: string;
  files_scanned: number;
  summary: Record<string, number>;
  exit_code: number;
  issues: VibeScanIssue[];
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  LOW: vscode.DiagnosticSeverity.Information,
  INFO: vscode.DiagnosticSeverity.Hint,
};

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let scanning = false;

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("vibescan");
  context.subscriptions.push(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "vibescan.scan";
  statusBarItem.text = "$(shield) VibeScan";
  statusBarItem.tooltip = "Click to scan project";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("vibescan.scan", () => runScan()),
    vscode.commands.registerCommand("vibescan.clear", () => {
      diagnosticCollection.clear();
      statusBarItem.text = "$(shield) VibeScan";
      statusBarItem.tooltip = "Click to scan project";
    })
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      const config = vscode.workspace.getConfiguration("vibescan");
      if (config.get<boolean>("scanOnSave")) {
        runScan();
      }
    })
  );
}

async function runScan() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showWarningMessage("VibeScan: No workspace folder open.");
    return;
  }

  if (scanning) {
    return;
  }
  scanning = true;

  const config = vscode.workspace.getConfiguration("vibescan");
  const pythonPath = config.get<string>("pythonPath") || "python";
  const minSeverity = config.get<string>("minSeverity") || "low";
  const projectPath = workspaceFolder.uri.fsPath;

  statusBarItem.text = "$(loading~spin) VibeScan scanning...";
  statusBarItem.tooltip = "Scanning in progress...";

  try {
    const result = await execVibescan(
      pythonPath,
      projectPath,
      minSeverity
    );
    applyDiagnostics(result, projectPath);

    const total = result.issues.length;
    const critical = result.summary.critical || 0;
    const high = result.summary.high || 0;

    if (total === 0) {
      statusBarItem.text = "$(shield) VibeScan: Clean";
      statusBarItem.tooltip = `Scanned ${result.files_scanned} files — no issues`;
      vscode.window.showInformationMessage(
        `VibeScan: No issues found in ${result.files_scanned} files.`
      );
    } else {
      statusBarItem.text = `$(warning) VibeScan: ${total} issues`;
      statusBarItem.tooltip = `CRITICAL: ${critical} | HIGH: ${high} | Total: ${total}`;

      const severity =
        critical > 0 ? "CRITICAL" : high > 0 ? "HIGH" : "MEDIUM";
      const showFn =
        critical > 0 || high > 0
          ? vscode.window.showErrorMessage
          : vscode.window.showWarningMessage;
      showFn(
        `VibeScan: Found ${total} issues (${severity} ${critical > 0 ? critical : high > 0 ? high : total}).`
      );
    }
  } catch (err: unknown) {
    statusBarItem.text = "$(error) VibeScan: Error";
    const message = err instanceof Error ? err.message : String(err);

    if (
      message.includes("ENOENT") ||
      message.includes("not found") ||
      message.includes("No module")
    ) {
      const action = await vscode.window.showErrorMessage(
        "VibeScan: vibescan-cli is not installed. Install it?",
        "Install via pip"
      );
      if (action) {
        const terminal = vscode.window.createTerminal("VibeScan Install");
        terminal.sendText("pip install vibescan-cli");
        terminal.show();
      }
    } else {
      vscode.window.showErrorMessage(`VibeScan: ${message}`);
    }
  } finally {
    scanning = false;
  }
}

function execVibescan(
  pythonPath: string,
  projectPath: string,
  minSeverity: string
): Promise<VibeScanResult> {
  return new Promise((resolve, reject) => {
    const args = [
      "-m",
      "vibescan",
      projectPath,
      "--format",
      "json",
      "--min-severity",
      minSeverity,
    ];

    execFile(
      pythonPath,
      args,
      {
        cwd: projectPath,
        maxBuffer: 10 * 1024 * 1024,
        timeout: 120_000,
      },
      (error, stdout, stderr) => {
        // vibescan returns exit code 1 when issues found — that's normal
        if (error && !stdout.trim()) {
          reject(new Error(stderr || error.message));
          return;
        }

        try {
          const result: VibeScanResult = JSON.parse(stdout);
          resolve(result);
        } catch {
          reject(new Error(`Failed to parse VibeScan output: ${stdout.slice(0, 200)}`));
        }
      }
    );
  });
}

function applyDiagnostics(result: VibeScanResult, projectPath: string) {
  diagnosticCollection.clear();

  // Group issues by file
  const byFile = new Map<string, VibeScanIssue[]>();
  for (const issue of result.issues) {
    const filePath = path.isAbsolute(issue.file)
      ? issue.file
      : path.join(projectPath, issue.file);
    const existing = byFile.get(filePath) || [];
    existing.push(issue);
    byFile.set(filePath, existing);
  }

  for (const [filePath, issues] of byFile) {
    const uri = vscode.Uri.file(filePath);
    const diagnostics: vscode.Diagnostic[] = issues.map((issue) => {
      const line = Math.max((issue.line || 1) - 1, 0);
      const range = new vscode.Range(line, 0, line, 1000);
      const severity =
        SEVERITY_MAP[issue.severity] ?? vscode.DiagnosticSeverity.Warning;

      const diag = new vscode.Diagnostic(range, issue.message, severity);
      diag.source = "VibeScan";
      diag.code = issue.rule_id;

      // Add why + fix as related information
      const detail = `${issue.why}\nFix: ${issue.fix}`;
      diag.message = `[${issue.severity}] ${issue.message}\n${detail}`;

      return diag;
    });

    // Sort by severity
    diagnostics.sort((a, b) => {
      const aRank = a.severity ?? 3;
      const bRank = b.severity ?? 3;
      return aRank - bRank;
    });

    diagnosticCollection.set(uri, diagnostics);
  }
}

export function deactivate() {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}
