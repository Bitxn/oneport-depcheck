import os
import stat
import subprocess


PRE_COMMIT_CONFIG = """\
repos:
  - repo: local
    hooks:
      - id: depcheck
        name: oneport-depcheck vulnerability scan
        entry: depcheck scan --fail-on CRITICAL --no-supply-chain --no-license --no-nvd --no-github
        language: system
        pass_filenames: false
        files: (requirements.*\\.txt|setup\\.py|pyproject\\.toml|package\\.json|package-lock\\.json)$
        stages: [commit]
"""

VSCODE_SETTINGS = """\
{
  "depcheck.enabled": true,
  "depcheck.runOnSave": true,
  "depcheck.severity": "HIGH",
  "depcheck.command": "depcheck scan --no-nvd --no-github --format json",
  "emeraldwalk.runonsave": {
    "commands": [
      {
        "match": "requirements.*\\.txt",
        "cmd": "depcheck scan -r ${file} --no-nvd --format json > .depcheck-last.json 2>&1"
      }
    ]
  }
}
"""

VSCODE_TASKS = """\
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "depcheck: scan project",
      "type": "shell",
      "command": "depcheck scan --fix",
      "group": "test",
      "presentation": { "reveal": "always", "panel": "shared" },
      "problemMatcher": []
    },
    {
      "label": "depcheck: generate SBOM",
      "type": "shell",
      "command": "depcheck sbom",
      "group": "build",
      "presentation": { "reveal": "always" },
      "problemMatcher": []
    },
    {
      "label": "depcheck: open HTML report",
      "type": "shell",
      "command": "depcheck scan -o depcheck-report.html && start depcheck-report.html",
      "windows": { "command": "depcheck scan -o depcheck-report.html && start depcheck-report.html" },
      "linux":   { "command": "depcheck scan -o depcheck-report.html && xdg-open depcheck-report.html" },
      "osx":     { "command": "depcheck scan -o depcheck-report.html && open depcheck-report.html" },
      "group": "test",
      "presentation": { "reveal": "silent" },
      "problemMatcher": []
    }
  ]
}
"""


def install_pre_commit_hook(project_path: str = ".") -> str:
    """
    Install pre-commit hook two ways:
    1. If pre-commit framework is installed → writes .pre-commit-config.yaml
    2. Fallback → writes a raw git hook script to .git/hooks/pre-commit
    """
    if _pre_commit_available():
        config_path = os.path.join(project_path, ".pre-commit-config.yaml")
        if os.path.exists(config_path):
            with open(config_path) as f:
                existing = f.read()
            if "depcheck" in existing:
                return f"depcheck hook already in {config_path}"
            with open(config_path, "a") as f:
                f.write("\n" + PRE_COMMIT_CONFIG)
        else:
            with open(config_path, "w") as f:
                f.write(PRE_COMMIT_CONFIG)

        subprocess.run(["pre-commit", "install"], cwd=project_path,
                       capture_output=True)
        return config_path

    else:
        return _install_git_hook(project_path)


def _install_git_hook(project_path: str) -> str:
    """Write a raw git pre-commit hook script."""
    hooks_dir = os.path.join(project_path, ".git", "hooks")
    if not os.path.isdir(hooks_dir):
        raise FileNotFoundError(
            f"No .git/hooks directory found at {project_path}. "
            "Is this a git repository?"
        )

    hook_path = os.path.join(hooks_dir, "pre-commit")
    hook_script = """\
#!/bin/sh
# oneport-depcheck pre-commit hook
# Auto-installed by: depcheck install-hook

echo "Running depcheck security scan..."
depcheck scan --fail-on CRITICAL --no-nvd --no-github --no-supply-chain
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "COMMIT BLOCKED: Critical vulnerabilities found."
  echo "Run 'depcheck scan --fix' to see upgrade commands."
  echo "Use 'git commit --no-verify' to bypass (not recommended)."
  exit 1
fi

exit 0
"""
    existing = ""
    if os.path.exists(hook_path):
        with open(hook_path) as f:
            existing = f.read()
        if "depcheck" in existing:
            return f"Hook already installed at {hook_path}"
        hook_script = existing.rstrip() + "\n\n" + hook_script

    with open(hook_path, "w") as f:
        f.write(hook_script)

    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path


def _pre_commit_available() -> bool:
    try:
        result = subprocess.run(
            ["pre-commit", "--version"],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def install_vscode_config(project_path: str = ".") -> list[str]:
    """Write VS Code settings.json and tasks.json for depcheck integration."""
    vscode_dir = os.path.join(project_path, ".vscode")
    os.makedirs(vscode_dir, exist_ok=True)

    written = []

    settings_path = os.path.join(vscode_dir, "settings.json")
    if not os.path.exists(settings_path):
        with open(settings_path, "w") as f:
            f.write(VSCODE_SETTINGS)
        written.append(settings_path)

    tasks_path = os.path.join(vscode_dir, "tasks.json")
    if not os.path.exists(tasks_path):
        with open(tasks_path, "w") as f:
            f.write(VSCODE_TASKS)
        written.append(tasks_path)

    return written


def uninstall_hook(project_path: str = ".") -> str:
    """Remove depcheck from .git/hooks/pre-commit."""
    hook_path = os.path.join(project_path, ".git", "hooks", "pre-commit")
    if not os.path.exists(hook_path):
        return "No hook found."
    with open(hook_path) as f:
        lines = f.readlines()
    cleaned = []
    skip = False
    for line in lines:
        if "oneport-depcheck" in line or "depcheck" in line:
            skip = True
        if not skip:
            cleaned.append(line)
        if skip and line.strip() == "":
            skip = False
    with open(hook_path, "w") as f:
        f.writelines(cleaned)
    return hook_path