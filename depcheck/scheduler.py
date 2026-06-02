import os
import sys
import subprocess
import platform
from pathlib import Path


def install_cron_job(
    requirements_path: str = None,
    slack_webhook: str = None,
    schedule: str = "0 9 * * 1",  # Every Monday 9am
) -> str:
    """
    Install a weekly cron job that runs depcheck scan automatically.
    Works on Linux and macOS. Returns the cron entry added.
    """
    if platform.system() == "Windows":
        return _install_windows_task(requirements_path, slack_webhook)

    depcheck_bin = _find_depcheck()
    cmd_parts = [depcheck_bin, "scan"]

    if requirements_path:
        cmd_parts += ["-r", os.path.abspath(requirements_path)]

    cmd_parts += ["--no-nvd", "--fail-on", "CRITICAL"]

    if slack_webhook:
        cmd_parts += ["--slack-webhook", slack_webhook]

    log_path = os.path.expanduser("~/.depcheck/scheduled-scan.log")
    cmd = " ".join(cmd_parts)
    cron_line = f"{schedule} {cmd} >> {log_path} 2>&1"

    current = _get_crontab()
    if cmd in current:
        return f"Cron job already installed:\n  {cron_line}"

    new_crontab = current.rstrip() + f"\n{cron_line}\n"
    _set_crontab(new_crontab)
    return cron_line


def remove_cron_job() -> bool:
    """Remove any depcheck cron entries."""
    current = _get_crontab()
    lines = [l for l in current.splitlines() if "depcheck" not in l]
    _set_crontab("\n".join(lines) + "\n")
    return True


def _find_depcheck() -> str:
    import shutil
    path = shutil.which("depcheck")
    if path:
        return path
    return sys.executable.replace("python", "depcheck")


def _get_crontab() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def _set_crontab(content: str) -> None:
    proc = subprocess.Popen(
        ["crontab", "-"],
        stdin=subprocess.PIPE, text=True
    )
    proc.communicate(content)


def _install_windows_task(requirements_path: str, slack_webhook: str) -> str:
    """
    Generate a Windows Task Scheduler XML for weekly scans.
    Returns the XML string — user runs schtasks to register it.
    """
    depcheck_bin = _find_depcheck()
    args = "scan"
    if requirements_path:
        args += f" -r {requirements_path}"
    if slack_webhook:
        args += f" --slack-webhook {slack_webhook}"

    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-01T09:00:00</StartBoundary>
      <ScheduleByWeek><WeeksInterval>1</WeeksInterval>
        <DaysOfWeek><Monday/></DaysOfWeek>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>{depcheck_bin}</Command>
      <Arguments>{args}</Arguments>
    </Exec>
  </Actions>
</Task>"""

    task_path = "depcheck-task.xml"
    with open(task_path, "w", encoding="utf-16") as f:
        f.write(xml)

    return (f"Windows task XML written to {task_path}\n"
            f"Register with:\n"
            f"  schtasks /Create /XML {task_path} /TN depcheck-weekly")


def show_schedule_status(console) -> None:
    """Show whether a scheduled scan is installed."""
    if platform.system() == "Windows":
        console.print("[dim]Check Task Scheduler for 'depcheck-weekly'[/dim]")
        return
    current = _get_crontab()
    lines = [l for l in current.splitlines() if "depcheck" in l]
    if lines:
        console.print("[green]Scheduled scan is active:[/green]")
        for l in lines:
            console.print(f"  [dim]{l}[/dim]")
    else:
        console.print("[yellow]No scheduled scan installed.[/yellow]")
        console.print("[dim]Run: depcheck schedule --install[/dim]")
    console.print()