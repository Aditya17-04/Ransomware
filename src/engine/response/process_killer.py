"""
engine/response/process_killer.py
──────────────────────────────────
Response Action — Kill Malicious Process
=========================================
Terminates a process identified by PID using the Windows ``taskkill``
command or, as a fallback, :mod:`psutil`.

Security considerations
───────────────────────
  • Only processes explicitly flagged by the Decision Engine are killed —
    never entire process trees unless the ``force`` flag is set.
  • The action is fully audited via the structured logger.
  • In *dry-run* mode the system call is skipped and only the log is written.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import psutil

from src.utils.logger import get_logger

log = get_logger(__name__)


class ProcessKiller:
    """
    Terminates a process by PID.

    Parameters
    ----------
    config : dict
        The ``response.kill_process`` sub-section of the master config.
    dry_run : bool
        If *True* log the action but do not execute it.
    """

    def __init__(self, config: dict[str, Any], dry_run: bool = False) -> None:
        self._force   = config.get("force", True)
        self._dry_run = dry_run

    # ── Public interface ──────────────────────────────────────────────────────

    def kill(self, pid: int, reason: str = "") -> bool:
        """
        Terminate the process with *pid*.

        Parameters
        ----------
        pid     : int   — Process ID to terminate.
        reason  : str   — Human-readable reason (for audit log).

        Returns
        -------
        bool
            *True* if the process was successfully terminated (or does not
            exist), *False* otherwise.
        """
        if not self._process_exists(pid):
            log.warning("Kill requested for PID %d but process not found.", pid)
            return True   # Already gone — mission accomplished.

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe  = proc.exe() if hasattr(proc, "exe") else "unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            log.warning("Could not introspect PID %d before killing.", pid)
            name, exe = "unknown", "unknown"

        log.warning(
            "RESPONSE: Kill PID=%d  name='%s'  exe='%s'  reason='%s'",
            pid, name, exe, reason,
        )

        if self._dry_run:
            log.info("[DRY-RUN] Process kill skipped.")
            return True

        # ── Windows taskkill ──────────────────────────────────────────────────
        if sys.platform == "win32":
            return self._taskkill(pid)

        # ── POSIX fallback via psutil ─────────────────────────────────────────
        return self._psutil_kill(pid)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _process_exists(self, pid: int) -> bool:
        return psutil.pid_exists(pid)

    def _taskkill(self, pid: int) -> bool:
        cmd = ["taskkill", "/PID", str(pid)]
        if self._force:
            cmd.append("/F")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                log.info("PID %d terminated via taskkill.", pid)
                return True
            log.error(
                "taskkill failed for PID %d: %s", pid, result.stderr.strip()
            )
            return False
        except subprocess.TimeoutExpired:
            log.error("taskkill timed out for PID %d.", pid)
            return False
        except FileNotFoundError:
            log.error("'taskkill' not found — falling back to psutil.")
            return self._psutil_kill(pid)

    def _psutil_kill(self, pid: int) -> bool:
        try:
            proc = psutil.Process(pid)
            if self._force:
                proc.kill()
            else:
                proc.terminate()
            proc.wait(timeout=5)
            log.info("PID %d terminated via psutil.", pid)
            return True
        except psutil.NoSuchProcess:
            log.info("PID %d already exited.", pid)
            return True
        except psutil.AccessDenied:
            log.error("Access denied killing PID %d — insufficient privileges.", pid)
            return False
        except Exception as exc:
            log.error("Failed to kill PID %d: %s", pid, exc)
            return False
