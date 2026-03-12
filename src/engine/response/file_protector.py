"""
engine/response/file_protector.py
───────────────────────────────────
Response Action — File Protection & Recovery
=============================================
Two complementary defences are implemented:

1. **Write-permission revocation** (`revoke_write`)
   Uses ``icacls`` (Windows) or ``chmod`` (POSIX) to strip write permissions
   from directories classified as critical.  This immediately prevents a
   ransomware process from encrypting or deleting further files.

2. **Volume Shadow Copy (VSS) snapshot** (`create_vss_snapshot`)
   Calls ``vssadmin create shadow /for=<drive>`` to create an on-demand
   shadow copy of the target volume.  If files are already encrypted, the
   shadow copy provides a clean recovery point.

Restoration
───────────
  `restore_write(path)`   — re-grants users write access (post-remediation).
  `list_vss_snapshots()`  — lists available shadow copies.

Security notes
──────────────
  • These commands require Administrator / elevated privileges.
  • All operations are logged at WARNING or above for SIEM ingestion.
  • Dry-run mode is fully supported.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from src.utils.logger import get_logger

log = get_logger(__name__)


class FileProtector:
    """
    Protects critical directories and invokes VSS backups.

    Parameters
    ----------
    config : dict
        The ``response.file_protection`` sub-section of the master config.
    dry_run : bool
        If *True* log actions but do not execute system commands.
    """

    def __init__(self, config: dict[str, Any], dry_run: bool = False) -> None:
        self._protected_dirs: list[str] = config.get("protected_dirs", [])
        self._vss_enabled:    bool      = config.get("vss_backup", True)
        self._revoke_on_alert: bool     = config.get("revoke_write_on_alert", True)
        self._dry_run = dry_run

    # ── Public interface ──────────────────────────────────────────────────────

    def protect_all_critical_dirs(self, reason: str = "") -> list[bool]:
        """
        Revoke write access on all directories listed in *config.protected_dirs*.

        Returns a list of per-directory success flags.
        """
        results: list[bool] = []
        for path in self._protected_dirs:
            results.append(self.revoke_write(path, reason=reason))
        return results

    def revoke_write(self, path: str, reason: str = "") -> bool:
        """
        Strip write permissions from *path* for all non-SYSTEM users.

        On Windows:  ``icacls <path> /deny *S-1-1-0:(W) /T``
        On Linux:    ``chmod -R a-w <path>``
        """
        resolved = Path(path)
        log.warning(
            "RESPONSE: Revoke write on '%s' (exists=%s) reason='%s'",
            path, resolved.exists(), reason,
        )

        if self._dry_run:
            log.info("[DRY-RUN] revoke_write skipped.")
            return True

        if sys.platform == "win32":
            return self._icacls_deny(str(resolved))
        return self._chmod_remove_write(str(resolved))

    def restore_write(self, path: str) -> bool:
        """
        Restore write permissions on *path* after threat remediation.

        On Windows:  ``icacls <path> /remove:d *S-1-1-0 /T``
        On Linux:    ``chmod -R u+w <path>``
        """
        log.info("RESPONSE: Restore write on '%s'.", path)

        if self._dry_run:
            log.info("[DRY-RUN] restore_write skipped.")
            return True

        if sys.platform == "win32":
            return self._icacls_grant(path)
        return self._chmod_restore_write(path)

    def create_vss_snapshot(self, drive: str = "C:") -> str | None:
        """
        Trigger a Volume Shadow Copy snapshot for *drive*.

        Parameters
        ----------
        drive : str
            Drive letter with colon, e.g. ``"C:"``.

        Returns
        -------
        str | None
            The GUID of the created shadow copy, or *None* on failure.
        """
        if not self._vss_enabled:
            log.info("VSS backup is disabled in config.")
            return None

        if sys.platform != "win32":
            log.warning("VSS is Windows-only — skipping on %s.", sys.platform)
            return None

        log.warning(
            "RESPONSE: Creating VSS shadow copy for drive '%s'.", drive
        )

        if self._dry_run:
            log.info("[DRY-RUN] VSS create skipped.")
            return "DRY-RUN-GUID"

        return self._vssadmin_create(drive)

    def list_vss_snapshots(self) -> list[dict[str, str]]:
        """Return a list of dicts describing existing shadow copies."""
        if sys.platform != "win32":
            return []
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=30,
            )
            return self._parse_vss_list(result.stdout)
        except Exception as exc:
            log.error("Failed to list VSS snapshots: %s", exc)
            return []

    # ── Windows icacls helpers ────────────────────────────────────────────────

    def _icacls_deny(self, path: str) -> bool:
        """
        Deny write access to Everyone (SID *S-1-1-0*).

        ``Everyone:(W)`` covers CreateFiles, WriteData, WriteAttributes.
        ``/T`` applies recursively; ``/C`` continues on error.
        """
        return self._run_cmd([
            "icacls", path,
            "/deny", "*S-1-1-0:(W,WD,WDAC,WO)",
            "/T", "/C", "/Q",
        ])

    def _icacls_grant(self, path: str) -> bool:
        """Remove the explicit deny ACE previously added by _icacls_deny."""
        return self._run_cmd([
            "icacls", path,
            "/remove:d", "*S-1-1-0",
            "/T", "/C", "/Q",
        ])

    # ── POSIX chmod helpers ───────────────────────────────────────────────────

    def _chmod_remove_write(self, path: str) -> bool:
        return self._run_cmd(["chmod", "-R", "a-w", path])

    def _chmod_restore_write(self, path: str) -> bool:
        return self._run_cmd(["chmod", "-R", "u+w", path])

    # ── VSS helpers ───────────────────────────────────────────────────────────

    def _vssadmin_create(self, drive: str) -> str | None:
        try:
            result = subprocess.run(
                ["vssadmin", "create", "shadow", f"/for={drive}"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                guid = self._extract_vss_guid(result.stdout)
                log.info("VSS shadow copy created: %s", guid)
                return guid
            log.error("vssadmin create shadow failed:\n%s", result.stderr)
            return None
        except subprocess.TimeoutExpired:
            log.error("VSS snapshot creation timed out.")
            return None
        except FileNotFoundError:
            log.error("'vssadmin' not found — VSS requires Windows Server/Pro.")
            return None

    @staticmethod
    def _extract_vss_guid(output: str) -> str:
        """Parse the shadow copy GUID from vssadmin stdout."""
        match = re.search(r"\{[0-9a-fA-F\-]{36}\}", output)
        return match.group(0) if match else "UNKNOWN-GUID"

    @staticmethod
    def _parse_vss_list(output: str) -> list[dict[str, str]]:
        """Very simple parser for ``vssadmin list shadows`` output."""
        snapshots: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Shadow Copy ID:"):
                if current:
                    snapshots.append(current)
                current = {"id": line.split(":", 1)[1].strip()}
            elif line.startswith("Shadow Copy Volume:") and current:
                current["volume"] = line.split(":", 1)[1].strip()
            elif line.startswith("Creation Time:") and current:
                current["created"] = line.split(":", 1)[1].strip()
        if current:
            snapshots.append(current)
        return snapshots

    # ── Generic subprocess runner ─────────────────────────────────────────────

    def _run_cmd(self, cmd: list[str]) -> bool:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                log.debug("CMD OK: %s", " ".join(cmd))
                return True
            log.error(
                "CMD failed (rc=%d): %s\n%s",
                result.returncode, " ".join(cmd), result.stderr.strip(),
            )
            return False
        except subprocess.TimeoutExpired:
            log.error("CMD timed out: %s", " ".join(cmd))
            return False
        except FileNotFoundError:
            log.error("Command not found: '%s'", cmd[0])
            return False
