"""
engine/response/network_isolator.py
────────────────────────────────────
Response Action — Network Isolation
=====================================
Blocks a specific IP address or IP:Port combination by adding a Windows
Firewall (netsh advfirewall) deny rule, or disabling/re-enabling the NIC
for full host isolation.

Firewall rule lifecycle
───────────────────────
  1. add_block_rule(ip, port)  → creates an outbound+inbound deny rule.
  2. The rule is prefixed with "AI-RIDS-BLOCK-" for easy identification.
  3. If *auto_remove_after_seconds* > 0 a daemon thread schedules removal.
  4. remove_block_rule(ip, port) removes the rule explicitly (or at shutdown).

NIC isolation
─────────────
  isolate_nic(name)   → disables the specified network adapter.
  restore_nic(name)   → re-enables the adapter.

Security notes
──────────────
  • All commands operate only on the local firewall — no remote changes.
  • Rules include the source IP to avoid collateral blocking.
  • The audit log captures all adds / removes.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from typing import Any

from src.utils.logger import get_logger

log = get_logger(__name__)


class NetworkIsolator:
    """
    Adds and removes Windows Firewall deny rules to block malicious hosts.

    Parameters
    ----------
    config : dict
        The ``response.network_isolation`` sub-section of the master config.
    dry_run : bool
        If *True* log actions but do not execute system commands.
    """

    def __init__(self, config: dict[str, Any], dry_run: bool = False) -> None:
        self._prefix      = config.get("rule_prefix", "AI-RIDS-BLOCK")
        self._auto_remove = int(config.get("auto_remove_after_seconds", 3600))
        self._dry_run     = dry_run
        self._active_rules: dict[str, float] = {}   # rule_name → creation ts

    # ── Public interface ──────────────────────────────────────────────────────

    def block_ip(self, ip: str, port: int | None = None, reason: str = "") -> bool:
        """
        Add a Windows Firewall outbound+inbound deny rule for *ip* (and
        optionally *port*).

        Parameters
        ----------
        ip     : str        — Remote IP address to block.
        port   : int | None — Specific port; *None* blocks all ports on *ip*.
        reason : str        — Audit annotation.
        """
        rule_name = self._rule_name(ip, port)

        log.warning(
            "RESPONSE: Block ip=%s port=%s name='%s' reason='%s'",
            ip, port or "*", rule_name, reason,
        )

        if self._dry_run:
            log.info("[DRY-RUN] Firewall rule add skipped.")
            return True

        if sys.platform != "win32":
            return self._iptables_block(ip, port)

        ok_out = self._netsh_add_rule(rule_name + "-OUT", ip, port, "out")
        ok_in  = self._netsh_add_rule(rule_name + "-IN",  ip, port, "in")

        if ok_out or ok_in:
            self._active_rules[rule_name] = time.time()
            if self._auto_remove > 0:
                self._schedule_removal(rule_name, ip, port)
            return True
        return False

    def unblock_ip(self, ip: str, port: int | None = None) -> bool:
        """Remove a previously added block rule."""
        rule_name = self._rule_name(ip, port)
        log.info("RESPONSE: Unblock ip=%s port=%s rule='%s'", ip, port or "*", rule_name)

        if self._dry_run:
            log.info("[DRY-RUN] Firewall rule remove skipped.")
            return True

        if sys.platform != "win32":
            return self._iptables_unblock(ip, port)

        ok_out = self._netsh_del_rule(rule_name + "-OUT")
        ok_in  = self._netsh_del_rule(rule_name + "-IN")
        self._active_rules.pop(rule_name, None)
        return ok_out or ok_in

    def disable_nic(self, adapter_name: str) -> bool:
        """
        Completely isolate the host by disabling a NIC.

        **Use with caution** — this terminates ALL network connectivity
        through the named adapter until :meth:`enable_nic` is called.
        """
        log.critical(
            "RESPONSE: Disabling NIC '%s' for full network isolation.", adapter_name
        )
        if self._dry_run:
            log.info("[DRY-RUN] NIC disable skipped.")
            return True

        if sys.platform != "win32":
            log.warning("NIC disable via netsh is Windows-only.")
            return False

        return self._run_cmd([
            "netsh", "interface", "set", "interface",
            adapter_name, "admin=disabled",
        ])

    def enable_nic(self, adapter_name: str) -> bool:
        """Re-enable a previously disabled NIC."""
        log.info("RESPONSE: Re-enabling NIC '%s'.", adapter_name)
        if self._dry_run:
            return True
        if sys.platform != "win32":
            return False
        return self._run_cmd([
            "netsh", "interface", "set", "interface",
            adapter_name, "admin=enabled",
        ])

    def remove_all_rules(self) -> None:
        """Remove all AI-RIDS firewall rules (cleanup at shutdown)."""
        log.info("Removing all AI-RIDS firewall rules.")
        for rule_name in list(self._active_rules.keys()):
            # Parse ip/port back from rule name
            self._netsh_del_rule(rule_name + "-OUT")
            self._netsh_del_rule(rule_name + "-IN")
        self._active_rules.clear()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _rule_name(self, ip: str, port: int | None) -> str:
        safe_ip = ip.replace(".", "_").replace(":", "_")
        suffix  = f"_{port}" if port else ""
        return f"{self._prefix}-{safe_ip}{suffix}"

    def _netsh_add_rule(
        self, name: str, ip: str, port: int | None, direction: str
    ) -> bool:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            "profile=any",
            "protocol=any",
        ]
        if port:
            cmd += [f"remoteport={port}"]
        return self._run_cmd(cmd)

    def _netsh_del_rule(self, name: str) -> bool:
        return self._run_cmd([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}",
        ])

    def _iptables_block(self, ip: str, port: int | None) -> bool:
        """Linux fallback using iptables OUTPUT/INPUT chains."""
        cmds: list[list[str]] = []
        if port:
            cmds += [
                ["iptables", "-A", "OUTPUT", "-d", ip, "--dport", str(port), "-j", "DROP"],
                ["iptables", "-A", "INPUT",  "-s", ip, "--sport", str(port), "-j", "DROP"],
            ]
        else:
            cmds += [
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                ["iptables", "-A", "INPUT",  "-s", ip, "-j", "DROP"],
            ]
        return all(self._run_cmd(c) for c in cmds)

    def _iptables_unblock(self, ip: str, port: int | None) -> bool:
        cmds: list[list[str]] = []
        if port:
            cmds += [
                ["iptables", "-D", "OUTPUT", "-d", ip, "--dport", str(port), "-j", "DROP"],
                ["iptables", "-D", "INPUT",  "-s", ip, "--sport", str(port), "-j", "DROP"],
            ]
        else:
            cmds += [
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                ["iptables", "-D", "INPUT",  "-s", ip, "-j", "DROP"],
            ]
        return all(self._run_cmd(c) for c in cmds)

    def _run_cmd(self, cmd: list[str]) -> bool:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                log.debug("CMD OK: %s", " ".join(cmd))
                return True
            log.error(
                "CMD failed (rc=%d): %s\nstderr: %s",
                result.returncode, " ".join(cmd), result.stderr.strip(),
            )
            return False
        except subprocess.TimeoutExpired:
            log.error("CMD timed out: %s", " ".join(cmd))
            return False
        except FileNotFoundError:
            log.error("Command not found: %s", cmd[0])
            return False

    def _schedule_removal(self, rule_name: str, ip: str, port: int | None) -> None:
        """Daemon thread that removes a rule after *auto_remove* seconds."""
        def _remove_later() -> None:
            time.sleep(self._auto_remove)
            log.info("Auto-removing firewall rule '%s' after %ds.", rule_name, self._auto_remove)
            self.unblock_ip(ip, port)

        t = threading.Thread(target=_remove_later, daemon=True)
        t.start()
