"""
telemetry/file_monitor.py
─────────────────────────
File System Monitor
===================
Uses the ``watchdog`` library to register OS-native inotify / ReadDirectoryChangesW
callbacks on configured watch paths.

For every file-system event the monitor:
  1. Records the event type (create / modify / delete / rename).
  2. Reads up to 64 KB of modified file content and computes its Shannon entropy.
  3. Inspects the resulting extension for known ransomware suffixes.
  4. Pushes :class:`FileEvent` objects into the shared output queue.

The :class:`~features.aggregator.FeatureAggregator` aggregates these events
over a 5-second sliding window into a compact feature vector.

Shannon entropy reference
─────────────────────────
Plaintext:   ~3–5 bits/byte
Compressed:  ~7–8 bits/byte
Encrypted:   ~7.9–8.0 bits/byte   ← ransomware fingerprint
"""

from __future__ import annotations

import math
import os
import queue
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from src.utils.logger import get_logger

log = get_logger(__name__)

# Bytes to sample for entropy calculation (limit I/O overhead)
_ENTROPY_SAMPLE_BYTES = 65_536   # 64 KB


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class FileEvent:
    """A single file-system telemetry event."""
    timestamp:  float
    event_type: str          # "create" | "modify" | "delete" | "rename"
    path:       str
    extension:  str
    entropy:    float        # Shannon entropy of sampled bytes (0–8)
    is_suspicious_ext: bool  # Extension matches ransomware known list


def compute_shannon_entropy(data: bytes) -> float:
    """
    Compute the Shannon entropy (bits per byte) for *data*.

    H = -∑ p(x) log₂ p(x)   for each unique byte value x.

    Returns a value in [0, 8].  Values ≥ 7.2 indicate heavily compressed
    or encrypted content.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _safe_read_bytes(path: str, max_bytes: int = _ENTROPY_SAMPLE_BYTES) -> bytes:
    """Read up to *max_bytes* bytes from *path*, returning b'' on any error."""
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes)
    except (OSError, PermissionError):
        return b""


# ── Watchdog event handler ────────────────────────────────────────────────────

class _FSHandler(FileSystemEventHandler):
    """Converts watchdog callbacks into :class:`FileEvent` objects."""

    def __init__(
        self,
        output_queue: queue.Queue,
        suspicious_exts: set[str],
        entropy_threshold: float,
    ) -> None:
        super().__init__()
        self._queue = output_queue
        self._suspicious_exts = suspicious_exts
        self._entropy_threshold = entropy_threshold

    # ── Watchdog callbacks ────────────────────────────────────────────────────

    def on_created(self, event: FileCreatedEvent | DirCreatedEvent) -> None:
        if not event.is_directory:
            self._emit(event.src_path, "create")

    def on_modified(self, event: FileModifiedEvent | DirModifiedEvent) -> None:
        if not event.is_directory:
            self._emit(event.src_path, "modify")

    def on_deleted(self, event: FileDeletedEvent | DirDeletedEvent) -> None:
        if not event.is_directory:
            self._emit_no_read(event.src_path, "delete")

    def on_moved(self, event: FileMovedEvent | DirMovedEvent) -> None:
        if not event.is_directory:
            # Ransomware often renames files after encrypting them
            self._emit_no_read(event.dest_path, "rename")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _emit(self, path: str, event_type: str) -> None:
        ext = Path(path).suffix.lower()
        data = _safe_read_bytes(path)
        entropy = compute_shannon_entropy(data)
        self._push(FileEvent(
            timestamp=time.time(),
            event_type=event_type,
            path=path,
            extension=ext,
            entropy=entropy,
            is_suspicious_ext=(ext in self._suspicious_exts),
        ))

    def _emit_no_read(self, path: str, event_type: str) -> None:
        """For delete / rename we cannot read content — entropy is unknown."""
        ext = Path(path).suffix.lower()
        self._push(FileEvent(
            timestamp=time.time(),
            event_type=event_type,
            path=path,
            extension=ext,
            entropy=0.0,
            is_suspicious_ext=(ext in self._suspicious_exts),
        ))

    def _push(self, event: FileEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            log.debug("File event queue full — dropping event for '%s'.", event.path)


# ── Main monitor class ────────────────────────────────────────────────────────

class FileMonitor:
    """
    Monitors one or more directory trees for file-system activity.

    Parameters
    ----------
    config : dict
        The ``telemetry.file`` section of the master configuration.
    output_queue : queue.Queue
        Shared queue consumed by the :class:`~features.aggregator.FeatureAggregator`.
    """

    def __init__(self, config: dict[str, Any], output_queue: queue.Queue) -> None:
        self._cfg = config
        self._queue = output_queue

        self._watch_paths: list[str] = config.get("watch_paths", [])
        self._entropy_threshold: float = config.get("entropy_threshold", 7.2)
        self._suspicious_exts: set[str] = {
            e.lower() for e in config.get("suspicious_extensions", [])
        }

        self._handler = _FSHandler(
            output_queue=self._queue,
            suspicious_exts=self._suspicious_exts,
            entropy_threshold=self._entropy_threshold,
        )
        self._observer = Observer()

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self) -> None:
        paths_monitored: list[str] = []
        for path in self._watch_paths:
            if os.path.isdir(path):
                self._observer.schedule(self._handler, path, recursive=True)
                paths_monitored.append(path)
            else:
                log.warning("Watch path does not exist — skipping: %s", path)

        if not paths_monitored:
            # Fall back to the current working directory so the monitor is
            # never completely silent during development / testing.
            fallback = os.getcwd()
            log.warning(
                "No valid watch paths found.  Monitoring CWD as fallback: %s",
                fallback,
            )
            self._observer.schedule(self._handler, fallback, recursive=False)
            paths_monitored.append(fallback)

        self._observer.start()
        log.info("FileMonitor watching: %s", paths_monitored)

    def stop(self) -> None:
        log.info("FileMonitor stopping.")
        self._observer.stop()
        self._observer.join()
