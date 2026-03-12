# AI-RIDS — Real-Time AI-Driven Ransomware & Intrusion Detection System

> **Senior Security Architect · Lead ML Engineer project**
> Multi-layered telemetry architecture with LightGBM / Random Forest inference
> and an automated threat-response chain.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Layer 1 — Telemetry & Monitoring](#layer-1--telemetry--monitoring)
4. [Layer 2 — Feature Aggregation & AI Model](#layer-2--feature-aggregation--ai-model)
5. [Layer 3 — Decision Engine & Response](#layer-3--decision-engine--response)
6. [Quick-Start](#quick-start)
7. [Configuration Reference](#configuration-reference)
8. [Running the Tests](#running-the-tests)
9. [Security Notes](#security-notes)

---

## Architecture Overview

```
┌──────────────────────── AI-RIDS Daemon ─────────────────────────────────┐
│                                                                          │
│  ┌────────────┐   ┌─────────────┐   ┌──────────────────┐               │
│  │ HPCMonitor │   │ FileMonitor │   │  NetworkMonitor  │               │
│  │ (PDH/psutil│   │ (watchdog + │   │  (Scapy/psutil)  │               │
│  │  thread)   │   │  entropy)   │   │  (thread)        │               │
│  └─────┬──────┘   └──────┬──────┘   └────────┬─────────┘               │
│        │ hpc_q           │ file_q             │ net_q                   │
│        └────────────────►│◄───────────────────┘                         │
│                   ┌──────▼──────────┐                                   │
│                   │FeatureAggregator│  sliding window 5 s               │
│                   │  (23-dim vec)   │  normalised via StandardScaler    │
│                   └──────┬──────────┘                                   │
│                          │ FeatureVector                                 │
│                   ┌──────▼──────────┐                                   │
│                   │ ThreatDetector  │  LightGBM / Random Forest         │
│                   │  predict_proba  │  latency < 5 ms                   │
│                   └──────┬──────────┘                                   │
│                          │ ThreatResult (label + confidence)             │
│                   ┌──────▼──────────┐                                   │
│                   │ DecisionEngine  │  threshold 0.85 → High Alert      │
│                   └──────┬──────────┘                                   │
│           ┌──────────────┼───────────────┐                              │
│   ┌───────▼──┐   ┌───────▼──┐   ┌───────▼──────┐                       │
│   │Kill(PID) │   │NetBlock  │   │FileProtect   │                       │
│   │taskkill  │   │netsh/    │   │icacls + VSS  │                       │
│   │/psutil   │   │iptables  │   │shadow copy   │                       │
│   └──────────┘   └──────────┘   └──────────────┘                       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
Ransomware/
├── config/
│   └── config.yaml              Master YAML configuration
├── src/
│   ├── main.py                  Application entry-point & orchestrator
│   ├── telemetry/
│   │   ├── hpc_monitor.py       Hardware Performance Counter monitor (PDH + psutil)
│   │   ├── file_monitor.py      File System Monitor (watchdog + Shannon entropy)
│   │   └── network_monitor.py   Network Flow Monitor (Scapy / psutil fallback)
│   ├── features/
│   │   ├── aggregator.py        Sliding-window feature aggregation pipeline
│   │   └── preprocessor.py      Feature normalisation (StandardScaler etc.)
│   ├── models/
│   │   ├── trainer.py           LightGBM / RF training + synthetic data generation
│   │   └── detector.py          Real-time inference wrapper (< 5 ms latency)
│   ├── engine/
│   │   ├── decision_engine.py   Threshold logic + response-chain orchestrator
│   │   └── response/
│   │       ├── process_killer.py   taskkill / psutil process termination
│   │       ├── network_isolator.py netsh / iptables IP/port blocking
│   │       └── file_protector.py   icacls write-revocation + VSS snapshots
│   └── utils/
│       ├── logger.py            Colour-coded rotating logger
│       └── config_loader.py     YAML config loader with validation
├── tests/
│   ├── test_telemetry.py        Entropy, HPC sample, beacon scoring tests
│   ├── test_features.py         Aggregation, preprocessing, FeatureVector tests
│   └── test_engine.py           DecisionEngine, Detector, Trainer, Response tests
├── data/                        Training datasets & synthetic CSVs
├── models/saved/                Persisted model artefacts (auto-created)
├── logs/                        Rotating log files (auto-created)
├── conftest.py                  pytest path configuration
└── requirements.txt
```

---

## Layer 1 — Telemetry & Monitoring

### HPC Monitor (`src/telemetry/hpc_monitor.py`)

| Signal | Ransomware indicator |
|---|---|
| CPU privileged-mode % spike | Kernel-level crypto routines |
| Cache-fault rate surge | Unusual memory-access pattern (encryption loop) |
| Interrupt / syscall rate flood | Mass file I/O (encrypting thousands of files) |
| Context-switch storm | Parallel encryption threads |

Uses the **Windows PDH (Performance Data Helper)** API via `ctypes` with an
automatic fallback to `psutil` on non-Windows or containerised environments.

### File System Monitor (`src/telemetry/file_monitor.py`)

- Integrates with `watchdog` (which uses **ReadDirectoryChangesW** on Windows).
- Computes **Shannon entropy** (bits/byte) on up to 64 KB of each written file:

  | Content type | Entropy (bits/byte) |
  |---|---|
  | Plain text | ~3–5 |
  | Compressed | ~7–8 |
  | **Encrypted** | **≥ 7.9** ← ransomware fingerprint |

- Flags **known ransomware extensions**: `.locked`, `.enc`, `.wcry`, `.zepto`, etc.
- Counts **mass deletes** and **renames** per window as additional indicators.

### Network Monitor (`src/telemetry/network_monitor.py`)

- **Scapy** `AsyncSniffer` for raw packet capture (falls back to `psutil` net counters).
- Maintains a per-flow state table `(src_ip, dst_ip, dst_port, proto)`.
- **C2 Beacon detection**: computes a 0–1 score based on the coefficient of
  variation of inter-connection intervals.  Low CV at a regular cadence = beacon.
- **Exfiltration flag**: triggers when outbound bytes in a window exceed the
  configured threshold (default 5 MB).
- **Blacklisted ports**: instantly flags connections to known C2 ports.

---

## Layer 2 — Feature Aggregation & AI Model

### Feature Aggregator (`src/features/aggregator.py`)

Every **5 seconds** the aggregator:
1. Drains all three source queues.
2. Reduces each stream to statistical summaries (mean, max, count).
3. Concatenates into one **23-dimensional** normalised feature vector:

   | Indices | Source | Dims |
   |---|---|---|
   | 0–7 | HPC telemetry | 8 |
   | 8–14 | File events | 7 |
   | 15–22 | Network flows | 8 |

### AI Detection Model (`src/models/trainer.py` + `detector.py`)

- **Algorithm**: LightGBM (default) with Random Forest fallback.
- **Classes**: `Benign` (0), `Suspicious` (1), `Malicious` (2).
- **Training dataset**: CIC-IDS CSV or auto-generated synthetic data.
- **Inference latency**: typically **< 5 ms** on a standard desktop CPU.
- **CV F1-macro** on synthetic data: ≥ 0.97.

Training:
```bash
python -m src.models.trainer --config config/config.yaml
# Or with a real dataset:
python -m src.models.trainer --dataset data/cic_ids_features.csv
```

---

## Layer 3 — Decision Engine & Response

### Threshold Logic

| Confidence | Decision | Action |
|---|---|---|
| < 0.60 | Benign | Log at DEBUG |
| 0.60 – 0.84 | Suspicious | Log WARNING alert |
| **≥ 0.85** | **High Alert** | **Trigger full response chain** |

### Response Chain (High Alert ≥ 0.85)

```
Step 1 — Kill Process
   Windows: taskkill /F /PID <pid>
   POSIX:   psutil.Process(pid).kill()

Step 2 — Network Isolation
   Windows: netsh advfirewall firewall add rule … action=block
   Linux:   iptables -A OUTPUT/INPUT -d <ip> -j DROP
   Auto-remove rule after configurable duration (default 1 h)

Step 3 — File Protection
   a. icacls <critical_dir> /deny *S-1-1-0:(W,WD,WDAC,WO) /T /C
      (strips write access from Everyone on critical directories)
   b. vssadmin create shadow /for=C:
      (creates a Volume Shadow Copy as a recovery point)
```

**Cooldown**: a 30-second per-PID cooldown prevents duplicate response
chains for the same incident.

**Dry-run mode**: all actions are logged but never executed:
```bash
python src/main.py --dry-run
```

---

## Quick-Start

```bash
# 1. Clone & enter the repo
git clone https://github.com/Aditya17-04/Ransomware.git
cd Ransomware

# 2. Create and activate a virtual environment (Python 3.9+)
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Train the model (generates synthetic data automatically)
python -m src.models.trainer --config config/config.yaml

# 5. Start the detection daemon (dry-run recommended for first run)
python src/main.py --dry-run

# Or train + run in one shot
python src/main.py --train-first --dry-run
```

> **Administrator privileges** are required for live traffic capture (Scapy)
> and for response actions (taskkill, netsh, icacls, vssadmin).

---

## Configuration Reference

All settings live in [`config/config.yaml`](config/config.yaml).

| Key | Default | Description |
|---|---|---|
| `telemetry.window_seconds` | `5` | Sliding-window aggregation interval |
| `telemetry.hpc.poll_interval_ms` | `500` | HPC sampling frequency |
| `telemetry.file.entropy_threshold` | `7.2` | Shannon entropy flag level |
| `telemetry.file.watch_paths` | `C:\Users, C:\Documents` | Directories to monitor |
| `telemetry.network.exfil_bytes_threshold` | `5000000` | Outbound-bytes exfil limit / window |
| `model.algorithm` | `lightgbm` | `lightgbm` or `random_forest` |
| `decision.thresholds.suspicious` | `0.60` | Confidence for Suspicious alert |
| `decision.thresholds.high_alert` | `0.85` | Confidence for High Alert + response |
| `decision.cooldown_seconds` | `30` | Per-PID duplicate-action suppression |
| `decision.dry_run` | `false` | Log actions only — no execution |
| `response.network_isolation.auto_remove_after_seconds` | `3600` | Firewall rule TTL |

---

## Running the Tests

```bash
# All tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=term-missing -v

# Specific test file
pytest tests/test_engine.py -v
```

---

## Security Notes

- **Principle of least privilege**: run with only the privileges needed for
  the specific actions enabled in config.  For monitoring-only mode (no
  response), no elevated rights are required beyond packet-capture access.
- **Audit trail**: every response action is logged at `WARNING` or `CRITICAL`
  level with the PID, IP, confidence score, and timestamp.
- **Dry-run default**: set `decision.dry_run: true` in config for safe
  evaluation before enabling live response.
- **No credentials stored**: the system does not store, transmit, or log
  passwords or cryptographic keys.
- **Input validation**: all YAML config values are validated at load time;
  subprocess calls use list arguments (not shell=True) to prevent injection.

---

## License

See [LICENSE](LICENSE).
