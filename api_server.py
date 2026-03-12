"""
api_server.py
─────────────
Flask REST API bridge for the AI-RIDS React UI.

Simulates a live telemetry pipeline that cycles through Benign → Suspicious
→ Malicious phases every ~2.5 minutes, emitting realistic metric values and
generating AlertRecord entries for the Alerts tab.

Endpoints
─────────
  GET /api/status        — System health & current threat label
  GET /api/telemetry     — Rolling 60-point history for HPC / File / Network
  GET /api/threat        — Rolling confidence history + latest reading
  GET /api/alerts        — List of the last 200 triggered alerts
  GET /api/config        — Full config.yaml contents
  GET /api/model         — Model metadata and thresholds

Run
───
  pip install flask flask-cors pyyaml
  python api_server.py
"""

from __future__ import annotations

import math
import os
import random
import threading
import time
from collections import deque

import yaml
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ─── In-memory circular buffers ───────────────────────────────────────────────
MAX_HISTORY = 60          # ~5 min at 5s interval

hpc_history    : deque = deque(maxlen=MAX_HISTORY)
file_history   : deque = deque(maxlen=MAX_HISTORY)
net_history    : deque = deque(maxlen=MAX_HISTORY)
threat_history : deque = deque(maxlen=MAX_HISTORY)
alerts         : deque = deque(maxlen=200)

_alert_id   = 0
_start_time = time.time()
_state_lock = threading.Lock()


# ─── Simulation thread ────────────────────────────────────────────────────────

def _noise(sigma: float = 1.0) -> float:
    return random.gauss(0, sigma)


def _simulate() -> None:
    global _alert_id

    # Phase cycle: 0=Benign(30 ticks), 1=Suspicious(20), 2=Malicious(15)
    phases       = [("Benign", 30), ("Suspicious", 20), ("Malicious", 15)]
    phase_idx    = 0
    phase_tick   = 0

    while True:
        phase_name, phase_len = phases[phase_idx]

        t = time.time()
        ts = round(t * 1000)   # ms epoch for JS

        if phase_name == "Benign":
            cpu      = max(0, 12 + _noise(4))
            priv     = max(0,  2 + _noise(1))
            cache    = max(0, 45 + _noise(15))
            page     = max(0,  8 + _noise(4))
            ctx      = max(0, 480 + _noise(80))
            syscalls = max(0, 750 + _noise(150))
            f_evts   = max(0,  2 + abs(_noise(1)))
            entropy  = max(0, min(8, 3.4 + _noise(0.4)))
            renames  = max(0, abs(_noise(0.5)))
            deletes  = max(0, abs(_noise(0.3)))
            bytes_out = max(0, 48000 + _noise(9000))
            conns    = max(1,  3 + abs(_noise(1)))
            conf     = max(0, min(1, 0.06 + abs(_noise(0.04))))
            label    = "Benign"

        elif phase_name == "Suspicious":
            cpu      = max(0,  58 + _noise(10))
            priv     = max(0,  18 + _noise(5))
            cache    = max(0, 420 + _noise(90))
            page     = max(0,  85 + _noise(18))
            ctx      = max(0, 2100 + _noise(350))
            syscalls = max(0, 5200 + _noise(900))
            f_evts   = max(0,  18 + abs(_noise(5)))
            entropy  = max(0, min(8, 6.4 + _noise(0.4)))
            renames  = max(0,  6 + abs(_noise(2)))
            deletes  = max(0,  4 + abs(_noise(1.5)))
            bytes_out = max(0, 550000 + _noise(80000))
            conns    = max(1,  16 + abs(_noise(4)))
            conf     = max(0, min(1, 0.68 + abs(_noise(0.07))))
            label    = "Suspicious"

        else:  # Malicious
            cpu      = max(0,  91 + _noise(4))
            priv     = max(0,  62 + _noise(8))
            cache    = max(0, 2100 + _noise(400))
            page     = max(0,  510 + _noise(80))
            ctx      = max(0, 8200 + _noise(900))
            syscalls = max(0, 21000 + _noise(2500))
            f_evts   = max(0,  85 + abs(_noise(18)))
            entropy  = max(0, min(8, 7.65 + _noise(0.15)))
            renames  = max(0,  32 + abs(_noise(7)))
            deletes  = max(0,  26 + abs(_noise(5)))
            bytes_out = max(0, 6200000 + _noise(400000))
            conns    = max(1,  52 + abs(_noise(9)))
            conf     = max(0, min(1, 0.93 + abs(_noise(0.025))))
            label    = "Malicious"

        # --- probabilities (must sum to ~1)
        if label == "Benign":
            p_b, p_s, p_m = conf, round(random.uniform(0.03, 0.10), 4), round(random.uniform(0.01, 0.06), 4)
        elif label == "Suspicious":
            p_b  = round(random.uniform(0.05, 0.15), 4)
            p_s  = conf
            p_m  = round(random.uniform(0.04, 0.12), 4)
        else:
            p_b  = round(random.uniform(0.01, 0.06), 4)
            p_s  = round(random.uniform(0.02, 0.10), 4)
            p_m  = conf

        with _state_lock:
            hpc_history.append({
                "ts": ts,
                "cpu_total_pct":          round(cpu,      2),
                "cpu_privileged_pct":     round(priv,     2),
                "cache_faults_per_sec":   round(cache,    1),
                "page_faults_per_sec":    round(page,     1),
                "context_switches_per_sec": round(ctx,    0),
                "syscalls_per_sec":       round(syscalls, 0),
            })

            file_history.append({
                "ts": ts,
                "events_per_window": round(f_evts,  1),
                "avg_entropy":       round(entropy, 3),
                "renames":           round(renames, 1),
                "deletes":           round(deletes, 1),
            })

            net_history.append({
                "ts": ts,
                "bytes_out":   round(bytes_out),
                "connections": round(conns, 1),
            })

            threat_history.append({
                "ts":          ts,
                "label":       label,
                "confidence":  round(conf, 4),
                "probabilities": {
                    "Benign":     round(p_b, 4),
                    "Suspicious": round(p_s, 4),
                    "Malicious":  round(p_m, 4),
                },
            })

            # Emit alerts
            if label == "Malicious" and conf >= 0.85 and random.random() < 0.35:
                _alert_id += 1
                alerts.appendleft({
                    "id":          _alert_id,
                    "ts":          ts,
                    "level":       "HighAlert",
                    "label":       "Malicious",
                    "confidence":  round(conf, 4),
                    "pid":         random.randint(1000, 65535),
                    "remote_ip":   f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    "remote_port": random.choice([4444, 1337, 31337, 6666, 8080]),
                    "actions_taken": ["kill_process", "network_isolation", "file_protection"],
                })
            elif label == "Suspicious" and conf >= 0.60 and random.random() < 0.25:
                _alert_id += 1
                alerts.appendleft({
                    "id":          _alert_id,
                    "ts":          ts,
                    "level":       "Suspicious",
                    "label":       "Suspicious",
                    "confidence":  round(conf, 4),
                    "pid":         random.randint(1000, 65535),
                    "remote_ip":   f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                    "remote_port": random.choice([443, 8080, 9999, 3389]),
                    "actions_taken": ["logged"],
                })

        # Advance phase
        phase_tick += 1
        if phase_tick >= phase_len:
            phase_tick = 0
            phase_idx  = (phase_idx + 1) % len(phases)

        time.sleep(5)


_sim_thread = threading.Thread(target=_simulate, daemon=True, name="sim")
_sim_thread.start()


# ─── Config helper ────────────────────────────────────────────────────────────

def _load_config() -> dict:
    cfg_path = os.path.join(os.path.dirname(__file__), "config", "config.yaml")
    try:
        with open(cfg_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    uptime = round(time.time() - _start_time)
    with _state_lock:
        latest = threat_history[-1] if threat_history else {}
        n_alerts = len(alerts)
    return jsonify({
        "running":            True,
        "uptime_seconds":     uptime,
        "alert_count":        n_alerts,
        "current_label":      latest.get("label", "Unknown"),
        "current_confidence": latest.get("confidence", 0.0),
    })


@app.route("/api/telemetry")
def api_telemetry():
    with _state_lock:
        return jsonify({
            "hpc":     list(hpc_history),
            "file":    list(file_history),
            "network": list(net_history),
        })


@app.route("/api/threat")
def api_threat():
    with _state_lock:
        return jsonify({
            "history": list(threat_history),
            "latest":  threat_history[-1] if threat_history else {},
        })


@app.route("/api/alerts")
def api_alerts():
    with _state_lock:
        return jsonify({"alerts": list(alerts)})


@app.route("/api/config")
def api_config():
    return jsonify(_load_config())


@app.route("/api/model")
def api_model():
    cfg = _load_config()
    mc  = cfg.get("model", {})
    dc  = cfg.get("decision", {})
    fc  = cfg.get("features", {})
    return jsonify({
        "algorithm":       mc.get("algorithm", "lightgbm"),
        "classes":         mc.get("classes", ["Benign", "Suspicious", "Malicious"]),
        "thresholds":      dc.get("thresholds", {"suspicious": 0.60, "high_alert": 0.85}),
        "cooldown_seconds": dc.get("cooldown_seconds", 30),
        "feature_count":   fc.get("vector_size", 23),
        "scaler":          fc.get("scaler", "standard"),
        "lightgbm_params": mc.get("lightgbm", {}),
        "rf_params":       mc.get("random_forest", {}),
        "training":        mc.get("training", {}),
    })


# ─── Entrypoint ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("AI-RIDS API server starting on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
