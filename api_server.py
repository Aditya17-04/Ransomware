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
from flask import Flask, jsonify, request
from flask_cors import CORS

# ─── Supabase (optional) ──────────────────────────────────────────────────────
# Set SUPABASE_URL and SUPABASE_KEY in a .env file or environment variables.
# Alerts will persist across restarts when configured; falls back to in-memory.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from supabase import create_client as _sb_factory
    _SUPABASE_URL = os.getenv("SUPABASE_URL", "")
    _SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
    _sb = _sb_factory(_SUPABASE_URL, _SUPABASE_KEY) if (_SUPABASE_URL and _SUPABASE_KEY) else None
except Exception:
    _sb = None

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


# ─── Supabase helpers ────────────────────────────────────────────────────────

def _sb_insert(alert: dict) -> None:
    """Persist one alert row to Supabase (called outside _state_lock)."""
    if _sb is None:
        return
    try:
        _sb.table("alerts").insert({
            "ts":           alert["ts"],
            "level":        alert["level"],
            "label":        alert["label"],
            "confidence":   alert["confidence"],
            "pid":          alert.get("pid"),
            "remote_ip":    alert.get("remote_ip"),
            "remote_port":  alert.get("remote_port"),
            "actions_taken": alert.get("actions_taken", []),
        }).execute()
    except Exception as exc:
        print(f"[Supabase] insert failed: {exc}")


def _sb_load_recent(limit: int = 200) -> None:
    """On startup — back-fill the in-memory deque from Supabase."""
    if _sb is None:
        return
    try:
        resp = (
            _sb.table("alerts")
            .select("*")
            .order("ts", desc=True)
            .limit(limit)
            .execute()
        )
        rows = list(reversed(resp.data or []))   # oldest-first
        global _alert_id
        with _state_lock:
            for row in rows:
                entry = {
                    "id":           row["id"],
                    "ts":           row["ts"],
                    "level":        row["level"],
                    "label":        row["label"],
                    "confidence":   row["confidence"],
                    "pid":          row.get("pid"),
                    "remote_ip":    row.get("remote_ip"),
                    "remote_port":  row.get("remote_port"),
                    "actions_taken": row.get("actions_taken", []),
                }
                alerts.appendleft(entry)
                _alert_id = max(_alert_id, row["id"])
        print(f"[Supabase] loaded {len(rows)} historical alerts.")
    except Exception as exc:
        print(f"[Supabase] startup load failed: {exc}")


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

            # Emit alerts — build dict inside lock, persist to DB outside
            _new_alert = None
            if label == "Malicious" and conf >= 0.85 and random.random() < 0.35:
                _alert_id += 1
                _new_alert = {
                    "id":          _alert_id,
                    "ts":          ts,
                    "level":       "HighAlert",
                    "label":       "Malicious",
                    "confidence":  round(conf, 4),
                    "pid":         random.randint(1000, 65535),
                    "remote_ip":   f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    "remote_port": random.choice([4444, 1337, 31337, 6666, 8080]),
                    "actions_taken": ["kill_process", "network_isolation", "file_protection"],
                }
                alerts.appendleft(_new_alert)
            elif label == "Suspicious" and conf >= 0.60 and random.random() < 0.25:
                _alert_id += 1
                _new_alert = {
                    "id":          _alert_id,
                    "ts":          ts,
                    "level":       "Suspicious",
                    "label":       "Suspicious",
                    "confidence":  round(conf, 4),
                    "pid":         random.randint(1000, 65535),
                    "remote_ip":   f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                    "remote_port": random.choice([443, 8080, 9999, 3389]),
                    "actions_taken": ["logged"],
                }
                alerts.appendleft(_new_alert)

        # Persist to Supabase OUTSIDE the state lock (network I/O)
        if _new_alert:
            _sb_insert(_new_alert)

        # Advance phase
        phase_tick += 1
        if phase_tick >= phase_len:
            phase_tick = 0
            phase_idx  = (phase_idx + 1) % len(phases)

        time.sleep(5)


_sim_thread = threading.Thread(target=_simulate, daemon=True, name="sim")
_sim_thread.start()
_sb_load_recent()   # back-fill from Supabase on startup


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
    page  = max(1, int(request.args.get("page",  1)))
    limit = min(200, max(1, int(request.args.get("limit", 50))))
    with _state_lock:
        all_alerts = list(alerts)
    total  = len(all_alerts)
    start  = (page - 1) * limit
    return jsonify({
        "alerts": all_alerts[start : start + limit],
        "total":  total,
        "page":   page,
        "limit":  limit,
        "pages":  max(1, math.ceil(total / limit)),
    })


@app.route("/api/alerts/clear", methods=["DELETE"])
def api_alerts_clear():
    """Clear all alerts from memory and Supabase."""
    with _state_lock:
        alerts.clear()
    db_err = None
    if _sb is not None:
        try:
            _sb.table("alerts").delete().neq("id", 0).execute()
        except Exception as exc:
            db_err = str(exc)
    resp = {"cleared": True}
    if db_err:
        resp["db_error"] = db_err
    return jsonify(resp)


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
