import { usePolling }  from '../hooks/usePolling'
import { getStatus, getThreat, getAlerts } from '../api/client'
import StatusCard  from '../components/StatusCard'
import ThreatGauge from '../components/ThreatGauge'
import AlertBadge  from '../components/AlertBadge'
import LiveChart   from '../components/LiveChart'
import {
  Shield, AlertTriangle, Clock, Activity,
  Zap, Server, TrendingUp, Cpu, HardDrive, Globe,
} from 'lucide-react'

function fmtUptime(s) {
  if (s == null) return '—'
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`
}

function fmtTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

/* Animated SVG network background — mimics the Resilio globe arcs */
function NetworkBg() {
  const nodes = [
    { cx: '18%',  cy: '30%', r: 4,   delay: '0s'    },
    { cx: '45%',  cy: '55%', r: 5.5, delay: '0.8s'  },
    { cx: '62%',  cy: '25%', r: 3.5, delay: '1.5s'  },
    { cx: '78%',  cy: '60%', r: 4,   delay: '0.4s'  },
    { cx: '88%',  cy: '35%', r: 3,   delay: '2s'    },
    { cx: '30%',  cy: '75%', r: 3,   delay: '1.2s'  },
    { cx: '55%',  cy: '80%', r: 4.5, delay: '0.6s'  },
  ]
  const arcs = [
    'M 18 30 Q 35 10 45 55',
    'M 45 55 Q 55 35 62 25',
    'M 62 25 Q 72 42 78 60',
    'M 78 60 Q 83 47 88 35',
    'M 45 55 Q 50 70 55 80',
    'M 18 30 Q 24 55 30 75',
    'M 30 75 Q 42 77 55 80',
    'M 62 25 Q 75 28 88 35',
  ]
  return (
    <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 100 100" preserveAspectRatio="none">
      <defs>
        <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#6366f1" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.1" />
        </linearGradient>
        <filter id="blur1">
          <feGaussianBlur stdDeviation="0.3" />
        </filter>
      </defs>
      {arcs.map((d, i) => (
        <path key={i} d={d} fill="none" stroke="url(#arcGrad)" strokeWidth="0.3" filter="url(#blur1)" />
      ))}
      {nodes.map((n, i) => (
        <g key={i}>
          <circle cx={n.cx} cy={n.cy} r={n.r * 1.8} fill="#6366f1" opacity="0.08" />
          <circle cx={n.cx} cy={n.cy} r={n.r * 0.6} fill="#818cf8" opacity="0.9">
            <animate attributeName="r" values={`${n.r * 0.5};${n.r * 1};${n.r * 0.5}`} dur="2.5s" begin={n.delay} repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.9;0.4;0.9" dur="2.5s" begin={n.delay} repeatCount="indefinite" />
          </circle>
          {i === 1 && (
            <circle cx={n.cx} cy={n.cy} r="1" fill="#fbbf24">
              <animate attributeName="r" values="1;2.5;1" dur="1.5s" repeatCount="indefinite" />
            </circle>
          )}
        </g>
      ))}
    </svg>
  )
}

const FEATURE_CARDS = [
  { icon: Cpu,      label: 'HPC Monitor',       sub: 'Hardware performance counters track CPU encryption spikes' },
  { icon: HardDrive,label: 'File System Monitor',sub: 'Watches entropy, renames and mass-delete patterns in real time' },
  { icon: Globe,    label: 'Network Monitor',    sub: 'C2 beacon detection, exfiltration alerts, connection fan-out' },
]

function RecentAlertRow({ alert }) {
  const isHigh = alert.level === 'HighAlert'
  return (
    <tr className={`border-b border-white/[0.04] hover:bg-brand-500/5 transition-colors ${isHigh ? 'bg-risk-high/5' : ''}`}>
      <td className="py-2.5 px-4 text-xs font-mono text-slate-400 whitespace-nowrap">{fmtTime(alert.ts)}</td>
      <td className="py-2.5 px-4"><AlertBadge level={alert.level} size="xs" /></td>
      <td className="py-2.5 px-4 text-xs text-slate-300 font-mono">{alert.pid ?? '—'}</td>
      <td className="py-2.5 px-4 text-xs text-slate-300 font-mono whitespace-nowrap">{alert.remote_ip}:{alert.remote_port}</td>
      <td className="py-2.5 px-4">
        <span className={`text-xs font-bold ${alert.confidence >= 0.85 ? 'text-risk-high' : alert.confidence >= 0.60 ? 'text-risk-medium' : 'text-risk-low'}`}>
          {(alert.confidence * 100).toFixed(1)}%
        </span>
      </td>
    </tr>
  )
}

export default function Dashboard() {
  const { data: status,  loading: sLoad } = usePolling(getStatus,  4000)
  const { data: threat,  loading: tLoad  } = usePolling(getThreat,  3000)
  const { data: alertsD, loading: aLoad  } = usePolling(getAlerts,  5000)

  const latest       = threat?.latest ?? {}
  const confidence   = latest?.confidence ?? 0
  const history      = (threat?.history ?? []).slice(-40)
  const recentAlerts = (alertsD?.alerts ?? []).slice(0, 8)

  const accentForLabel = l => l === 'Malicious' ? 'red' : l === 'Suspicious' ? 'amber' : 'emerald'

  return (
    <div className="space-y-6 animate-fade-in">

      {/* ── Hero banner ────────────────────────────────────────────────── */}
      <div className="relative rounded-2xl overflow-hidden min-h-[220px] flex items-center"
           style={{ background: 'linear-gradient(135deg, #070f1f 0%, #0c1628 60%, #0f1c38 100%)' }}>
        <NetworkBg />
        {/* Glow blob */}
        <div className="absolute right-0 top-0 w-96 h-96 rounded-full opacity-20 pointer-events-none"
             style={{ background: 'radial-gradient(circle, #4f46e5 0%, transparent 70%)', transform: 'translate(30%, -30%)' }} />

        <div className="relative z-10 px-8 py-8 flex flex-col sm:flex-row items-start sm:items-center gap-8 w-full">
          {/* Left: title + feature list */}
          <div className="flex-1">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-brand-500/30 bg-brand-500/10 text-xs text-brand-400 font-semibold tracking-wider mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse-fast" />
              LIVE THREAT INTELLIGENCE
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white leading-tight mb-1">
              AI-Powered
            </h1>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-gradient leading-tight mb-4">
              Ransomware Detection
            </h1>
            <p className="text-slate-400 text-sm max-w-md mb-5">
              Predict ransomware attacks before encryption completes — monitoring CPU, filesystem, and network in real time.
            </p>
            <div className="flex flex-wrap gap-2">
              <span className="badge-low px-3 py-1 rounded-full text-xs font-semibold">● Low Risk</span>
              <span className="badge-medium px-3 py-1 rounded-full text-xs font-semibold">● Medium Risk</span>
              <span className="badge-high px-3 py-1 rounded-full text-xs font-semibold">● High Risk</span>
            </div>
          </div>

          {/* Right: feature cards */}
          <div className="flex flex-col gap-3 min-w-[260px] w-full sm:w-auto">
            {FEATURE_CARDS.map(({ icon: Icon, label, sub }) => (
              <div key={label} className="glass-light rounded-xl px-4 py-3 flex items-center gap-3 hover:border-brand-500/30 transition-all">
                <div className="p-2 rounded-lg bg-brand-500/15 shrink-0">
                  <Icon className="w-4 h-4 text-brand-400" strokeWidth={1.75} />
                </div>
                <div>
                  <p className="text-sm font-semibold text-white">{label}</p>
                  <p className="text-xs text-slate-500">{sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── KPI cards ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatusCard title="Threat Level"  value={latest?.label ?? 'Unknown'} sub={`Confidence: ${(confidence*100).toFixed(1)}%`} icon={Shield}        accent={accentForLabel(latest?.label)} loading={tLoad} />
        <StatusCard title="Total Alerts"  value={status?.alert_count ?? 0}   sub="Since startup"                                  icon={AlertTriangle}  accent="amber"  loading={sLoad} />
        <StatusCard title="System Uptime" value={fmtUptime(status?.uptime_seconds)} sub="Detection daemon"                        icon={Clock}          accent="cyan"   loading={sLoad} />
        <StatusCard title="Pipeline"      value="3 Layers"                   sub="HPC · File · Network"                           icon={Server}         accent="violet" loading={false} />
      </div>

      {/* ── Gauge + Confidence timeline ────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">

        <div className="lg:col-span-2 glass rounded-xl border border-brand-500/10 p-5 flex flex-col items-center">
          <div className="flex items-center gap-2 self-start mb-3">
            <Zap className="w-4 h-4 text-brand-400" />
            <span className="text-sm font-semibold text-slate-200">Threat Confidence</span>
          </div>
          <ThreatGauge confidence={confidence} />

          <div className="w-full mt-4 space-y-2.5">
            {[
              { label: 'Benign',     color: '#22c55e', key: 'Benign'     },
              { label: 'Suspicious', color: '#f59e0b', key: 'Suspicious' },
              { label: 'Malicious',  color: '#ef4444', key: 'Malicious'  },
            ].map(({ label, color, key }) => {
              const pct = ((latest?.probabilities?.[key] ?? 0) * 100).toFixed(1)
              return (
                <div key={key} className="flex items-center gap-2">
                  <span className="text-[11px] text-slate-500 w-20 shrink-0">{label}</span>
                  <div className="flex-1 h-1.5 bg-navy-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-700"
                         style={{ width: `${pct}%`, background: color }} />
                  </div>
                  <span className="text-[11px] font-mono text-slate-400 w-10 text-right">{pct}%</span>
                </div>
              )
            })}
          </div>
        </div>

        <div className="lg:col-span-3 glass rounded-xl border border-brand-500/10 p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-brand-400" />
            <span className="text-sm font-semibold text-slate-200">Confidence Timeline</span>
          </div>
          <LiveChart
            data={history}
            lines={[{ key: 'confidence', color: '#818cf8', name: 'Confidence' }]}
            xKey="ts" height={210} yDomain={[0, 1]}
          />
          <div className="flex gap-4 mt-2">
            {[{ label: 'Suspicious ≥ 0.60', color: '#f59e0b' }, { label: 'High Alert ≥ 0.85', color: '#ef4444' }].map(({ label, color }) => (
              <div key={label} className="flex items-center gap-1">
                <span className="w-3 h-0.5 rounded" style={{ background: color }} />
                <span className="text-[10px] text-slate-500">{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Recent Alerts ──────────────────────────────────────────────── */}
      <div className="glass rounded-xl border border-brand-500/10 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.05]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-risk-medium" />
            <span className="text-sm font-semibold text-white">Recent Alerts</span>
          </div>
          <span className="text-xs text-slate-500">Last 8 events</span>
        </div>
        {aLoad ? (
          <div className="p-6 text-center text-slate-500 text-sm">Loading alerts…</div>
        ) : recentAlerts.length === 0 ? (
          <div className="p-8 text-center">
            <Activity className="w-8 h-8 mx-auto mb-2 text-slate-600" />
            <p className="text-slate-500 text-sm">No alerts yet — system is monitoring.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[480px]">
              <thead>
                <tr className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest border-b border-white/[0.04]">
                  <th className="py-2.5 px-4 text-left">Time</th>
                  <th className="py-2.5 px-4 text-left">Level</th>
                  <th className="py-2.5 px-4 text-left">PID</th>
                  <th className="py-2.5 px-4 text-left">Remote</th>
                  <th className="py-2.5 px-4 text-left">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map(a => <RecentAlertRow key={a.id} alert={a} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  )
}
