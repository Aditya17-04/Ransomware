import { usePolling }  from '../hooks/usePolling'
import { getStatus, getThreat, getAlerts } from '../api/client'
import StatusCard  from '../components/StatusCard'
import ThreatGauge from '../components/ThreatGauge'
import AlertBadge  from '../components/AlertBadge'
import LiveChart   from '../components/LiveChart'
import {
  Shield, AlertTriangle, Clock,
  Zap, Server, TrendingUp,
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
