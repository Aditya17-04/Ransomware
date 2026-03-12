import { useState, useMemo } from 'react'
import { usePolling } from '../hooks/usePolling'
import { getAlerts }  from '../api/client'
import AlertBadge from '../components/AlertBadge'
import { AlertTriangle, Filter, Trash2, CheckCircle, Shield } from 'lucide-react'

function fmtTs(ms) {
  return new Date(ms).toLocaleString([], {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function ActionChips({ actions }) {
  const map = {
    kill_process:       { label: 'Kill PID',    color: 'text-red-400    bg-red-500/10    border-red-500/30'     },
    network_isolation:  { label: 'Net Block',   color: 'text-amber-400  bg-amber-500/10  border-amber-500/30'   },
    file_protection:    { label: 'File Lock',   color: 'text-violet-400 bg-violet-500/10 border-violet-500/30'  },
    logged:             { label: 'Logged',      color: 'text-slate-400  bg-slate-500/10  border-slate-500/30'   },
  }
  return (
    <div className="flex flex-wrap gap-1">
      {(actions ?? []).map(a => {
        const m = map[a] ?? { label: a, color: 'text-slate-400 bg-slate-500/10 border-slate-500/30' }
        return (
          <span key={a} className={`text-[10px] border rounded px-1.5 py-0.5 font-medium ${m.color}`}>
            {m.label}
          </span>
        )
      })}
    </div>
  )
}

const FILTER_OPTS = ['All', 'HighAlert', 'Suspicious']

export default function Alerts() {
  const [filter, setFilter] = useState('All')
  const { data, loading } = usePolling(getAlerts, 4000)

  const all = data?.alerts ?? []

  const haStats = all.filter(a => a.level === 'HighAlert').length
  const susStats = all.filter(a => a.level === 'Suspicious').length

  const filtered = useMemo(() => {
    if (filter === 'All') return all
    return all.filter(a => a.level === filter)
  }, [all, filter])

  return (
    <div className="space-y-5">

      {/* Summary row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="glass border border-white/[0.06] rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-500/10">
            <Filter className="w-5 h-5 text-slate-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider">Total</p>
            <p className="text-2xl font-bold text-white">{all.length}</p>
          </div>
        </div>
        <div className="glass border border-red-500/20 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-500/10">
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider">High Alerts</p>
            <p className="text-2xl font-bold text-red-400">{haStats}</p>
          </div>
        </div>
        <div className="glass border border-amber-500/20 rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-amber-500/10">
            <Shield className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider">Suspicious</p>
            <p className="text-2xl font-bold text-amber-400">{susStats}</p>
          </div>
        </div>
      </div>

      {/* Table card */}
      <div className="glass border border-white/[0.06] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.06]">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span className="text-sm font-semibold text-slate-300">Alert Log</span>
          </div>
          {/* Filter buttons */}
          <div className="flex gap-1 bg-navy-800 rounded-lg p-1">
            {FILTER_OPTS.map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-all
                  ${filter === f
                    ? 'bg-brand-600 text-white'
                    : 'text-slate-400 hover:text-white'}`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="p-10 text-center text-slate-500">
            <div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
            Loading alerts…
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-slate-500">
            <CheckCircle className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No alerts matching filter "{filter}".</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[700px]">
              <thead>
                <tr className="text-[10px] font-semibold uppercase tracking-widest text-slate-500 bg-navy-800/40">
                  <th className="py-2.5 px-4 text-left">#</th>
                  <th className="py-2.5 px-4 text-left">Timestamp</th>
                  <th className="py-2.5 px-4 text-left">Level</th>
                  <th className="py-2.5 px-4 text-left">Confidence</th>
                  <th className="py-2.5 px-4 text-left">PID</th>
                  <th className="py-2.5 px-4 text-left">Remote Host</th>
                  <th className="py-2.5 px-4 text-left">Actions Taken</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a, idx) => (
                  <tr
                    key={a.id}
                    className={`border-b border-white/[0.06] hover:bg-navy-800/40 transition-colors
                      ${a.level === 'HighAlert' ? 'bg-red-950/10' : ''}`}
                  >
                    <td className="py-2.5 px-4 text-xs text-slate-500 font-mono">{a.id}</td>
                    <td className="py-2.5 px-4 text-xs text-slate-400 font-mono whitespace-nowrap">{fmtTs(a.ts)}</td>
                    <td className="py-2.5 px-4"><AlertBadge level={a.level} /></td>
                    <td className="py-2.5 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-navy-700 rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${(a.confidence * 100).toFixed(0)}%`,
                              background: a.confidence >= 0.85 ? '#ef4444' : a.confidence >= 0.60 ? '#f59e0b' : '#22c55e'
                            }}
                          />
                        </div>
                        <span className={`text-xs font-bold font-mono ${
                          a.confidence >= 0.85 ? 'text-red-400'
                          : a.confidence >= 0.60 ? 'text-amber-400'
                          : 'text-emerald-400'
                        }`}>
                          {(a.confidence * 100).toFixed(1)}%
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-xs font-mono text-slate-300">{a.pid}</td>
                    <td className="py-2.5 px-4 text-xs font-mono text-slate-300 whitespace-nowrap">
                      {a.remote_ip}:{a.remote_port}
                    </td>
                    <td className="py-2.5 px-4"><ActionChips actions={a.actions_taken} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  )
}
