import { usePolling } from '../hooks/usePolling'
import { getModel }   from '../api/client'
import { BrainCircuit, Sliders, Layers, Database, BarChart2 } from 'lucide-react'

const FEATURE_GROUPS = [
  {
    name: 'HPC Features',
    color: '#06b6d4',
    count: 8,
    dims: '[0–7]',
    items: [
      'CPU Total %', 'CPU Privileged %', 'Interrupts/sec',
      'Cache Faults/sec', 'Page Faults/sec', 'Pages/sec',
      'Context Switches/sec', 'Syscalls/sec',
    ],
  },
  {
    name: 'File Features',
    color: '#f59e0b',
    count: 7,
    dims: '[8–14]',
    items: [
      'Events/window', 'Avg Shannon Entropy', 'High-Entropy Count',
      'Rename Count', 'Delete Count', 'Suspicious Ext Flag', 'Entropy Std Dev',
    ],
  },
  {
    name: 'Network Features',
    color: '#a78bfa',
    count: 8,
    dims: '[15–22]',
    items: [
      'Bytes In', 'Bytes Out', 'Packets In', 'Packets Out',
      'New Connections', 'Beacon Score', 'Unique Remote IPs', 'C2 Port Flag',
    ],
  },
]

function ThresholdBar({ label, value, color }) {
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between items-center">
        <span className="text-xs text-slate-400">{label}</span>
        <span className="text-xs font-bold font-mono" style={{ color }}>
          {(value * 100).toFixed(0)}%
        </span>
      </div>
      <div className="h-3 bg-navy-700 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${value * 100}%`, background: color }}
        />
      </div>
    </div>
  )
}

function ParamTable({ params }) {
  return (
    <table className="w-full text-xs">
      <tbody>
        {Object.entries(params ?? {}).map(([k, v]) => (
          <tr key={k} className="border-b border-white/[0.06]">
            <td className="py-1.5 pr-4 text-slate-400 font-mono">{k}</td>
            <td className="py-1.5 text-slate-200 font-mono text-right">{String(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export default function ModelInfo() {
  const { data, loading } = usePolling(getModel, 30_000)

  if (loading) {
    return (
      <div className="text-center py-20 text-slate-500">
        <div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        Loading model metadata…
      </div>
    )
  }

  const algo        = data?.algorithm ?? 'lightgbm'
  const thresholds  = data?.thresholds  ?? {}
  const params      = algo === 'lightgbm' ? data?.lightgbm_params : data?.rf_params
  const training    = data?.training ?? {}
  const classes     = data?.classes ?? ['Benign', 'Suspicious', 'Malicious']
  const featCount   = data?.feature_count ?? 23
  const cooldown    = data?.cooldown_seconds ?? 30

  return (
    <div className="space-y-5">

      {/* Header cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass border border-brand-500/30 rounded-xl p-4">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Algorithm</p>
          <p className="text-lg font-bold text-brand-400 capitalize">{algo.replace('_', ' ')}</p>
        </div>
        <div className="glass border border-white/[0.06] rounded-xl p-4">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Feature Vector</p>
          <p className="text-lg font-bold text-white">{featCount} <span className="text-sm font-normal text-slate-400">dims</span></p>
        </div>
        <div className="glass border border-white/[0.06] rounded-xl p-4">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Output Classes</p>
          <p className="text-lg font-bold text-white">{classes.length}</p>
        </div>
        <div className="glass border border-white/[0.06] rounded-xl p-4">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Alert Cooldown</p>
          <p className="text-lg font-bold text-white">{cooldown} <span className="text-sm font-normal text-slate-400">sec</span></p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* Decision thresholds */}
        <div className="glass border border-white/[0.06] rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2 mb-1">
            <Sliders className="w-4 h-4 text-brand-400" />
            <span className="text-sm font-semibold text-slate-300">Decision Thresholds</span>
          </div>
          <ThresholdBar label="Suspicious Threshold"  value={thresholds.suspicious ?? 0.60} color="#f59e0b" />
          <ThresholdBar label="High Alert Threshold"  value={thresholds.high_alert  ?? 0.85} color="#ef4444" />

          <div className="pt-2 space-y-2 text-xs text-slate-400">
            <div className="flex items-start gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mt-1 shrink-0" />
              <p><span className="text-emerald-400 font-medium">Benign</span>: confidence &lt; {((thresholds.suspicious ?? 0.60) * 100).toFixed(0)}% → logged only.</p>
            </div>
            <div className="flex items-start gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400 mt-1 shrink-0" />
              <p><span className="text-amber-400 font-medium">Suspicious</span>: {((thresholds.suspicious ?? 0.60) * 100).toFixed(0)}% ≤ conf &lt; {((thresholds.high_alert ?? 0.85) * 100).toFixed(0)}% → alert raised.</p>
            </div>
            <div className="flex items-start gap-2">
              <span className="w-2 h-2 rounded-full bg-red-400 mt-1 shrink-0" />
              <p><span className="text-red-400 font-medium">High Alert</span>: conf ≥ {((thresholds.high_alert ?? 0.85) * 100).toFixed(0)}% → full response chain triggered.</p>
            </div>
          </div>
        </div>

        {/* Response chain */}
        <div className="glass border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <BrainCircuit className="w-4 h-4 text-brand-400" />
            <span className="text-sm font-semibold text-slate-300">High Alert Response Chain</span>
          </div>
          <ol className="relative border-l border-white/[0.06] ml-2 space-y-4">
            {[
              { step: '1', color: '#ef4444', title: 'Kill Process', desc: 'Terminate the offending PID immediately via taskkill /F.' },
              { step: '2', color: '#f59e0b', title: 'Network Isolation', desc: 'Block remote IP/port via Windows Firewall netsh rule. Auto-expires after 1h.' },
              { step: '3', color: '#a78bfa', title: 'File Protection', desc: 'Revoke write permissions on critical dirs + trigger Volume Shadow Copy backup.' },
            ].map(({ step, color, title, desc }) => (
              <li key={step} className="ml-5">
                <span
                  className="absolute -left-2 flex w-4 h-4 items-center justify-center rounded-full text-[9px] font-bold text-white"
                  style={{ background: color }}
                >
                  {step}
                </span>
                <p className="text-xs font-semibold" style={{ color }}>{title}</p>
                <p className="text-[11px] text-slate-400 mt-0.5">{desc}</p>
              </li>
            ))}
          </ol>
        </div>
      </div>

      {/* Feature vector breakdown */}
      <div className="glass border border-white/[0.06] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Layers className="w-4 h-4 text-brand-400" />
          <span className="text-sm font-semibold text-slate-300">Feature Vector Layout ({featCount} dims)</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {FEATURE_GROUPS.map(g => (
            <div key={g.name} className="rounded-lg border bg-navy-800/40 overflow-hidden"
              style={{ borderColor: `${g.color}33` }}>
              <div className="px-3 py-2 flex items-center justify-between"
                style={{ background: `${g.color}15`, borderBottom: `1px solid ${g.color}33` }}>
                <span className="text-xs font-semibold" style={{ color: g.color }}>{g.name}</span>
                <span className="text-[10px] font-mono text-slate-400">{g.dims} ({g.count} features)</span>
              </div>
              <ul className="px-3 py-2 space-y-0.5">
                {g.items.map((item, i) => (
                  <li key={i} className="flex items-center gap-2 text-[11px] text-slate-400">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: g.color }} />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Hyperparameters */}
      <div className="glass border border-white/[0.06] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <BarChart2 className="w-4 h-4 text-brand-400" />
          <span className="text-sm font-semibold text-slate-300 capitalize">
            {algo.replace('_', ' ')} Hyperparameters
          </span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Model Params</p>
            <ParamTable params={params} />
          </div>
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Training Config</p>
            <ParamTable params={training} />
          </div>
        </div>
      </div>

    </div>
  )
}
