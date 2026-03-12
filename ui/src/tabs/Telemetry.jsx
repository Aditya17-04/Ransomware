import { useState } from 'react'
import { usePolling } from '../hooks/usePolling'
import { getTelemetry } from '../api/client'
import LiveChart from '../components/LiveChart'
import StatusCard from '../components/StatusCard'
import {
  Cpu, HardDrive, Wifi,
  MemoryStick, FileText, Network,
} from 'lucide-react'

const SUB_TABS = [
  { id: 'hpc',     label: 'HPC',         icon: Cpu     },
  { id: 'file',    label: 'File System',  icon: HardDrive },
  { id: 'network', label: 'Network',      icon: Wifi    },
]

// ── HPC panel ──────────────────────────────────────────────────────────────
function HPCPanel({ hpc }) {
  const latest = hpc.at(-1) ?? {}
  return (
    <div className="space-y-5">
      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { title: 'CPU Total',     value: `${latest.cpu_total_pct?.toFixed(1) ?? 0}%`,     accent: 'cyan'   },
          { title: 'Privileged',    value: `${latest.cpu_privileged_pct?.toFixed(1) ?? 0}%`, accent: 'violet' },
          { title: 'Cache Faults',  value: `${latest.cache_faults_per_sec?.toFixed(0) ?? 0}/s`, accent: 'amber' },
          { title: 'Page Faults',   value: `${latest.page_faults_per_sec?.toFixed(0) ?? 0}/s`,  accent: 'amber' },
          { title: 'Ctx Switches',  value: `${(latest.context_switches_per_sec ?? 0).toLocaleString()}/s`, accent: 'slate' },
          { title: 'Syscalls',      value: `${(latest.syscalls_per_sec ?? 0).toLocaleString()}/s`,         accent: 'slate' },
        ].map(c => (
          <div key={c.title} className="bg-surface-800 rounded-xl border border-surface-700 p-3">
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{c.title}</p>
            <p className={`text-lg font-bold ${
              c.accent === 'cyan'   ? 'text-cyan-400'   :
              c.accent === 'violet' ? 'text-violet-400' :
              c.accent === 'amber'  ? 'text-amber-400'  :
              'text-slate-300'
            }`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Charts row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="CPU Utilisation (%)"
            data={hpc}
            lines={[
              { key: 'cpu_total_pct',      color: '#06b6d4', name: 'Total CPU%'     },
              { key: 'cpu_privileged_pct', color: '#a78bfa', name: 'Privileged%'    },
            ]}
            xKey="ts" height={190} unit="%" yDomain={[0, 100]}
          />
        </div>
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="Memory Pressure"
            data={hpc}
            lines={[
              { key: 'cache_faults_per_sec', color: '#f59e0b', name: 'Cache Faults/s' },
              { key: 'page_faults_per_sec',  color: '#fb923c', name: 'Page Faults/s'  },
            ]}
            xKey="ts" height={190} unit="/s"
          />
        </div>
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="Context Switches / sec"
            data={hpc}
            lines={[{ key: 'context_switches_per_sec', color: '#818cf8', name: 'Ctx Switches/s' }]}
            xKey="ts" height={170}
          />
        </div>
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="System Calls / sec"
            data={hpc}
            lines={[{ key: 'syscalls_per_sec', color: '#34d399', name: 'Syscalls/s' }]}
            xKey="ts" height={170}
          />
        </div>
      </div>

      <div className="bg-surface-800/50 rounded-xl border border-surface-700 p-4 text-xs text-slate-400 leading-relaxed">
        <p className="font-semibold text-slate-300 mb-1">Crypto-jacking / Side-channel Indicators</p>
        <p>• Sustained <span className="text-violet-400">high privileged-time</span> → kernel-level encryption routines running.</p>
        <p>• Spike in <span className="text-amber-400">cache faults</span> → unusual memory-access pattern typical of crypto miners.</p>
        <p>• Elevated <span className="text-cyan-400">syscall rate + high CPU</span> → mass file-encryption syscalls (ransomware signature).</p>
      </div>
    </div>
  )
}

// ── File panel ────────────────────────────────────────────────────────────
function FilePanel({ file }) {
  const latest = file.at(-1) ?? {}
  const entropyColor = (latest.avg_entropy ?? 0) >= 7.2 ? 'text-red-400' : (latest.avg_entropy ?? 0) >= 6.0 ? 'text-amber-400' : 'text-emerald-400'

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { title: 'Events / Window',    value: latest.events_per_window?.toFixed(0) ?? 0, accent: 'cyan'    },
          { title: 'Avg Shannon Entropy',value: latest.avg_entropy?.toFixed(3) ?? 0,       accent: 'amber'   },
          { title: 'Renames',            value: latest.renames?.toFixed(0) ?? 0,           accent: 'violet'  },
          { title: 'Deletions',          value: latest.deletes?.toFixed(0) ?? 0,           accent: 'red'     },
        ].map(c => (
          <div key={c.title} className="bg-surface-800 rounded-xl border border-surface-700 p-3">
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{c.title}</p>
            <p className={`text-2xl font-bold ${
              c.accent === 'cyan'   ? 'text-cyan-400'   :
              c.accent === 'amber'  ? 'text-amber-400'  :
              c.accent === 'violet' ? 'text-violet-400' :
              'text-red-400'
            }`}>{c.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="File Events / Window"
            data={file}
            lines={[{ key: 'events_per_window', color: '#06b6d4', name: 'Events' }]}
            xKey="ts" height={190}
          />
          <p className="text-[10px] text-slate-500 mt-1">Threshold: ≥ 20 events/window → Suspicious</p>
        </div>
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="Shannon Entropy (0–8)"
            data={file}
            lines={[{ key: 'avg_entropy', color: '#f59e0b', name: 'Entropy' }]}
            xKey="ts" height={190} yDomain={[0, 8]}
          />
          <p className="text-[10px] text-slate-500 mt-1">Threshold: ≥ 7.2 → Suspicious. Max possible: 8.0</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="File Renames / Window"
            data={file}
            lines={[{ key: 'renames', color: '#a78bfa', name: 'Renames' }]}
            xKey="ts" height={160}
          />
        </div>
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="File Deletions / Window"
            data={file}
            lines={[{ key: 'deletes', color: '#f87171', name: 'Deletions' }]}
            xKey="ts" height={160}
          />
          <p className="text-[10px] text-slate-500 mt-1">Threshold: ≥ 10 deletions/window → Suspicious</p>
        </div>
      </div>

      <div className="bg-surface-800/50 rounded-xl border border-surface-700 p-4 text-xs text-slate-400 leading-relaxed">
        <p className="font-semibold text-slate-300 mb-1">Ransomware File Indicators</p>
        <p>• <span className="text-amber-400">High entropy</span> (≥ 7.2 bits) after writes → ciphertext replacing plaintext files.</p>
        <p>• <span className="text-violet-400">Mass renames</span> to .enc / .locked / .crypto → known ransomware staging.</p>
        <p>• <span className="text-red-400">Bulk deletions</span> → shadow copy removal or document wiping.</p>
      </div>
    </div>
  )
}

// ── Network panel ─────────────────────────────────────────────────────────
function NetworkPanel({ net }) {
  const latest = net.at(-1) ?? {}
  const mbOut  = ((latest.bytes_out ?? 0) / 1_000_000).toFixed(2)

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-surface-800 rounded-xl border border-surface-700 p-4">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Bytes Out / Window</p>
          <p className={`text-2xl font-bold ${parseFloat(mbOut) >= 5 ? 'text-red-400' : 'text-cyan-400'}`}>
            {mbOut} <span className="text-sm font-normal text-slate-400">MB</span>
          </p>
          <p className="text-[10px] text-slate-500 mt-0.5">Exfil threshold: ≥ 5 MB / window</p>
        </div>
        <div className="bg-surface-800 rounded-xl border border-surface-700 p-4">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Active Connections</p>
          <p className={`text-2xl font-bold ${(latest.connections ?? 0) >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {latest.connections?.toFixed(0) ?? 0}
          </p>
          <p className="text-[10px] text-slate-500 mt-0.5">Beacon detection: 30–300 s periodic reconnects</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="Outbound Bytes / Window"
            data={net.map(p => ({ ...p, mb_out: parseFloat((p.bytes_out / 1_000_000).toFixed(3)) }))}
            lines={[{ key: 'mb_out', color: '#06b6d4', name: 'MB Out' }]}
            xKey="ts" height={220} unit="MB"
          />
          <div className="flex items-center gap-1 mt-1">
            <span className="w-3 h-0.5 bg-red-500/60 rounded" />
            <span className="text-[10px] text-slate-500">Exfiltration threshold: 5 MB</span>
          </div>
        </div>
        <div className="bg-surface-900 border border-surface-700 rounded-xl p-4">
          <LiveChart
            title="Active Connections"
            data={net}
            lines={[{ key: 'connections', color: '#a78bfa', name: 'Connections' }]}
            xKey="ts" height={220}
          />
        </div>
      </div>

      <div className="bg-surface-800/50 rounded-xl border border-surface-700 p-4 text-xs text-slate-400 leading-relaxed">
        <p className="font-semibold text-slate-300 mb-1">C2 Beacon / Exfiltration Indicators</p>
        <p>• <span className="text-cyan-400">Periodic outbound connections</span> at fixed 30–300 s cadence → C2 heartbeat beaconing.</p>
        <p>• <span className="text-red-400">Outbound bytes ≥ 5 MB/window</span> → potential data exfiltration to remote host.</p>
        <p>• Connections to blacklisted ports <span className="text-amber-400">4444, 1337, 31337, 8080</span> → known malware ports.</p>
      </div>
    </div>
  )
}

// ── Main Telemetry tab ─────────────────────────────────────────────────────
export default function Telemetry() {
  const [sub, setSub] = useState('hpc')
  const { data, loading } = usePolling(getTelemetry, 4000)

  const hpc  = data?.hpc     ?? []
  const file = data?.file    ?? []
  const net  = data?.network ?? []

  return (
    <div className="space-y-5">
      {/* Sub-tab bar */}
      <div className="flex gap-2 bg-surface-900 border border-surface-700 rounded-xl p-1.5 w-fit">
        {SUB_TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setSub(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all
              ${sub === id
                ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                : 'text-slate-400 hover:text-white hover:bg-surface-800'
              }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="text-slate-500 text-sm text-center py-12">
          <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          Connecting to telemetry stream…
        </div>
      )}

      {!loading && sub === 'hpc'     && <HPCPanel     hpc={hpc}   />}
      {!loading && sub === 'file'    && <FilePanel    file={file}  />}
      {!loading && sub === 'network' && <NetworkPanel net={net}    />}
    </div>
  )
}
