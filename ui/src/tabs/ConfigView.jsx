import { useState } from 'react'
import { usePolling }  from '../hooks/usePolling'
import { getConfig }   from '../api/client'
import { Settings, ChevronRight, ChevronDown, Copy, Check } from 'lucide-react'

/** Recursively render a config section as an expandable tree. */
function ConfigNode({ label, value, depth = 0 }) {
  const [open, setOpen] = useState(depth < 2)
  const isObj   = value !== null && typeof value === 'object' && !Array.isArray(value)
  const isArr   = Array.isArray(value)
  const indent  = depth * 16

  if (isObj) {
    return (
      <div style={{ marginLeft: depth > 0 ? indent : 0 }}>
        <button
          onClick={() => setOpen(o => !o)}
          className="flex items-center gap-1 text-xs font-semibold text-slate-300 hover:text-white py-0.5 group w-full text-left"
        >
          {open
            ? <ChevronDown className="w-3 h-3 text-cyan-500" />
            : <ChevronRight className="w-3 h-3 text-cyan-500" />}
          <span className="text-cyan-400">{label}</span>
          <span className="text-slate-600 ml-1">{`{${Object.keys(value).length}}`}</span>
        </button>
        {open && (
          <div className="border-l border-surface-600 ml-2 pl-3 mt-0.5 space-y-0.5">
            {Object.entries(value).map(([k, v]) => (
              <ConfigNode key={k} label={k} value={v} depth={depth + 1} />
            ))}
          </div>
        )}
      </div>
    )
  }

  if (isArr) {
    return (
      <div style={{ marginLeft: depth > 0 ? indent : 0 }}>
        <button
          onClick={() => setOpen(o => !o)}
          className="flex items-center gap-1 text-xs py-0.5 w-full text-left group"
        >
          {open
            ? <ChevronDown className="w-3 h-3 text-slate-500" />
            : <ChevronRight className="w-3 h-3 text-slate-500" />}
          <span className="text-amber-400 font-medium">{label}</span>
          <span className="text-slate-500 ml-1">[{value.length}]</span>
        </button>
        {open && (
          <div className="border-l border-surface-600 ml-2 pl-3 mt-0.5 space-y-0.5">
            {value.map((v, i) => (
              <ConfigNode key={i} label={String(i)} value={v} depth={depth + 1} />
            ))}
          </div>
        )}
      </div>
    )
  }

  // Primitive value
  const valColor =
    typeof value === 'boolean'
      ? value ? 'text-emerald-400' : 'text-red-400'
      : typeof value === 'number'
      ? 'text-violet-300'
      : value === null
      ? 'text-slate-500'
      : 'text-slate-200'

  return (
    <div
      className="flex items-baseline gap-2 text-xs py-0.5"
      style={{ marginLeft: depth > 0 ? indent : 0 }}
    >
      <span className="text-amber-400 font-medium shrink-0">{label}:</span>
      <span className={`font-mono ${valColor}`}>
        {value === null ? 'null' : String(value)}
      </span>
    </div>
  )
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {/* clipboard unavailable */}
  }

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors px-2.5 py-1.5 rounded-md hover:bg-surface-700"
    >
      {copied
        ? <><Check className="w-3.5 h-3.5 text-emerald-400" /> Copied</>
        : <><Copy className="w-3.5 h-3.5" /> Copy YAML</>
      }
    </button>
  )
}

const SECTION_LABELS = {
  system:    'System',
  telemetry: 'Telemetry Layer',
  features:  'Feature Engineering',
  model:     'AI Detection Model',
  decision:  'Decision Engine',
  response:  'Response Actions',
}

export default function ConfigView() {
  const { data, loading } = usePolling(getConfig, 60_000)
  const [rawYaml, setRawYaml] = useState('')

  // Build YAML string for copy (simple serialization)
  const yamlStr = data ? JSON.stringify(data, null, 2) : ''

  if (loading) {
    return (
      <div className="text-center py-20 text-slate-500">
        <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        Loading configuration…
      </div>
    )
  }

  const sections = Object.entries(data ?? {})

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white">config.yaml</h2>
          <span className="text-xs text-slate-500 font-mono">config/config.yaml</span>
        </div>
        <CopyButton text={yamlStr} />
      </div>

      {/* Section cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {sections.map(([sectionKey, sectionVal]) => (
          <div key={sectionKey} className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-surface-700 bg-surface-800/60 flex items-center gap-2">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
                {SECTION_LABELS[sectionKey] ?? sectionKey}
              </span>
            </div>
            <div className="px-4 py-3 font-mono text-[12px] leading-relaxed max-h-72 overflow-y-auto">
              {typeof sectionVal === 'object' && sectionVal !== null
                ? Object.entries(sectionVal).map(([k, v]) => (
                    <ConfigNode key={k} label={k} value={v} depth={0} />
                  ))
                : <span className="text-slate-300">{String(sectionVal)}</span>
              }
            </div>
          </div>
        ))}
      </div>

      {/* Raw JSON view */}
      <details className="bg-surface-900 border border-surface-700 rounded-xl overflow-hidden">
        <summary className="px-4 py-3 text-sm font-semibold text-slate-400 hover:text-white cursor-pointer select-none">
          Raw JSON (API response)
        </summary>
        <pre className="px-4 pb-4 pt-2 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-96 leading-relaxed">
          {JSON.stringify(data, null, 2)}
        </pre>
      </details>

    </div>
  )
}
