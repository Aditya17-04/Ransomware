/**
 * StatusCard — a compact metric card with icon, value, label, and optional trend.
 *
 * Props:
 *   title    : string
 *   value    : string | number
 *   sub      : string (secondary text below value)
 *   icon     : Lucide component
 *   accent   : 'cyan' | 'emerald' | 'amber' | 'red' | 'violet' | 'slate'
 *   loading  : bool
 */

const ACCENT = {
  cyan:    { ring: 'border-cyan-500/30',    icon: 'text-cyan-400',    bg: 'bg-cyan-500/10'    },
  emerald: { ring: 'border-emerald-500/30', icon: 'text-emerald-400', bg: 'bg-emerald-500/10' },
  amber:   { ring: 'border-amber-500/30',   icon: 'text-amber-400',   bg: 'bg-amber-500/10'   },
  red:     { ring: 'border-red-500/30',     icon: 'text-red-400',     bg: 'bg-red-500/10'     },
  violet:  { ring: 'border-violet-500/30',  icon: 'text-violet-400',  bg: 'bg-violet-500/10'  },
  slate:   { ring: 'border-slate-600',      icon: 'text-slate-400',   bg: 'bg-slate-700/30'   },
}

export default function StatusCard({ title, value, sub, icon: Icon, accent = 'cyan', loading = false }) {
  const a = ACCENT[accent] ?? ACCENT.slate

  return (
    <div className={`bg-surface-800 rounded-xl border ${a.ring} p-4 flex items-start gap-3`}>
      {Icon && (
        <div className={`p-2 rounded-lg ${a.bg} shrink-0 mt-0.5`}>
          <Icon className={`w-5 h-5 ${a.icon}`} strokeWidth={1.75} />
        </div>
      )}
      <div className="min-w-0">
        <p className="text-xs text-slate-500 font-medium uppercase tracking-wider mb-0.5">{title}</p>
        {loading
          ? <div className="h-7 w-24 bg-surface-700 rounded animate-pulse mt-1" />
          : <p className="text-2xl font-bold text-white leading-tight">{value ?? '—'}</p>
        }
        {sub && <p className="text-xs text-slate-500 mt-0.5 truncate">{sub}</p>}
      </div>
    </div>
  )
}
