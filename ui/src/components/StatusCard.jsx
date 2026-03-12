const ACCENT = {
  cyan:    { border: 'border-accent-cyan/20',    icon: 'text-accent-cyan',    bg: 'bg-accent-cyan/10',    glow: 'shadow-[0_0_20px_rgba(34,211,238,0.15)]'  },
  emerald: { border: 'border-risk-low/20',       icon: 'text-risk-low',       bg: 'bg-risk-low/10',       glow: 'shadow-[0_0_20px_rgba(34,197,94,0.15)]'   },
  amber:   { border: 'border-risk-medium/20',    icon: 'text-risk-medium',    bg: 'bg-risk-medium/10',    glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]'  },
  red:     { border: 'border-risk-high/20',      icon: 'text-risk-high',      bg: 'bg-risk-high/10',      glow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)]'   },
  violet:  { border: 'border-brand-400/20',      icon: 'text-brand-400',      bg: 'bg-brand-400/10',      glow: 'shadow-[0_0_20px_rgba(129,140,248,0.15)]' },
  slate:   { border: 'border-white/[0.06]',      icon: 'text-slate-400',      bg: 'bg-white/[0.04]',      glow: '' },
}

export default function StatusCard({ title, value, sub, icon: Icon, accent = 'cyan', loading = false }) {
  const a = ACCENT[accent] ?? ACCENT.slate

  return (
    <div className={`glass rounded-xl border ${a.border} p-5 flex items-start gap-4 ${a.glow} transition-all hover:scale-[1.01]`}>
      {Icon && (
        <div className={`p-2.5 rounded-xl ${a.bg} shrink-0`}>
          <Icon className={`w-5 h-5 ${a.icon}`} strokeWidth={1.75} />
        </div>
      )}
      <div className="min-w-0 flex-1">
        <p className="text-xs text-slate-500 font-semibold uppercase tracking-widest mb-1">{title}</p>
        {loading
          ? <div className="h-7 w-24 bg-navy-700 rounded-lg animate-pulse mt-1" />
          : <p className="text-2xl font-bold text-white leading-tight">{value ?? '—'}</p>
        }
        {sub && <p className="text-xs text-slate-500 mt-1 truncate">{sub}</p>}
      </div>
    </div>
  )
}
