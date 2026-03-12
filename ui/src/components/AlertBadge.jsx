/** Colour-coded badge for threat level / alert level. */

const STYLES = {
  Benign:     'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  Suspicious: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  Malicious:  'bg-red-500/15 text-red-400 border-red-500/30',
  HighAlert:  'bg-red-600/25 text-red-300 border-red-500/50',
  Unknown:    'bg-slate-600/20 text-slate-400 border-slate-600/40',
}

export default function AlertBadge({ level, size = 'sm' }) {
  const cls = STYLES[level] ?? STYLES.Unknown
  const pad = size === 'xs' ? 'px-1.5 py-0 text-[10px]' : 'px-2.5 py-0.5 text-xs'
  return (
    <span className={`inline-flex items-center rounded-full border font-semibold tracking-wide ${pad} ${cls}`}>
      {level === 'HighAlert' ? 'HIGH ALERT' : level?.toUpperCase()}
    </span>
  )
}
