/** Colour-coded badge for threat level / alert level. */

const STYLES = {
  Benign:     'badge-low',
  Suspicious: 'badge-medium',
  Malicious:  'badge-high',
  HighAlert:  'bg-risk-high/20 text-risk-high border border-risk-high/40',
  Unknown:    'bg-navy-700 text-slate-400 border border-navy-600',
}

export default function AlertBadge({ level, size = 'sm' }) {
  const cls = STYLES[level] ?? STYLES.Unknown
  const pad = size === 'xs' ? 'px-1.5 py-0 text-[10px]' : 'px-2.5 py-0.5 text-xs'
  return (
    <span className={`inline-flex items-center rounded-full font-semibold tracking-wide ${pad} ${cls}`}>
      {level === 'HighAlert' ? 'HIGH ALERT' : level?.toUpperCase()}
    </span>
  )
}
