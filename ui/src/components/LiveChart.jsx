/**
 * LiveChart — a Recharts LineChart wrapper styled for the dark theme.
 *
 * Props:
 *   data       : array of objects
 *   lines      : [{ key, color, name }]
 *   xKey       : key for x-axis (default 'ts', expects ms epoch)
 *   height     : number (default 180)
 *   unit       : string appended to tooltip values
 *   title      : string (optional section header)
 *   formatX    : fn(value) → string  (optional x-axis tick formatter)
 */

import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from 'recharts'

function defaultFmtX(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function CustomTooltip({ active, payload, label, unit }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface-800 border border-surface-600 rounded-lg p-3 shadow-xl text-xs">
      <p className="text-slate-400 mb-1.5">{defaultFmtX(label)}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: p.color }} className="font-medium">
          {p.name}: <span className="text-white">{typeof p.value === 'number' ? p.value.toLocaleString() : p.value}{unit ? ` ${unit}` : ''}</span>
        </p>
      ))}
    </div>
  )
}

export default function LiveChart({
  data = [],
  lines = [],
  xKey = 'ts',
  height = 180,
  unit = '',
  title = '',
  yDomain,
}) {
  return (
    <div>
      {title && (
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">{title}</p>
      )}
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey={xKey}
            tickFormatter={defaultFmtX}
            tick={{ fill: '#475569', fontSize: 9 }}
            axisLine={false}
            tickLine={false}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: '#475569', fontSize: 9 }}
            axisLine={false}
            tickLine={false}
            domain={yDomain}
            tickFormatter={v => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v}
            width={36}
          />
          <Tooltip content={<CustomTooltip unit={unit} />} />
          {lines.length > 1 && (
            <Legend
              wrapperStyle={{ fontSize: '10px', color: '#94a3b8', paddingTop: '4px' }}
            />
          )}
          {lines.map(({ key, color, name }) => (
            <Line
              key={key}
              type="monotone"
              dataKey={key}
              name={name ?? key}
              stroke={color}
              strokeWidth={1.75}
              dot={false}
              activeDot={{ r: 3, fill: color }}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
