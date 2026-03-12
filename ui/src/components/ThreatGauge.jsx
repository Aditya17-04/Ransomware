/**
 * ThreatGauge — SVG semicircle speedometer showing threat confidence (0–1).
 *
 * Layout (viewBox 0 0 220 130):
 *   • Background semicircle: grey
 *   • Three colour-zone segments: green (0–0.60), amber (0.60–0.85), red (0.85–1.0)
 *   • Filled arc from 0 → current confidence (colour = zone of current value)
 *   • Animated needle
 *   • Centre text: percentage + label
 */

const CX = 110, CY = 105, R = 88, SW = 16   // centre, radius, stroke-width

/** Convert standard-math degrees (0=right, 90=top, 180=left) to SVG x,y */
function toXY(deg, radius = R) {
  const rad = (deg * Math.PI) / 180
  return {
    x: CX + radius * Math.cos(rad),
    y: CY - radius * Math.sin(rad),
  }
}

/** Build an SVG arc path from startDeg → endDeg going clockwise (sweep=1) */
function arc(startDeg, endDeg, radius = R) {
  const s = toXY(startDeg, radius)
  const e = toXY(endDeg,   radius)
  // span in degrees (always positive, going clockwise)
  const span = ((startDeg - endDeg) + 360) % 360
  const large = span > 180 ? 1 : 0
  return `M ${s.x} ${s.y} A ${radius} ${radius} 0 ${large} 1 ${e.x} ${e.y}`
}

// Key degree positions:
//   confidence=0   → 180° (left)
//   confidence=0.60 → 72°
//   confidence=0.85 → 27°
//   confidence=1   → 0°  (right)
const DEG_SUSPICIOUS = 72   // 180 - 0.60*180
const DEG_HIGH_ALERT = 27   // 180 - 0.85*180

export default function ThreatGauge({ confidence = 0 }) {
  const safeConf  = Math.max(0, Math.min(0.9999, confidence))
  const needleDeg = 180 - safeConf * 180

  const color = safeConf >= 0.85 ? '#ef4444'
              : safeConf >= 0.60 ? '#f59e0b'
              : '#22c55e'

  const label = safeConf >= 0.85 ? 'MALICIOUS'
              : safeConf >= 0.60 ? 'SUSPICIOUS'
              : 'BENIGN'

  const needle = toXY(needleDeg, R - 8)
  const tickDegs = [0, 36, 72, 108, 144, 180]

  return (
    <svg viewBox="0 0 220 130" className="w-full select-none" aria-label="Threat confidence gauge">
      {/* ── Background arc (full semicircle) */}
      <path d={arc(180, 0.01)} fill="none" stroke="#1e293b" strokeWidth={SW} strokeLinecap="butt" />

      {/* ── Colour zone segments (dim) */}
      <path d={arc(180, DEG_SUSPICIOUS)} fill="none" stroke="#14532d" strokeWidth={SW} strokeLinecap="butt" />
      <path d={arc(DEG_SUSPICIOUS, DEG_HIGH_ALERT)} fill="none" stroke="#78350f" strokeWidth={SW} strokeLinecap="butt" />
      <path d={arc(DEG_HIGH_ALERT, 0.01)}           fill="none" stroke="#7f1d1d" strokeWidth={SW} strokeLinecap="butt" />

      {/* ── Filled value arc */}
      {safeConf > 0.002 && (
        <path
          d={arc(180, needleDeg + 0.01)}
          fill="none"
          stroke={color}
          strokeWidth={SW}
          strokeLinecap="butt"
          style={{ filter: `drop-shadow(0 0 4px ${color}66)` }}
        />
      )}

      {/* ── Tick marks */}
      {tickDegs.map(deg => {
        const o = toXY(deg, R + 6)
        const i = toXY(deg, R - SW / 2 - 3)
        return (
          <line key={deg} x1={o.x} y1={o.y} x2={i.x} y2={i.y}
            stroke="#334155" strokeWidth="1.5" strokeLinecap="round" />
        )
      })}

      {/* ── Scale labels */}
      {[
        { deg: 180, val: '0' },
        { deg: 90,  val: '.5' },
        { deg: 0,   val: '1' },
      ].map(({ deg, val }) => {
        const p = toXY(deg, R + 16)
        return (
          <text key={deg} x={p.x} y={p.y + 4} textAnchor="middle"
            fill="#475569" fontSize="9" fontFamily="Inter, sans-serif">
            {val}
          </text>
        )
      })}

      {/* ── Zone marker lines */}
      {[DEG_SUSPICIOUS, DEG_HIGH_ALERT].map(deg => {
        const o = toXY(deg, R + 8)
        const i = toXY(deg, R - SW - 2)
        return (
          <line key={deg} x1={o.x} y1={o.y} x2={i.x} y2={i.y}
            stroke="#334155" strokeWidth="1" strokeDasharray="2,2" />
        )
      })}

      {/* ── Needle */}
      <line
        x1={CX} y1={CY}
        x2={needle.x} y2={needle.y}
        stroke="white" strokeWidth="2.5" strokeLinecap="round"
        style={{ filter: 'drop-shadow(0 0 3px rgba(255,255,255,0.5))' }}
      />
      {/* Needle pivot */}
      <circle cx={CX} cy={CY} r={6}  fill="#0f172a" stroke={color} strokeWidth="2" />
      <circle cx={CX} cy={CY} r={2.5} fill={color} />

      {/* ── Centre text */}
      <text x={CX} y={CY - 18} textAnchor="middle"
        fill="white" fontSize="28" fontWeight="700" fontFamily="Inter, sans-serif"
        style={{ letterSpacing: '-0.5px' }}>
        {(safeConf * 100).toFixed(0)}%
      </text>
      <text x={CX} y={CY - 4} textAnchor="middle"
        fill={color} fontSize="10" fontWeight="600" fontFamily="Inter, sans-serif"
        style={{ letterSpacing: '1.5px' }}>
        {label}
      </text>

      {/* ── Threshold annotations */}
      {(() => {
        const p1 = toXY(DEG_SUSPICIOUS, R - SW - 10)
        const p2 = toXY(DEG_HIGH_ALERT,  R - SW - 10)
        return (
          <>
            <text x={p1.x - 2} y={p1.y} textAnchor="end"
              fill="#78350f" fontSize="7.5" fontFamily="Inter, sans-serif">0.60</text>
            <text x={p2.x + 2} y={p2.y} textAnchor="start"
              fill="#7f1d1d" fontSize="7.5" fontFamily="Inter, sans-serif">0.85</text>
          </>
        )
      })()}
    </svg>
  )
}
