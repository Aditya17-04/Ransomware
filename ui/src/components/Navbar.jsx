import { usePolling } from '../hooks/usePolling'
import { getStatus }  from '../api/client'
import {
  ShieldCheck, LayoutDashboard, Activity,
  AlertTriangle, BrainCircuit, Settings,
  Wifi, WifiOff, Radio, LogOut,
} from 'lucide-react'

const ICONS = {
  dashboard: LayoutDashboard,
  telemetry: Activity,
  alerts:    AlertTriangle,
  model:     BrainCircuit,
  config:    Settings,
}

function ThreatPill({ label }) {
  const map = {
    Benign:     'badge-low',
    Suspicious: 'badge-medium',
    Malicious:  'badge-high',
    Unknown:    'bg-navy-700 text-slate-400 border border-navy-600',
  }
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-semibold tracking-wide ${map[label] ?? map.Unknown}`}>
      {label}
    </span>
  )
}

export default function Navbar({ activeTab, tabs, onTabChange, user, onSignOut }) {
  const { data, error } = usePolling(getStatus, 4000)
  const connected = !error && data?.running

  return (
    <nav className="sticky top-0 z-50 border-b border-white/[0.06]"
         style={{ background: 'rgba(4,11,24,0.92)', backdropFilter: 'blur(16px)' }}>
      <div className="max-w-screen-2xl mx-auto px-6">
        <div className="flex items-center h-16 gap-6">

          {/* Brand */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-brand-gradient flex items-center justify-center shadow-glow-sm">
              <ShieldCheck className="w-4.5 h-4.5 text-white" strokeWidth={2} />
            </div>
            <div>
              <span className="font-bold text-white text-sm tracking-widest">AI-RIDS</span>
              <span className="hidden sm:block text-[10px] text-slate-500 tracking-wider -mt-0.5">INTRUSION DETECTION</span>
            </div>
          </div>

          {/* Divider */}
          <div className="w-px h-8 bg-white/[0.06] shrink-0" />

          {/* Tab buttons */}
          <div className="flex gap-1 overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
            {tabs.map(tab => {
              const Icon = ICONS[tab.id]
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => onTabChange(tab.id)}
                  className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-all duration-200
                    ${active
                      ? 'nav-active text-white'
                      : 'text-slate-400 hover:text-white hover:bg-navy-700/60'
                    }`}
                >
                  {Icon && <Icon className="w-3.5 h-3.5" />}
                  {tab.label}
                </button>
              )
            })}
          </div>

          {/* Right side */}
          <div className="ml-auto flex items-center gap-4 shrink-0">
            {data && <ThreatPill label={data.current_label} />}
            {user && (
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                     style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <div className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white"
                       style={{ background: 'linear-gradient(135deg,#4f46e5,#3b82f6)' }}>
                    {(user.name?.[0] ?? user.email?.[0] ?? 'U').toUpperCase()}
                  </div>
                  <span className="text-xs text-slate-300 hidden xl:block max-w-[120px] truncate">
                    {user.name || user.email}
                  </span>
                </div>
                <button
                  onClick={onSignOut}
                  title="Sign out"
                  className="p-2 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-all"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            )}
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border transition-all
              ${connected
                ? 'border-risk-low/30 text-risk-low bg-risk-low/10'
                : 'border-risk-high/30 text-risk-high bg-risk-high/10'
              }`}>
              {connected
                ? <Radio className="w-3 h-3 animate-pulse-fast" />
                : <WifiOff className="w-3 h-3" />}
              {connected ? 'LIVE' : 'OFFLINE'}
            </div>
          </div>

        </div>
      </div>
    </nav>
  )
}
