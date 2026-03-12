import { usePolling } from '../hooks/usePolling'
import { getStatus }  from '../api/client'
import {
  Shield, LayoutDashboard, Activity,
  AlertTriangle, BrainCircuit, Settings,
  Wifi, WifiOff,
} from 'lucide-react'

const ICONS = {
  dashboard: LayoutDashboard,
  telemetry: Activity,
  alerts:    AlertTriangle,
  model:     BrainCircuit,
  config:    Settings,
}

function LevelBadge({ label }) {
  const map = {
    Benign:     'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    Suspicious: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    Malicious:  'bg-red-500/15 text-red-400 border-red-500/30',
    Unknown:    'bg-slate-500/15 text-slate-400 border-slate-500/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${map[label] ?? map.Unknown}`}>
      {label}
    </span>
  )
}

export default function Navbar({ activeTab, tabs, onTabChange }) {
  const { data, error } = usePolling(getStatus, 4000)
  const connected = !error && data?.running

  return (
    <nav className="bg-surface-900 border-b border-surface-700 sticky top-0 z-50 shadow-lg">
      <div className="max-w-screen-2xl mx-auto px-4 sm:px-6">
        <div className="flex items-center h-14 gap-4">

          {/* Brand */}
          <div className="flex items-center gap-2 shrink-0 mr-2">
            <Shield className="text-cyan-400 w-6 h-6" strokeWidth={2} />
            <span className="font-bold text-white text-base tracking-wider">AI-RIDS</span>
          </div>

          {/* Tab buttons */}
          <div className="flex gap-1 overflow-x-auto no-scrollbar">
            {tabs.map(tab => {
              const Icon = ICONS[tab.id]
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => onTabChange(tab.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-all
                    ${active
                      ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                      : 'text-slate-400 hover:text-white hover:bg-surface-800'
                    }`}
                >
                  {Icon && <Icon className="w-3.5 h-3.5" />}
                  {tab.label}
                </button>
              )
            })}
          </div>

          {/* Right: live status */}
          <div className="ml-auto flex items-center gap-3 shrink-0">
            {data && (
              <LevelBadge label={data.current_label} />
            )}
            <div className="flex items-center gap-1.5">
              {connected
                ? <Wifi className="w-4 h-4 text-emerald-400" />
                : <WifiOff className="w-4 h-4 text-red-400" />}
              <span className={`text-xs font-medium ${connected ? 'text-emerald-400' : 'text-red-400'}`}>
                {connected ? 'LIVE' : 'OFFLINE'}
              </span>
            </div>
          </div>

        </div>
      </div>
    </nav>
  )
}
