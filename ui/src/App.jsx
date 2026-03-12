import { useState } from 'react'
import Navbar      from './components/Navbar'
import Dashboard   from './tabs/Dashboard'
import Telemetry   from './tabs/Telemetry'
import Alerts      from './tabs/Alerts'
import ModelInfo   from './tabs/ModelInfo'
import ConfigView  from './tabs/ConfigView'

const TABS = [
  { id: 'dashboard', label: 'Dashboard'   },
  { id: 'telemetry', label: 'Telemetry'   },
  { id: 'alerts',    label: 'Alerts'      },
  { id: 'model',     label: 'ML Model'    },
  { id: 'config',    label: 'Config'      },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard')

  return (
    <div className="min-h-screen bg-surface-950 text-slate-200">
      <Navbar activeTab={activeTab} tabs={TABS} onTabChange={setActiveTab} />
      <main className="max-w-screen-2xl mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'telemetry' && <Telemetry />}
        {activeTab === 'alerts'    && <Alerts />}
        {activeTab === 'model'     && <ModelInfo />}
        {activeTab === 'config'    && <ConfigView />}
      </main>
    </div>
  )
}
