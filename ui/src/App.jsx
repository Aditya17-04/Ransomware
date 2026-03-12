import { useState, useEffect } from 'react'
import { supabase }  from './lib/supabase'
import AuthPage      from './AuthPage'
import Navbar        from './components/Navbar'
import Dashboard     from './tabs/Dashboard'
import Telemetry     from './tabs/Telemetry'
import Alerts        from './tabs/Alerts'
import ModelInfo     from './tabs/ModelInfo'
import ConfigView    from './tabs/ConfigView'

const TABS = [
  { id: 'dashboard', label: 'Dashboard'   },
  { id: 'telemetry', label: 'Telemetry'   },
  { id: 'alerts',    label: 'Alerts'      },
  { id: 'model',     label: 'ML Model'    },
  { id: 'config',    label: 'Config'      },
]

function makeUser(sbUser) {
  return {
    email: sbUser.email,
    name:  sbUser.user_metadata?.full_name
        || sbUser.user_metadata?.name
        || sbUser.email.split('@')[0],
  }
}

export default function App() {
  const [user,         setUser]         = useState(null)
  const [authChecked,  setAuthChecked]  = useState(false)
  const [recovering,   setRecovering]   = useState(false)   // password-reset flow
  const [activeTab,    setActiveTab]    = useState('dashboard')

  useEffect(() => {
    // Restore session on page load (also handles OAuth redirect hash)
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session) setUser(makeUser(session.user))
      setAuthChecked(true)
    })

    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'PASSWORD_RECOVERY') {
        // User arrived via password-reset link — show set-new-password form
        setRecovering(true)
        setUser(null)
      } else if (session) {
        setUser(makeUser(session.user))
        setRecovering(false)
      } else {
        setUser(null)
      }
    })

    return () => subscription.unsubscribe()
  }, [])

  const handleSignOut = async () => {
    await supabase.auth.signOut()
    setUser(null)
  }

  // Blank screen while we verify the session (avoids auth-page flash)
  if (!authChecked) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: '#040b18' }}>
        <span className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!user) {
    return (
      <AuthPage
        onAuth={u => setUser(u)}
        initialMode={recovering ? 'reset' : 'signin'}
      />
    )
  }

  return (
    <div className="min-h-screen text-slate-200" style={{ background: '#040b18' }}>
      <Navbar
        activeTab={activeTab}
        tabs={TABS}
        onTabChange={setActiveTab}
        user={user}
        onSignOut={handleSignOut}
      />
      <main className="max-w-screen-2xl mx-auto px-4 sm:px-6 py-6 animate-fade-in">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'telemetry' && <Telemetry />}
        {activeTab === 'alerts'    && <Alerts />}
        {activeTab === 'model'     && <ModelInfo />}
        {activeTab === 'config'    && <ConfigView />}
      </main>
    </div>
  )
}
