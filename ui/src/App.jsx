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
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const searchParams = new URLSearchParams(window.location.search)
    const isRecoveryLink =
      hashParams.get('type') === 'recovery'
      || searchParams.get('type') === 'recovery'

    // Register listener FIRST — Supabase replays INITIAL_SESSION and any
    // pending events (PASSWORD_RECOVERY, SIGNED_IN) to late-registered listeners.
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'PASSWORD_RECOVERY' || (event === 'INITIAL_SESSION' && isRecoveryLink)) {
        // User arrived via password-reset link — show set-new-password form
        setRecovering(true)
        setUser(null)
      } else if (event === 'SIGNED_OUT') {
        setUser(null)
        setRecovering(false)
      } else if (event === 'USER_UPDATED') {
        // Fired by updateUser() during password reset; don't auto-login here —
        // handleReset calls signOut() which will land them on the sign-in page.
      } else if (session) {
        setUser(makeUser(session.user))
        setRecovering(false)
      } else {
        setUser(null)
        setRecovering(false)
      }
    })

    // Call getSession() AFTER registering the listener. This triggers the PKCE
    // code exchange when Supabase redirects back from Google OAuth (?code=...).
    // Some flows do not emit a later SIGNED_IN event reliably enough for this UI,
    // so hydrate the user directly from the resolved session here.
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (isRecoveryLink) {
        setRecovering(true)
        setUser(null)
      } else if (session) {
        setUser(makeUser(session.user))
        setRecovering(false)
      }
      setAuthChecked(true)
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
        key={recovering ? 'reset' : 'signin'}
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
