import { useState } from 'react'
import { supabase } from './lib/supabase'
import {
  Mail, Lock, Eye, EyeOff, User, ArrowRight,
  Shield, ShieldCheck, Cpu, HardDrive, Globe,
} from 'lucide-react'

/* ── Animated network background ─────────────────────────── */
function NetworkBg() {
  const nodes = [
    { cx: '10%', cy: '18%', r: 3.5, delay: '0s'   },
    { cx: '38%', cy: '42%', r: 5.5, delay: '0.8s' },
    { cx: '58%', cy: '16%', r: 3,   delay: '1.5s' },
    { cx: '74%', cy: '52%', r: 4,   delay: '0.4s' },
    { cx: '87%', cy: '28%', r: 3,   delay: '2s'   },
    { cx: '22%', cy: '70%', r: 3,   delay: '1.2s' },
    { cx: '52%', cy: '76%', r: 4.5, delay: '0.6s' },
    { cx: '66%', cy: '63%', r: 2.5, delay: '1.8s' },
    { cx: '92%', cy: '68%', r: 3,   delay: '1.0s' },
  ]
  const arcs = [
    'M 10 18 Q 26 8  38 42',
    'M 38 42 Q 49 27 58 16',
    'M 58 16 Q 67 34 74 52',
    'M 74 52 Q 81 40 87 28',
    'M 38 42 Q 44 60 52 76',
    'M 10 18 Q 16 46 22 70',
    'M 22 70 Q 36 74 52 76',
    'M 58 16 Q 73 22 87 28',
    'M 52 76 Q 60 69 66 63',
    'M 74 52 Q 70 57 66 63',
    'M 87 28 Q 90 48 92 68',
    'M 66 63 Q 79 65 92 68',
  ]
  return (
    <svg
      className="absolute inset-0 w-full h-full pointer-events-none"
      viewBox="0 0 100 100"
      preserveAspectRatio="xMidYMid slice"
    >
      <defs>
        <linearGradient id="authArcGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%"   stopColor="#6366f1" stopOpacity="0.55" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.08" />
        </linearGradient>
        <filter id="authBlur"><feGaussianBlur stdDeviation="0.2" /></filter>
      </defs>
      {arcs.map((d, i) => (
        <path key={i} d={d} fill="none" stroke="url(#authArcGrad)"
          strokeWidth="0.22" filter="url(#authBlur)" opacity="0.75" />
      ))}
      {nodes.map((n, i) => (
        <g key={i}>
          <circle cx={n.cx} cy={n.cy} r={n.r * 2.2} fill="#6366f1" opacity="0.05" />
          <circle cx={n.cx} cy={n.cy} r={n.r * 0.55} fill="#818cf8" opacity="0.85">
            <animate attributeName="r"
              values={`${n.r * 0.5};${n.r * 0.95};${n.r * 0.5}`}
              dur="2.5s" begin={n.delay} repeatCount="indefinite" />
            <animate attributeName="opacity"
              values="0.85;0.3;0.85"
              dur="2.5s" begin={n.delay} repeatCount="indefinite" />
          </circle>
          {i === 1 && (
            <circle cx={n.cx} cy={n.cy} r="0.9" fill="#fbbf24">
              <animate attributeName="r" values="0.8;2.2;0.8" dur="1.6s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="1;0.3;1" dur="1.6s" repeatCount="indefinite" />
            </circle>
          )}
        </g>
      ))}
    </svg>
  )
}

/* ── Google logo ─────────────────────────────────────────── */
function GoogleIcon() {
  return (
    <svg width="17" height="17" viewBox="0 0 18 18">
      <path fill="#4285F4" d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.716v2.259h2.908C16.658 14.251 17.64 11.943 17.64 9.2z"/>
      <path fill="#34A853" d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332C2.438 15.983 5.482 18 9 18z"/>
      <path fill="#FBBC05" d="M3.964 10.706A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.706V4.962H.957A9.009 9.009 0 0 0 0 9c0 1.452.348 2.826.957 4.038l3.007-2.332z"/>
      <path fill="#EA4335" d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0 5.482 0 2.438 2.017.957 4.962L3.964 7.294C4.672 5.167 6.656 3.58 9 3.58z"/>
    </svg>
  )
}

const FEATURES = [
  {
    icon: Cpu,
    label: 'HPC Performance Monitoring',
    sub:   'Hardware performance counters detect CPU encryption spikes in real time',
  },
  {
    icon: HardDrive,
    label: 'AI Threat Detection Engine',
    sub:   'ML models score ransomware likelihood from file entropy and syscall patterns',
  },
  {
    icon: Globe,
    label: 'Autonomous Response System',
    sub:   'Instantly isolates processes, blocks C2 channels and protects files',
  },
]

/* ── Reusable text input ─────────────────────────────────── */
function AuthInput({ type, value, onChange, placeholder, icon: Icon, right }) {
  return (
    <div className="relative">
      <Icon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoComplete="off"
        className="w-full pl-10 pr-10 py-3 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-colors"
        style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }}
        onFocus={e  => (e.target.style.borderColor = 'rgba(99,102,241,0.65)')}
        onBlur={e   => (e.target.style.borderColor = 'rgba(255,255,255,0.1)')}
      />
      {right && (
        <div className="absolute right-3.5 top-1/2 -translate-y-1/2">{right}</div>
      )}
    </div>
  )
}

/* ── Main auth page ──────────────────────────────────────── */
export default function AuthPage({ onAuth, initialMode = 'signin' }) {
  const [mode,      setMode]      = useState(initialMode)  // 'signin'|'signup'|'forgot'|'reset'
  const [showPass,  setShowPass]  = useState(false)
  const [showPass2, setShowPass2] = useState(false)
  const [fields,    setFields]    = useState({ name: '', email: '', password: '', password2: '' })
  const [error,     setError]     = useState('')
  const [info,      setInfo]      = useState('')
  const [loading,   setLoading]   = useState(false)

  const set = k => e => setFields(f => ({ ...f, [k]: e.target.value }))

  const switchMode = next => {
    setMode(next)
    setError('')
    setInfo('')
    setFields({ name: '', email: '', password: '', password2: '' })
    setShowPass(false)
    setShowPass2(false)
  }

  /* ── Google OAuth ────────────────────────────── */
  const [googleTooltip, setGoogleTooltip] = useState(false)
  const handleGoogle = async () => {
    setError('')
    const { error: sbErr } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: window.location.origin },
    })
    if (sbErr) {
      setGoogleTooltip(true)
      setTimeout(() => setGoogleTooltip(false), 6000)
    }
  }

  /* ── Forgot password ─────────────────────────── */
  const handleForgot = async e => {
    e.preventDefault()
    setError('')
    setInfo('')
    if (!fields.email.trim()) { setError('Please enter your email address.'); return }
    setLoading(true)
    try {
      const { error: sbErr } = await supabase.auth.resetPasswordForEmail(
        fields.email,
        { redirectTo: `${window.location.origin}` },
      )
      if (sbErr) throw sbErr
      setInfo('✅ Password reset email sent! Check your inbox and click the link to set a new password.')
    } catch (err) {
      setError(err.message || 'Failed to send reset email.')
    } finally {
      setLoading(false)
    }
  }

  /* ── Reset password (after email link) ──────── */
  const handleReset = async e => {
    e.preventDefault()
    setError('')
    // Prevent double-submit: if info is already set the update already succeeded
    if (info) return
    if (fields.password.length < 6)              { setError('Password must be at least 6 characters.'); return }
    if (fields.password !== fields.password2)    { setError('Passwords do not match.');                 return }
    setLoading(true)
    try {
      const { error: sbErr } = await supabase.auth.updateUser({ password: fields.password })
      if (sbErr) throw sbErr
      setError('')
      setInfo('✅ Password updated! Redirecting to sign in...')
      // Sign out after a short delay so the user sees the confirmation, then
      // the SIGNED_OUT event in App.jsx resets recovering=false and user=null,
      // which remounts AuthPage in sign-in mode.
      setTimeout(() => supabase.auth.signOut(), 1500)
    } catch (err) {
      setError(err.message || 'Failed to update password.')
    } finally {
      setLoading(false)
    }
  }

  /* ── Sign in / Sign up ───────────────────────── */
  const handleSubmit = async e => {
    e.preventDefault()
    setError('')
    setInfo('')
    if (mode === 'signup' && !fields.name.trim())        { setError('Please enter your name.');                return }
    if (!fields.email.trim())                             { setError('Please enter your email.');               return }
    if (!fields.password.trim())                          { setError('Please enter your password.');            return }
    if (mode === 'signup' && fields.password.length < 6) { setError('Password must be at least 6 characters.'); return }

    setLoading(true)
    try {
      if (mode === 'signup') {
        const { data, error: sbErr } = await supabase.auth.signUp({
          email:    fields.email,
          password: fields.password,
          options:  {
            data: { full_name: fields.name },
            emailRedirectTo: `${window.location.origin}`,
          },
        })
        if (sbErr) throw sbErr
        if (data.session) {
          const u = data.session.user
          onAuth({ email: u.email, name: u.user_metadata?.full_name || u.email.split('@')[0] })
        } else {
          setInfo('✅ Account created! Check your email to confirm your address, then sign in.')
          switchMode('signin')
        }
      } else {
        const { data, error: sbErr } = await supabase.auth.signInWithPassword({
          email:    fields.email,
          password: fields.password,
        })
        if (sbErr) throw sbErr
        const u = data.user
        onAuth({ email: u.email, name: u.user_metadata?.full_name || u.email.split('@')[0] })
      }
    } catch (err) {
      const msg = err.message || ''
      if (msg.toLowerCase().includes('rate limit') || msg.toLowerCase().includes('too many')) {
        setError('Too many sign-up attempts. Please wait a few minutes and try again, or sign in if you already have an account.')
      } else {
        setError(msg || 'Authentication failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex" style={{ background: '#060d1a' }}>

      {/* ════ LEFT HERO ════════════════════════════════════════ */}
      <div
        className="hidden lg:flex flex-col justify-between flex-1 relative overflow-hidden px-14 py-12"
        style={{ background: 'linear-gradient(135deg, #060d1a 0%, #091528 65%, #0e2040 100%)' }}
      >
        <NetworkBg />

        {/* Glow blobs */}
        <div className="absolute top-1/3 left-1/4 w-[550px] h-[550px] rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(79,70,229,0.10) 0%, transparent 70%)' }} />
        <div className="absolute bottom-1/4 right-1/3 w-[350px] h-[350px] rounded-full pointer-events-none"
          style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.07) 0%, transparent 70%)' }} />

        {/* Logo */}
        <div className="relative z-10 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center shadow-lg"
            style={{ background: 'linear-gradient(135deg, #4f46e5, #3b82f6)' }}>
            <Shield className="w-5 h-5 text-white" strokeWidth={2} />
          </div>
          <span className="text-white font-bold text-xl tracking-tight">AI-RIDS</span>
        </div>

        {/* Hero content */}
        <div className="relative z-10 flex-1 flex flex-col justify-center py-10">
          {/* Live badge */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-400 font-semibold tracking-wider mb-8 w-fit">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            LIVE RISK INTELLIGENCE
          </div>

          <h1 className="text-5xl font-extrabold text-white leading-tight mb-1">AI-Powered</h1>
          <h1 className="text-5xl font-extrabold leading-tight mb-6 text-gradient">
            Ransomware Detection
          </h1>
          <p className="text-slate-400 text-base max-w-md leading-relaxed mb-10">
            Predict ransomware attacks before encryption completes — monitoring CPU,
            filesystem, and network in real time.
          </p>

          {/* Feature cards */}
          <div className="flex flex-col gap-3 max-w-[530px]">
            {FEATURES.map(({ icon: Icon, label, sub }) => (
              <div
                key={label}
                className="flex items-center gap-4 px-5 py-4 rounded-xl border border-white/[0.07] transition-colors hover:border-brand-500/20"
                style={{ background: 'rgba(10,22,48,0.65)', backdropFilter: 'blur(8px)' }}
              >
                <div className="p-2.5 rounded-lg shrink-0"
                  style={{ background: 'rgba(99,102,241,0.15)' }}>
                  <Icon className="w-5 h-5 text-indigo-400" strokeWidth={1.75} />
                </div>
                <div>
                  <p className="text-sm font-semibold text-white">{label}</p>
                  <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">{sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom risk badges */}
        <div className="relative z-10 flex items-center gap-3">
          <span className="badge-low   px-3 py-1.5 rounded-full text-xs font-semibold">● Low Risk</span>
          <span className="badge-medium px-3 py-1.5 rounded-full text-xs font-semibold">● Medium Risk</span>
          <span className="badge-high  px-3 py-1.5 rounded-full text-xs font-semibold">● High Risk</span>
        </div>
      </div>

      {/* ════ RIGHT AUTH CARD ══════════════════════════════════ */}
      <div
        className="w-full lg:w-[450px] xl:w-[490px] flex items-center justify-center px-8 py-14 shrink-0"
        style={{ background: 'rgba(8,15,32,0.98)', borderLeft: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div className="w-full max-w-[340px]">

          {/* Mobile logo */}
          <div className="flex items-center gap-3 mb-8 lg:hidden">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center"
              style={{ background: 'linear-gradient(135deg,#4f46e5,#3b82f6)' }}>
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="text-white font-bold text-lg">AI-RIDS</span>
          </div>

          {/* Heading */}
          <h2 className="text-2xl font-bold text-white mb-1">
            {mode === 'signin'  ? 'Welcome back'      :
             mode === 'signup'  ? 'Create Account'    :
             mode === 'forgot'  ? 'Reset Password'    :
                                  'Set New Password'}
          </h2>
          <p className="text-sm text-slate-500 mb-8">
            {mode === 'signin'  ? 'Sign in to your AI-RIDS account'           :
             mode === 'signup'  ? 'Start monitoring threats in seconds'        :
             mode === 'forgot'  ? 'Enter your email and we\'ll send a reset link' :
                                  'Enter your new password below'}
          </p>

          {/* ── FORGOT PASSWORD FORM ── */}
          {mode === 'forgot' && (
            <form onSubmit={handleForgot} className="space-y-4">
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Email Address
                </label>
                <AuthInput type="email" value={fields.email} onChange={set('email')}
                  placeholder="you@company.com" icon={Mail} />
              </div>
              {error && <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</p>}
              {info  && <p className="text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">{info}</p>}
              <button type="submit" disabled={loading}
                className="w-full py-3 rounded-lg text-sm font-semibold text-white flex items-center justify-center gap-2 transition-all hover:brightness-110 active:scale-[0.98] disabled:opacity-60"
                style={{ background: 'linear-gradient(135deg,#5b5cf6,#4f46e5)', boxShadow: '0 4px 20px rgba(79,70,229,0.45)' }}>
                {loading
                  ? <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  : <>Send Reset Link <ArrowRight className="w-4 h-4" /></>}
              </button>
              <button type="button" onClick={() => switchMode('signin')}
                className="w-full text-center text-sm text-slate-500 hover:text-slate-300 transition-colors pt-1">
                ← Back to Sign In
              </button>
            </form>
          )}

          {/* ── RESET PASSWORD FORM (after email link) ── */}
          {mode === 'reset' && (
            <form onSubmit={handleReset} className="space-y-4">
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">New Password</label>
                <AuthInput type={showPass ? 'text' : 'password'} value={fields.password} onChange={set('password')}
                  placeholder="At least 6 characters" icon={Lock}
                  right={<button type="button" onClick={() => setShowPass(s => !s)} className="text-slate-500 hover:text-slate-300 transition-colors">
                    {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>} />
              </div>
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Confirm Password</label>
                <AuthInput type={showPass2 ? 'text' : 'password'} value={fields.password2} onChange={set('password2')}
                  placeholder="Repeat password" icon={Lock}
                  right={<button type="button" onClick={() => setShowPass2(s => !s)} className="text-slate-500 hover:text-slate-300 transition-colors">
                    {showPass2 ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>} />
              </div>
              {error && <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</p>}
              {info  && <p className="text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">{info}</p>}
              <button type="submit" disabled={loading || !!info}
                className="w-full py-3 rounded-lg text-sm font-semibold text-white flex items-center justify-center gap-2 transition-all hover:brightness-110 active:scale-[0.98] disabled:opacity-60"
                style={{ background: 'linear-gradient(135deg,#5b5cf6,#4f46e5)', boxShadow: '0 4px 20px rgba(79,70,229,0.45)' }}>
                {loading
                  ? <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  : <>Update Password <ArrowRight className="w-4 h-4" /></>}
              </button>
            </form>
          )}

          {/* ── SIGN IN / SIGN UP FORM ── */}
          {(mode === 'signin' || mode === 'signup') && (
            <>
            <form onSubmit={handleSubmit} className="space-y-4">

              {/* Name — signup only */}
              {mode === 'signup' && (
                <div>
                  <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                    Full Name
                  </label>
                  <AuthInput
                    type="text" value={fields.name} onChange={set('name')}
                    placeholder="Your name" icon={User}
                  />
                </div>
              )}

              {/* Email */}
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Email Address
                </label>
                <AuthInput
                  type="email" value={fields.email} onChange={set('email')}
                  placeholder="you@company.com" icon={Mail}
                />
              </div>

              {/* Password */}
              <div>
                <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Password
                </label>
                <AuthInput
                  type={showPass ? 'text' : 'password'}
                  value={fields.password} onChange={set('password')}
                  placeholder="••••••••" icon={Lock}
                  right={
                    <button type="button" onClick={() => setShowPass(s => !s)}
                      className="text-slate-500 hover:text-slate-300 transition-colors">
                      {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  }
                />
                {mode === 'signin' && (
                  <div className="flex justify-end mt-1.5">
                    <button type="button" onClick={() => switchMode('forgot')}
                      className="text-xs text-indigo-400 hover:text-indigo-300 transition-colors">
                      Forgot password?
                    </button>
                  </div>
                )}
              </div>

              {/* Error */}
              {error && (
                <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
                  {error}
                </p>
              )}

              {/* Info / confirmation */}
              {info && (
                <p className="text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
                  {info}
                </p>
              )}

              {/* Submit button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-lg text-sm font-semibold text-white flex items-center justify-center gap-2 transition-all hover:brightness-110 active:scale-[0.98] disabled:opacity-60 mt-1"
                style={{
                  background:  'linear-gradient(135deg, #5b5cf6, #4f46e5)',
                  boxShadow:   '0 4px 20px rgba(79,70,229,0.45)',
                }}
              >
                {loading
                  ? <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  : <>{mode === 'signin' ? 'Sign In' : 'Create Account'} <ArrowRight className="w-4 h-4" /></>
                }
              </button>
            </form>

            {/* OR divider */}
            <div className="flex items-center gap-3 my-5">
              <div className="flex-1 h-px bg-white/[0.08]" />
              <span className="text-xs text-slate-600 font-medium tracking-widest">OR</span>
              <div className="flex-1 h-px bg-white/[0.08]" />
            </div>

            {/* Google sign-in */}
            <div className="relative">
              <button
                type="button"
                onClick={handleGoogle}
                className="w-full py-3 rounded-lg text-sm font-medium text-slate-300 flex items-center justify-center gap-3 transition-all hover:bg-white/[0.07]"
                style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }}
              >
                <GoogleIcon />
                Sign in with Google
              </button>
              {googleTooltip && (
                <div className="absolute left-0 right-0 mt-2 px-4 py-3 rounded-xl text-xs leading-relaxed z-20"
                  style={{ background: '#0f1c38', border: '1px solid rgba(245,158,11,0.35)' }}>
                  <p className="text-amber-400 font-semibold mb-1">⚠ Google provider not enabled yet</p>
                  <p className="text-slate-400">To enable Google sign-in:</p>
                  <ol className="text-slate-400 mt-1 space-y-0.5 list-decimal list-inside">
                    <li>Create OAuth credentials at <span className="text-indigo-400">console.cloud.google.com</span></li>
                    <li>Add redirect URI: <span className="font-mono text-slate-300 break-all">https://ynvrmxdxvftohepdugbw.supabase.co/auth/v1/callback</span></li>
                    <li>Enable Google in <span className="text-indigo-400">Supabase → Auth → Providers</span></li>
                  </ol>
                  <p className="text-slate-500 mt-2">For now, use email/password sign-in above.</p>
                </div>
              )}
            </div>

            {/* 2FA notice — sign-in only */}
            {mode === 'signin' && (
              <div
                className="flex items-center gap-2 mt-4 px-3 py-2.5 rounded-lg"
                style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.06)' }}
              >
                <ShieldCheck className="w-4 h-4 text-slate-600 shrink-0" />
                <span className="text-xs text-slate-600">
                  Two-factor authentication available after sign-in
                </span>
              </div>
            )}

            {/* Toggle mode */}
            <p className="text-center text-sm text-slate-500 mt-6">
              {mode === 'signin' ? "Don't have an account? " : 'Already have an account? '}
              <button onClick={() => switchMode(mode === 'signin' ? 'signup' : 'signin')}
                className="text-indigo-400 hover:text-indigo-300 font-semibold transition-colors">
                {mode === 'signin' ? 'Create Account' : 'Sign In'}
              </button>
            </p>
            </>
          )}

          {/* ToS */}
          <p className="text-center text-[11px] text-slate-600 mt-4 leading-relaxed">
            By continuing you agree to AI-RIDS&apos;{' '}
            <span className="text-slate-500 hover:text-slate-400 cursor-pointer transition-colors">Terms of Service</span>
            {' and '}
            <span className="text-slate-500 hover:text-slate-400 cursor-pointer transition-colors">Privacy Policy</span>
          </p>

        </div>
      </div>

    </div>
  )
}
