/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        navy: {
          950: '#040b18',
          900: '#070f1f',
          800: '#0b1628',
          750: '#0e1c33',
          700: '#122240',
          600: '#1a3158',
          500: '#1e3a6e',
        },
        brand: {
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
        },
        accent: {
          blue:   '#3b82f6',
          indigo: '#6366f1',
          cyan:   '#22d3ee',
          teal:   '#2dd4bf',
        },
        risk: {
          low:    '#22c55e',
          medium: '#f59e0b',
          high:   '#ef4444',
        },
      },
      backgroundImage: {
        'navy-gradient': 'linear-gradient(135deg, #040b18 0%, #070f1f 50%, #0c1628 100%)',
        'card-gradient': 'linear-gradient(135deg, rgba(11,22,40,0.9) 0%, rgba(7,15,31,0.8) 100%)',
        'brand-gradient': 'linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%)',
        'glow-indigo': 'radial-gradient(ellipse at center, rgba(99,102,241,0.15) 0%, transparent 70%)',
      },
      boxShadow: {
        'card':     '0 4px 24px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.04)',
        'glow-sm':  '0 0 20px rgba(99,102,241,0.25)',
        'glow-md':  '0 0 40px rgba(99,102,241,0.3)',
        'glow-brand': '0 4px 20px rgba(79,70,229,0.5)',
      },
      animation: {
        'pulse-fast':  'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float':       'float 6s ease-in-out infinite',
        'glow-pulse':  'glowPulse 3s ease-in-out infinite',
        'slide-up':    'slideUp 0.4s ease-out',
        'fade-in':     'fadeIn 0.5s ease-out',
        'orbit':       'orbit 20s linear infinite',
      },
      keyframes: {
        float:      { '0%,100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-8px)' } },
        glowPulse:  { '0%,100%': { opacity: '0.6' }, '50%': { opacity: '1' } },
        slideUp:    { from: { transform: 'translateY(12px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        fadeIn:     { from: { opacity: '0' }, to: { opacity: '1' } },
        orbit:      { from: { transform: 'rotate(0deg) translateX(120px) rotate(0deg)' }, to: { transform: 'rotate(360deg) translateX(120px) rotate(-360deg)' } },
      },
    },
  },
  plugins: [],
}
