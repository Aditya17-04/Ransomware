import { useState, useEffect, useRef, useCallback } from 'react'

/**
 * Polls `fetcher` every `interval` ms and returns { data, error, loading }.
 * Re-runs whenever `deps` change.
 */
export function usePolling(fetcher, interval = 3000, deps = []) {
  const [data,    setData]    = useState(null)
  const [error,   setError]   = useState(null)
  const [loading, setLoading] = useState(true)
  const timer = useRef(null)

  const tick = useCallback(async () => {
    try {
      const result = await fetcher()
      setData(result)
      setError(null)
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      try {
        const result = await fetcher()
        if (!cancelled) { setData(result); setError(null) }
      } catch (err) {
        if (!cancelled) setError(err)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    run()
    timer.current = setInterval(run, interval)
    return () => {
      cancelled = true
      clearInterval(timer.current)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [interval, ...deps])

  return { data, error, loading }
}
