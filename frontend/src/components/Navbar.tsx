import { useEffect, useState } from 'react'
import { type Page } from '../App'
import axios from 'axios'

const API = 'http://localhost:8000'

interface Props {
  page: Page
  setPage: (p: Page) => void
}

export default function Navbar({ page, setPage }: Props) {
  const [ollamaReady, setOllamaReady] = useState<boolean | null>(null)

  useEffect(() => {
    axios.get(`${API}/health`)
      .then(r => setOllamaReady(r.data.tier2_available === true))
      .catch(() => setOllamaReady(false))
  }, [])

  return (
    <nav style={{
      background: '#1a2e4a',
      padding: '0 40px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      height: 60,
      boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 20, fontWeight: 700, color: 'white', letterSpacing: 1 }}>
          ASTRA
        </span>
        <span style={{ fontSize: 11, color: '#8ab0d0', fontWeight: 400, marginTop: 2 }}>
          Malware Analysis System
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {/* Ollama status indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: ollamaReady === null ? '#8ab0d0'
                      : ollamaReady ? '#27ae60'
                      : '#e74c3c',
          }} />
          <span style={{ color: '#8ab0d0' }}>
            {ollamaReady === null ? 'Checking...'
           : ollamaReady ? 'Tier 2 ready'
           : 'Ollama offline'}
          </span>
        </div>

        {(['upload', 'history'] as Page[]).map(p => (
          <button
            key={p}
            onClick={() => setPage(p)}
            style={{
              background: page === p ? 'rgba(255,255,255,0.15)' : 'transparent',
              color: page === p ? 'white' : '#8ab0d0',
              border: 'none',
              borderRadius: 6,
              padding: '6px 16px',
              fontSize: 13,
              fontWeight: page === p ? 600 : 400,
              cursor: 'pointer',
              textTransform: 'capitalize',
            }}
          >
            {p === 'upload' ? 'Analyse' : 'History'}
          </button>
        ))}
      </div>
    </nav>
  )
}
