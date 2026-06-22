import { useEffect, useState } from 'react'
import axios from 'axios'

const API = 'http://localhost:8000'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#c0392b',
  HIGH:     '#d68910',
  MEDIUM:   '#b7950b',
  LOW:      '#1a7a4a',
}

interface Props {
  onSelect: (jobId: string) => void
}

export default function HistoryPage({ onSelect }: Props) {
  const [jobs, setJobs] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    axios.get(`${API}/jobs`).then(r => {
      setJobs(r.data)
    }).finally(() => setLoading(false))
  }, [])

  if (loading) return <p style={{ color: '#7f8c8d', paddingTop: 40 }}>Loading history…</p>

  if (!jobs.length) {
    return (
      <div style={{ textAlign: 'center', paddingTop: 80 }}>
        <p style={{ color: '#7f8c8d' }}>No analyses yet. Submit a file to get started.</p>
      </div>
    )
  }

  return (
    <div>
      <h1 style={{ fontSize: 22, marginBottom: 24 }}>Analysis History</h1>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {jobs.map(job => (
          <div
            key={job.job_id}
            className="card"
            onClick={() => onSelect(job.job_id)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              cursor: 'pointer', padding: '16px 20px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <span style={{
                padding: '4px 12px', borderRadius: 999,
                background: SEV_COLOR[job.severity] || '#7f8c8d',
                color: 'white', fontSize: 11, fontWeight: 700,
                letterSpacing: 1, textTransform: 'uppercase',
                minWidth: 70, textAlign: 'center',
              }}>
                {job.severity || 'N/A'}
              </span>
              <div>
                <p style={{ fontWeight: 600, fontSize: 14, color: '#1a2e4a' }}>
                  {job.file || job.job_id}
                </p>
                <p style={{ fontSize: 12, color: '#7f8c8d' }}>
                  {job.generated_at ? new Date(job.generated_at).toLocaleString() : 'Unknown time'}
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <span style={{ fontWeight: 700, fontSize: 18, color: SEV_COLOR[job.severity] || '#7f8c8d' }}>
                {job.risk_score ?? '—'}
              </span>
              <span style={{ color: '#7f8c8d', fontSize: 13 }}>→</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
