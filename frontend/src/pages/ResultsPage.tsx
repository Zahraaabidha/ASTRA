import { useEffect, useState } from 'react'
import axios from 'axios'
import { type Page } from '../App'

const API = 'http://localhost:8000'

interface Props {
  jobId: string | null
  setPage: (p: Page) => void
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#c0392b',
  HIGH:     '#d68910',
  MEDIUM:   '#b7950b',
  LOW:      '#1a7a4a',
  UNKNOWN:  '#7f8c8d',
}

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: '#fde8e8',
  HIGH:     '#fef3e2',
  MEDIUM:   '#fefbe2',
  LOW:      '#e8f8ef',
  UNKNOWN:  '#f4f5f7',
}

export default function ResultsPage({ jobId, setPage }: Props) {
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!jobId) return
    const load = async () => {
      try {
        const res = await axios.get(`${API}/report/${jobId}`)
        setReport(res.data)
      } catch (e: any) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [jobId])

  if (!jobId) {
    return (
      <div style={{ textAlign: 'center', paddingTop: 80 }}>
        <p style={{ color: '#7f8c8d' }}>No analysis selected.</p>
        <button className="btn-primary" style={{ marginTop: 16 }} onClick={() => setPage('upload')}>
          Run Analysis
        </button>
      </div>
    )
  }

  if (loading) {
    return (
      <div style={{ textAlign: 'center', paddingTop: 80 }}>
        <div style={{ fontSize: 32, marginBottom: 12 }}>⏳</div>
        <p style={{ color: '#7f8c8d' }}>Loading report…</p>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div style={{ textAlign: 'center', paddingTop: 80, color: '#c0392b' }}>
        {error || 'Report not found'}
      </div>
    )
  }

  const sev = report.severity || 'UNKNOWN'
  const color = SEVERITY_COLORS[sev]
  const bg = SEVERITY_BG[sev]

  return (
    <div style={{ maxWidth: 900, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, marginBottom: 4 }}>
            {report.file_info?.name || 'Analysis Report'}
          </h1>
          <p style={{ fontSize: 12, color: '#7f8c8d' }}>
            {report.file_info?.format?.toUpperCase()} · Job {report.job_id?.slice(0, 8)}
            {report.file_info?.package_name ? ` · ${report.file_info.package_name}` : ''}
          </p>
        </div>
        <button className="btn-outline" style={{ fontSize: 13 }} onClick={() => setPage('upload')}>
          ← New analysis
        </button>
      </div>

      {/* Score banner */}
      <div className="card" style={{
        display: 'flex', alignItems: 'center', gap: 32,
        background: bg, border: `1.5px solid ${color}30`, marginBottom: 20,
      }}>
        <div style={{ textAlign: 'center', minWidth: 80 }}>
          <div style={{ fontSize: 42, fontWeight: 700, color, lineHeight: 1 }}>
            {report.risk_score}
          </div>
          <div style={{ fontSize: 11, color: '#7f8c8d', marginTop: 4 }}>/ 100</div>
        </div>
        <div style={{ flex: 1 }}>
          <span style={{
            display: 'inline-block', padding: '4px 14px', borderRadius: 999,
            background: color, color: 'white', fontSize: 12, fontWeight: 700,
            letterSpacing: 1, textTransform: 'uppercase', marginBottom: 8,
          }}>
            {sev}
          </span>
          <p style={{ fontSize: 14, color: '#2c3e50', lineHeight: 1.5 }}>
            {report.executive_summary}
          </p>
        </div>
      </div>

      {/* Impersonation alert */}
      {report.impersonation?.flag && (
        <div style={{
          padding: 16, borderRadius: 8, background: '#fde8e8',
          border: '1.5px solid #c0392b40', marginBottom: 20,
          display: 'flex', gap: 12, alignItems: 'flex-start',
        }}>
          <span style={{ fontSize: 20 }}>⚠️</span>
          <div>
            <p style={{ fontWeight: 600, color: '#c0392b', marginBottom: 4 }}>
              Impersonation Detected
            </p>
            <p style={{ fontSize: 13, color: '#2c3e50' }}>
              This file presents itself as <strong>{report.impersonation.matched_bank}</strong> but
              does not carry the bank's verified signing certificate.
            </p>
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>
        {/* Score breakdown */}
        <div className="card">
          <h3 style={{ fontSize: 14, marginBottom: 14 }}>Score Breakdown</h3>
          {Object.entries(report.score_breakdown || {}).map(([key, val]: [string, any]) => (
            <div key={key} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 4 }}>
                <span style={{ color: '#7f8c8d', textTransform: 'capitalize' }}>
                  {key.replace(/_/g, ' ')}
                </span>
                <span style={{ fontWeight: 600 }}>{val}</span>
              </div>
              <div style={{ height: 6, background: '#eaf0fb', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 3,
                  width: `${val}%`,
                  background: val >= 70 ? '#c0392b' : val >= 40 ? '#d68910' : '#1a7a4a',
                  transition: 'width 0.5s ease',
                }} />
              </div>
            </div>
          ))}
        </div>

        {/* Behavioral composites */}
        <div className="card">
          <h3 style={{ fontSize: 14, marginBottom: 14 }}>Behavioral Composites</h3>
          {Object.entries(report.behavioral_composites || {}).map(([key, val]: [string, any]) => {
            const active = val === true || (typeof val === 'number' && val > 0)
            return (
              <div key={key} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '7px 0', borderBottom: '1px solid #f0f2f5', fontSize: 13,
              }}>
                <span style={{ textTransform: 'capitalize', color: active ? '#c0392b' : '#7f8c8d' }}>
                  {key.replace(/_/g, ' ')}
                </span>
                <span style={{
                  fontWeight: 600,
                  color: active ? '#c0392b' : '#1a7a4a',
                }}>
                  {active ? '⚠ DETECTED' : '✓ CLEAR'}
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Attack chain */}
      {report.attack_chain && (
        <div className="card" style={{ marginBottom: 20, background: '#1a2e4a', color: 'white' }}>
          <h3 style={{ fontSize: 14, marginBottom: 10, color: '#8ab0d0' }}>Attack Chain Narrative</h3>
          <p style={{ fontSize: 13, lineHeight: 1.7, color: '#d0dff0' }}>
            {report.attack_chain}
          </p>
        </div>
      )}

      {/* Verified findings */}
      {(report.verified_findings?.length > 0 || report.inferred_findings?.length > 0) && (
        <div className="card" style={{ marginBottom: 20 }}>
          <h3 style={{ fontSize: 14, marginBottom: 16 }}>GenAI Findings</h3>

          {[
            { label: 'VERIFIED', findings: report.verified_findings, badgeClass: 'badge-verified' },
            { label: 'INFERRED / UNVERIFIED', findings: report.inferred_findings, badgeClass: 'badge-inferred' },
          ].map(({ label, findings, badgeClass }) =>
            findings?.length > 0 && (
              <div key={label} style={{ marginBottom: 16 }}>
                <p style={{ fontSize: 11, fontWeight: 700, color: '#7f8c8d',
                             textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                  {label}
                </p>
                {findings.map((f: any, i: number) => (
                  <div key={i} style={{
                    padding: '10px 12px', borderRadius: 6, marginBottom: 8,
                    background: badgeClass === 'badge-verified' ? '#f0faf4' : '#fff8e6',
                    border: `1px solid ${badgeClass === 'badge-verified' ? '#1a7a4a30' : '#d6891030'}`,
                  }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                      <span className={`badge ${badgeClass}`} style={{ marginTop: 1 }}>
                        {f.attack_class || 'OTHER'}
                      </span>
                      <p style={{ fontSize: 13, lineHeight: 1.5 }}>{f.behaviour}</p>
                    </div>
                    {f.citation && (
                      <p style={{ fontSize: 11, color: '#7f8c8d', marginTop: 6, fontFamily: 'monospace' }}>
                        {f.citation}
                      </p>
                    )}
                    <p style={{ fontSize: 11, color: '#7f8c8d', marginTop: 2 }}>
                      Confidence: {Math.round((f.confidence || 0) * 100)}%
                    </p>
                  </div>
                ))}
              </div>
            )
          )}
        </div>
      )}

      {/* Recommended actions */}
      {report.recommended_actions?.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <h3 style={{ fontSize: 14, marginBottom: 12 }}>Recommended Actions</h3>
          <ol style={{ paddingLeft: 20 }}>
            {report.recommended_actions.map((a: string, i: number) => (
              <li key={i} style={{ fontSize: 13, color: '#2c3e50', marginBottom: 8, lineHeight: 1.5 }}>
                {a}
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* CERT-In checklist */}
      {report.cert_in_checklist?.length > 0 && (
        <div className="card" style={{ marginBottom: 20, background: '#fef3e2', border: '1.5px solid #d6891040' }}>
          <h3 style={{ fontSize: 14, marginBottom: 12, color: '#d68910' }}>
            CERT-In Reporting Checklist (6-hour SLA)
          </h3>
          {report.cert_in_checklist.map((item: string, i: number) => (
            <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 8 }}>
              <input type="checkbox" style={{ marginTop: 2 }} />
              <p style={{ fontSize: 13, color: '#2c3e50', lineHeight: 1.5 }}>{item}</p>
            </div>
          ))}
        </div>
      )}

      {/* Network indicators */}
      {report.network_indicators?.length > 0 && (
        <div className="card" style={{ marginBottom: 20 }}>
          <h3 style={{ fontSize: 14, marginBottom: 12 }}>Network Indicators</h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {report.network_indicators.map((n: any, i: number) => (
              <span key={i} style={{
                padding: '4px 10px', borderRadius: 4, fontSize: 12,
                fontFamily: 'monospace', background: '#f4f5f7', color: '#2c3e50',
                border: '1px solid #d0d7e3',
              }}>
                {n.type}: {n.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Disclaimer */}
      <p style={{ fontSize: 11, color: '#7f8c8d', lineHeight: 1.6, textAlign: 'center', marginBottom: 40 }}>
        {report.disclaimer}
      </p>
    </div>
  )
}
