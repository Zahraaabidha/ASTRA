import { useState, useRef, type DragEvent, type ChangeEvent } from 'react'
import axios from 'axios'

const API = 'http://localhost:8000'

const ACCEPTED = '.apk,.dex,.exe,.dll,.js,.ps1,.vbs,.doc,.docm,.xls,.xlsm,.docx,.xlsx'

interface Props {
  onJobCreated: (jobId: string) => void
}

export default function UploadPage({ onJobCreated }: Props) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleDrop = (e: DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const dropped = e.dataTransfer.files[0]
    if (dropped) setFile(dropped)
  }

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) setFile(e.target.files[0])
  }

  const handleSubmit = async () => {
    if (!file) return
    setUploading(true)
    setError(null)
    try {
      const form = new FormData()
      form.append('file', file)
      const res = await axios.post(`${API}/analyze`, form)
      const { job_id } = res.data

      // Poll until complete
      let attempts = 0
      const poll = setInterval(async () => {
        attempts++
        try {
          const status = await axios.get(`${API}/jobs/${job_id}`)
          if (status.data.status === 'complete') {
            clearInterval(poll)
            setUploading(false)
            onJobCreated(job_id)
          } else if (status.data.status === 'error') {
            clearInterval(poll)
            setUploading(false)
            setError(status.data.error || 'Analysis failed')
          }
        } catch { /* keep polling */ }
        if (attempts > 60) {
          clearInterval(poll)
          setUploading(false)
          setError('Analysis timed out. Check backend logs.')
        }
      }, 3000)
    } catch (err: any) {
      setUploading(false)
      setError(err.response?.data?.detail || err.message)
    }
  }

  return (
    <div style={{ maxWidth: 640, margin: '0 auto', paddingTop: 48 }}>
      <h1 style={{ fontSize: 28, marginBottom: 8 }}>Submit a file for analysis</h1>
      <p style={{ color: '#7f8c8d', marginBottom: 32 }}>
        ASTRA runs static extraction, Tier 1 ML classification, and Tier 2 GenAI reverse engineering
        to produce a verified investigation report.
      </p>

      <div
        className="card"
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => !file && inputRef.current?.click()}
        style={{
          border: `2px dashed ${dragging ? '#1a2e4a' : '#d0d7e3'}`,
          background: dragging ? '#eaf0fb' : '#fff',
          borderRadius: 12,
          padding: '48px 32px',
          textAlign: 'center',
          cursor: file ? 'default' : 'pointer',
          transition: 'all 0.2s ease',
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPTED}
          style={{ display: 'none' }}
          onChange={handleChange}
        />

        {!file ? (
          <>
            <div style={{ fontSize: 40, marginBottom: 12 }}>📁</div>
            <p style={{ fontWeight: 600, fontSize: 16, marginBottom: 6, color: '#1a2e4a' }}>
              Drop a file here or click to browse
            </p>
            <p style={{ color: '#7f8c8d', fontSize: 13 }}>
              APK · DEX · EXE · DLL · JS · PS1 · VBS · DOCM · XLSM
            </p>
          </>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 28 }}>🗂️</span>
              <div style={{ textAlign: 'left' }}>
                <p style={{ fontWeight: 600, color: '#1a2e4a' }}>{file.name}</p>
                <p style={{ fontSize: 12, color: '#7f8c8d' }}>
                  {(file.size / 1024).toFixed(1)} KB
                </p>
              </div>
            </div>
            <button
              className="btn-outline"
              onClick={e => { e.stopPropagation(); setFile(null) }}
              style={{ fontSize: 12 }}
            >
              Remove
            </button>
          </div>
        )}
      </div>

      {error && (
        <div style={{
          marginTop: 16, padding: 14, borderRadius: 8,
          background: '#fde8e8', color: '#c0392b', fontSize: 13,
        }}>
          {error}
        </div>
      )}

      <button
        className="btn-primary"
        onClick={handleSubmit}
        disabled={!file || uploading}
        style={{
          marginTop: 20,
          width: '100%',
          padding: '14px 0',
          fontSize: 15,
          opacity: !file || uploading ? 0.5 : 1,
          cursor: !file || uploading ? 'not-allowed' : 'pointer',
        }}
      >
        {uploading ? '⏳  Analysing… this takes up to 60 seconds' : '🔍  Run ASTRA Analysis'}
      </button>

      <div style={{ marginTop: 40 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#7f8c8d',
                     textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 }}>
          What ASTRA checks
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {[
            ['🔐', 'Certificate impersonation', 'Detects fake bank apps'],
            ['📱', 'Behavioral composites', 'OTP theft, overlay, device control'],
            ['🤖', 'GenAI deobfuscation', 'Reasons about hidden malicious logic'],
            ['✅', 'Execution verification', 'Every inference confirmed by sandbox'],
          ].map(([icon, title, desc]) => (
            <div key={title} className="card" style={{ padding: '14px 16px' }}>
              <p style={{ fontWeight: 600, fontSize: 13, color: '#1a2e4a', marginBottom: 4 }}>
                {icon} {title}
              </p>
              <p style={{ fontSize: 12, color: '#7f8c8d' }}>{desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
