import { useState, useEffect, useRef } from 'react'
import UploadPage from './pages/UploadPage'
import ResultsPage from './pages/ResultsPage'
import HistoryPage from './pages/HistoryPage'
import Navbar from './components/Navbar'
import './index.css'

export type Page = 'upload' | 'results' | 'history'

export default function App() {
  const [page, setPage] = useState<Page>('upload')
  const [jobId, setJobId] = useState<string | null>(null)
  const audioRef = useRef<HTMLAudioElement>(null)

  useEffect(() => {
    const audio = audioRef.current
    if (!audio) return

    audio.volume = 0.4
    const tryPlay = () => audio.play().catch(() => {})

    tryPlay()

    // Browsers block autoplay until user interaction — retry on first interaction
    const onInteract = () => {
      tryPlay()
      window.removeEventListener('click', onInteract)
      window.removeEventListener('keydown', onInteract)
    }
    window.addEventListener('click', onInteract)
    window.addEventListener('keydown', onInteract)

    return () => {
      window.removeEventListener('click', onInteract)
      window.removeEventListener('keydown', onInteract)
    }
  }, [])

  const goToResults = (id: string) => {
    setJobId(id)
    setPage('results')
  }

  return (
    <>
      <audio ref={audioRef} src="/audio/theme.mp3" loop />
      <Navbar page={page} setPage={setPage} />
      <main style={{ flex: 1, padding: '32px 40px', maxWidth: 1100, margin: '0 auto', width: '100%' }}>
        {page === 'upload' && <UploadPage onJobCreated={goToResults} />}
        {page === 'results' && <ResultsPage jobId={jobId} setPage={setPage} />}
        {page === 'history' && <HistoryPage onSelect={goToResults} />}
      </main>
    </>
  )
}
