# Run from the project root: .\start_backend.ps1
$root = $PSScriptRoot
$python = "$root\venv\Scripts\python.exe"
$uvicorn = "$root\venv\Scripts\uvicorn.exe"

# Load .env
if (Test-Path "$root\.env") {
    Get-Content "$root\.env" | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.+)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
}

$env:PYTHONPATH = $root

Write-Host "Starting ASTRA backend on http://localhost:8000" -ForegroundColor Cyan
& $uvicorn backend.api.main:app --reload --port 8000 --host 0.0.0.0
