# Starts the isolated ARGUS lab (Docker) and the API/UI server on http://localhost:8765
$root = Split-Path -Parent $PSScriptRoot
Push-Location "$root\lab"; docker compose up -d --build; Pop-Location
Start-Sleep 8; & "$root\scripts\lab_init.ps1"     # one-time DVWA database setup
Push-Location "$root\backend"
python -m uvicorn argus.api:app --host 127.0.0.1 --port 8765
Pop-Location
