# Starts the isolated ARGUS lab (Docker) and the API/UI server on http://localhost:8765
$root = Split-Path -Parent $PSScriptRoot
Push-Location "$root\lab"; docker compose up -d --build; Pop-Location
Push-Location "$root\backend"
python -m uvicorn argus.api:app --host 127.0.0.1 --port 8765
Pop-Location
