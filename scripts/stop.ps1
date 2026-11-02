# Stops and removes only the ARGUS lab containers (other Docker projects are untouched)
$root = Split-Path -Parent $PSScriptRoot
Push-Location "$root\lab"; docker compose down; Pop-Location
