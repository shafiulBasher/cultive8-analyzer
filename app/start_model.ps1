# Memory-conscious local Qwen3.5 server.
# Run this from the Cultive8 project root in PowerShell.
$ErrorActionPreference = 'Stop'

$server = Get-Command 'llama-server' -ErrorAction SilentlyContinue
if (-not $server) {
    throw "llama-server was not found on PATH. Open a new PowerShell window and run: Get-Command llama-server"
}

Write-Host "Starting Qwen3.5 0.8B Q4_0 on CPU at http://127.0.0.1:8080 ..." -ForegroundColor Cyan
Write-Host "Context=2048 | threads=2 | parallel=1 | batch=128 | ubatch=32 | GPU layers=0 | reasoning=off" -ForegroundColor DarkCyan

& llama-server `
    -hf 'ggml-org/Qwen3.5-0.8B-GGUF:Q4_0' `
    -c 2048 `
    -t 2 `
    -tb 2 `
    -np 1 `
    -ngl 0 `
    -b 128 `
    -ub 32 `
    --reasoning off `
    --port 8080
