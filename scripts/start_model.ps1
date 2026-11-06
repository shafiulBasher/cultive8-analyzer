# ==========================================================
# CULTIVE8 - LOCAL AI MODEL SERVER
# Model: Qwen3.5 0.8B Q4_0
# Runtime: llama.cpp
# Hardware: CPU only
# ==========================================================

$ErrorActionPreference = 'Stop'

# Locate llama.cpp server.

$server = Get-Command 'llama-server' -ErrorAction SilentlyContinue

if (-not $server) {
    throw "llama-server was not found on PATH. Open a new PowerShell window and run: Get-Command llama-server"
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor DarkGreen
Write-Host " CULTIVE8 - LOCAL AI MODEL SERVER" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor DarkGreen
Write-Host ""

Write-Host "Model: Qwen3.5 0.8B Q4_0" -ForegroundColor Cyan
Write-Host "Runtime: llama.cpp" -ForegroundColor Cyan
Write-Host "Inference: CPU only" -ForegroundColor Cyan
Write-Host "Threads: 2" -ForegroundColor Cyan
Write-Host "Context: 2048 tokens" -ForegroundColor Cyan
Write-Host "Parallel slots: 1" -ForegroundColor Cyan
Write-Host "Batch size: 128" -ForegroundColor Cyan
Write-Host "Micro-batch size: 32" -ForegroundColor Cyan
Write-Host "GPU layers: 0" -ForegroundColor Cyan
Write-Host "Reasoning: disabled" -ForegroundColor Cyan

Write-Host ""

Write-Host "Starting local model at http://127.0.0.1:8080 ..." -ForegroundColor Yellow

# Start the local model server.

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