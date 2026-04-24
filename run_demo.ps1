$ErrorActionPreference = "Stop"

Write-Host "Starting AlterSpec AI Firewall demo..."
Write-Host ""

$env:ALTERSPEC_POLICY_FILE = "policies\advanced_ai_firewall_policy.yaml"

py alterspec_langchain_advanced_firewall_demo.py

Write-Host ""
Write-Host "Dashboard:"
Write-Host "http://127.0.0.1:8765/audit.html"
