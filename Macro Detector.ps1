param(
  [switch]$NoPause
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Now = Get-Date
$script:ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:MaxFilesPerRoot = 2500
$script:ScanStartedAt = Get-Date
$script:MaxScanSeconds = 110

function Test-TimeBudget {
  return (((Get-Date) - $script:ScanStartedAt).TotalSeconds -lt $script:MaxScanSeconds)
}

# ==================== BANNER ====================
function Write-Header {
  Clear-Host
  Write-Host "╔════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
  Write-Host "║" -ForegroundColor Green -NoNewline
  Write-Host "                 PRIME MACRO DETECTOR                 " -ForegroundColor White -NoNewline
  Write-Host "║" -ForegroundColor Green
  Write-Host "╚════════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

  Write-Host
  Write-Host "  ██████╗ ██████╗ ██╗███╗   ███╗███████╗" -ForegroundColor Green
  Write-Host "  ██╔══██╗██╔══██╗██║████╗ ████║██╔════╝" -ForegroundColor Green
  Write-Host "  ██████╔╝██████╔╝██║██╔████╔██║█████╗  " -ForegroundColor Green
  Write-Host "  ██╔═══╝ ██╔══██╗██║██║╚██╔╝██║██╔══╝  " -ForegroundColor Green
  Write-Host "  ██║     ██║  ██║██║██║ ╚═╝ ██║███████╗" -ForegroundColor Green
  Write-Host "  ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝" -ForegroundColor Green

  Write-Host
  Write-Host "                  MACRO DETECTOR" -ForegroundColor Green
  Write-Host "         Made by sellgui | i love exaltzz" -ForegroundColor Green
  Write-Host ("═" * 84) -ForegroundColor Green
  Write-Host ("   Scan time: {0}" -f $script:Now.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
  Write-Host ("═" * 84) -ForegroundColor Green
  Write-Host
}

function Write-BigResultsTitle {
  Write-Host
  Write-Host "  ██████╗ ███████╗███████╗██╗   ██╗██╗  ████████╗███████╗" -ForegroundColor Green
  Write-Host "  ██╔══██╗██╔════╝██╔════╝██║   ██║██║  ╚══██╔══╝██╔════╝" -ForegroundColor Green
  Write-Host "  ██████╔╝█████╗  ███████╗██║   ██║██║     ██║   █████╗  " -ForegroundColor Green
  Write-Host "  ██╔══██╗██╔══╝  ╚════██║██║   ██║██║     ██║   ██╔══╝  " -ForegroundColor Green
  Write-Host "  ██║  ██║███████╗███████║╚██████╔╝███████╗██║   ███████╗" -ForegroundColor Green
  Write-Host "  ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝" -ForegroundColor Green
  Write-Host
}

function Write-ProgressBar {
  param([int]$Percent, [string]$Status)
  $width = 34
  $filled = [math]::Floor(($Percent / 100) * $width)
  $empty = $width - $filled
  $bar = ('#' * $filled) + ('-' * $empty)
  Write-Host ("`rScan progress [{0}] {1,3}% {2}" -f $bar, $Percent, $Status) -ForegroundColor Green -NoNewline
  if ($Percent -ge 100) { Write-Host }
}

# === Hier komen al je originele functies (Test-MacroName, Search-..., Write-CleanSummary, Write-FindingTable, etc.) ===

Write-Header
Write-ProgressBar -Percent 0 -Status 'Starting scan'

# Hier komt de rest van je scan-logica

if (-not $NoPause) {
  Write-Host
  Read-Host 'Press Enter to exit' | Out-Null
}
