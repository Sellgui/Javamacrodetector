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

function Write-ProgressBar {
  param([int]$Percent, [string]$Status)
  $width = 34
  $filled = [math]::Floor(($Percent / 100) * $width)
  $empty = $width - $filled
  $bar = ('#' * $filled) + ('-' * $empty)
  Write-Host ("`rScan progress [{0}] {1,3}% {2}" -f $bar, $Percent, $Status) -ForegroundColor Green -NoNewline
  if ($Percent -ge 100) { Write-Host }
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

# ==================== ORIGINELE SCAN FUNCTIES (ongewijzigd) ====================
# (Plak hier alle functies uit je originele bestand: Get-SeverityRank, Test-MacroName, Test-PeripheralSoftwareName, Add-Finding, Get-UserDirs, Get-ScanRoots, Search-KnownMacroProcesses, etc.)

Write-Header
Write-ProgressBar -Percent 0 -Status 'Starting scan'

Search-KnownMacroProcesses
Write-ProgressBar -Percent 15 -Status 'Running processes checked'
Search-PeripheralSoftware
Write-ProgressBar -Percent 30 -Status 'Mouse and keyboard software checked'
Search-InAppMacroConfigs
Write-ProgressBar -Percent 40 -Status 'In-app macro configs checked'
Search-MacroFiles
Write-ProgressBar -Percent 50 -Status 'Macro file names checked'
Search-AhkScriptContent
Write-ProgressBar -Percent 60 -Status 'Macro files and scripts checked'
Search-DeletedMacros
Write-ProgressBar -Percent 70 -Status 'Deleted traces checked'
Search-Prefetch
Write-ProgressBar -Percent 88 -Status 'Windows execution traces checked'
Search-RecentJavaLogs
Write-ProgressBar -Percent 100 -Status 'Scan complete'

Write-Host
Write-BigResultsTitle   # <-- Nu alleen hier (na de scan)

Write-Host ('=' * 86) -ForegroundColor Green
Write-CleanSummary
Write-RecentMacroActivity
Write-FindingTable

Write-Host ('=' * 86) -ForegroundColor Green
Write-Host 'HIGH means direct evidence. MEDIUM means strong trace...' -ForegroundColor DarkGray

if (-not $NoPause) {
  Write-Host
  Read-Host 'Press Enter to exit' | Out-Null
}
