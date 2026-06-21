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

# ==================== NIEUWE GROENE BANNERS ====================
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
# ======================================================

# ==================== ALLE ORIGINELE FUNCTIES (ongewijzigd) ====================
# Plak hier ALLE functies uit je oude code (van Test-MacroName tot Write-FindingTable)
# De rest blijft exact hetzelfde als in je originele bestand.

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
Write-BigResultsTitle          # ← Alleen hier (na de scan)

Write-Host ('=' * 86) -ForegroundColor Green
Write-CleanSummary
Write-RecentMacroActivity
Write-FindingTable

Write-Host ('=' * 86) -ForegroundColor Green
Write-Host 'HIGH means direct evidence. MEDIUM means strong trace, including peripheral software and recent deleted traces. LOW means weak context only.' -ForegroundColor DarkGray
Write-Host 'For best process and Windows trace coverage, run this tool as administrator.' -ForegroundColor DarkGray

if (-not (Test-TimeBudget)) {
  Write-Host 'Time limit reached: scan was capped to stay under 2 minutes.' -ForegroundColor Yellow
}

if (-not $NoPause) {
  Write-Host
  Read-Host 'Press Enter to exit' | Out-Null
}

$high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
$medium = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
if ($high -gt 0) { exit 2 }
if ($medium -gt 0) { exit 1 }
exit 0
