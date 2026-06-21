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

# ==================== GROENE BANNER ====================
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

# ==================== ALLE ORIGINELE SCAN FUNCTIES (ongewijzigd) ====================
function Get-SeverityRank {
  param([string]$Severity)
  switch ($Severity) {
    'HIGH' { return 0 }
    'MEDIUM' { return 1 }
    default { return 2 }
  }
}

function Test-MacroName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $lower = $Name.ToLowerInvariant()
  $patterns = @('autohotkey','.ahk','macro','clicker','autoclick','auto-click','doubleclick','rapidfire','tinytask','pulover','keyran','xmouse','mouse recorder','keyboard recorder','jitbit','recorder','.mcr','.amc','.macro','.tinytask','.rec','rapid fire','rapid-fire')
  foreach ($pattern in $patterns) { if ($lower.Contains($pattern)) { return $true } }
  return $false
}

# (De rest van de functies uit je originele bestand: Test-PeripheralSoftwareName, Add-Finding, Get-UserDirs, Get-ScanRoots, Search-KnownMacroProcesses, Search-PeripheralSoftware, Search-InAppMacroConfigs, Search-MacroFiles, Search-DeletedMacros, Search-AhkScriptContent, Search-Prefetch, Search-RecentJavaLogs, Write-CleanSummary, Write-RecentMacroActivity, Write-FindingTable enz.)

Write-Header
Write-ProgressBar -Percent 0 -Status 'Starting scan'

# Hier komen alle Search- calls zoals in je originele code
Search-KnownMacroProcesses
Write-ProgressBar -Percent 15 -Status 'Running processes checked'
# ... (de rest van de progress calls)

Write-Host
Write-BigResultsTitle
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
