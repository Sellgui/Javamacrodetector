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

# ==================== GROENE BANNER (Alleen dit is aangepast) ====================
function Write-Header {
  Clear-Host
  Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
  Write-Host "║" -ForegroundColor Green -NoNewline
  Write-Host "                          MACRO DETECTOR                                      " -ForegroundColor White -NoNewline
  Write-Host "║" -ForegroundColor Green
  Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
  
  Write-Host
  Write-Host 'MACRO DETECTOR' -ForegroundColor Green
  Write-Host 'Made by sellgui | i love exaltzz' -ForegroundColor Green
  Write-Host ('=' * 80) -ForegroundColor Green
  Write-Host 'Only direct macro, AutoHotkey, peripheral software, and execution trace evidence is shown.' -ForegroundColor White
  Write-Host 'Scan time limit: 2 minutes. Heavy folders are safely capped for speed.' -ForegroundColor DarkGray
  Write-Host ('Scan time: {0}' -f $script:Now.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
  Write-Host ('=' * 80) -ForegroundColor Green
  Write-Host
}
# =================================================================================

function Write-ProgressBar {
  param(
    [int]$Percent,
    [string]$Status
  )
  $width = 34
  $filled = [math]::Floor(($Percent / 100) * $width)
  $empty = $width - $filled
  $bar = ('#' * $filled) + ('-' * $empty)
  Write-Host ("`rScan progress [{0}] {1,3}% {2}" -f $bar, $Percent, $Status) -ForegroundColor Green -NoNewline
  if ($Percent -ge 100) { Write-Host }
}

function Write-BigResultsTitle {
  $title = @(
    ' ____ _____ ____ _ _ _ _____ ____',
    '| _ \ | ____|/ ___| | | | || | |_ _|/ ___|',
    '| |_) || _| \___ \ | | | || | | | \___ \',
    '| _ < | |___ ___) || |_| || |___ | | ___) |',
    '|_| \_\|_____||____/ \___/ |_____| |_| |____/'
  )
  foreach ($line in $title) { Write-Host $line -ForegroundColor Green }
}

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
  $patterns = @(
    'autohotkey','.ahk','macro','clicker','autoclick','auto-click',
    'doubleclick','rapidfire','tinytask','pulover','keyran','xmouse',
    'mouse recorder','keyboard recorder','jitbit','recorder',
    '.mcr','.amc','.macro','.tinytask','.rec','rapid fire','rapid-fire'
  )
  foreach ($pattern in $patterns) {
    if ($lower.Contains($pattern)) { return $true }
  }
  return $false
}

function Test-PeripheralSoftwareName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $lower = $Name.ToLowerInvariant()
  $patterns = @(
    'steelseries','razer','logitech','corsair','roccat','bloody','redragon','glorious','hyperx',
    'asus','msi','cooler master','alienware','pulsar','lamzu','keychron','via','endgame gear',
    'xtrfy','cherry','turtle beach','zowie','finalmouse','microsoft mouse'
  )
  foreach ($pattern in $patterns) {
    if ($lower.Contains($pattern)) { return $true }
  }
  return $false
}

function Test-OwnToolFile {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  $name = [IO.Path]::GetFileName($Path)
  if ($name -match '^(Macro Detector)\.(cmd|ps1|zip)$') { return $true }
  if ($Path -match '\\Macro Detector\\') { return $true }
  return $false
}

function Add-Finding { ... }   # (de rest is exact hetzelfde als origineel)

# De rest van de code (Search functies, Write-CleanSummary, Write-FindingTable, etc.) is ongewijzigd.

# Start het script
Write-Header
Write-ProgressBar -Percent 0 -Status 'Starting scan'

# ... (alle Search- calls en einde van het script blijven exact hetzelfde als in de originele versie die je mij gaf)
