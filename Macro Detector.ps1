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

# ==================== ALLE ORIGINELE FUNCTIES ====================
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

function Test-PeripheralSoftwareName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $lower = $Name.ToLowerInvariant()
  $patterns = @('steelseries','steelseries gg','sonar','engine 3','razer','synapse','chroma','logitech','lghub','g hub','gaming software','corsair','icue','cue','roccat','swarm','bloody','a4tech','redragon','glorious','model o','hyperx','ngenuity','asus armoury','armoury crate','asus rog','msi center','dragon center','cooler master','masterplus','alienware','dellinc.alienwarecommandcenter','pulsar','lamzu','attackshark','ajazz','darmoshark','vgn','vxe','keychron','via','endgame gear','xtrfy','cherry','turtle beach','zowie','finalmouse','bloody7','bloody','mad catz','mars gaming','ayax','noganet','krom','kolt','blackweb','yanpol','bycombo','by-combo','motospeed','gaming mouse','microsoft mouse','mouse and keyboard center','x-mouse','xmouse','mouse manager','mouse recorder','keyboard recorder','macro recorder','button control')
  foreach ($pattern in $patterns) { if ($lower.Contains($pattern)) { return $true } }
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

function Add-Finding {
  param(
    [ValidateSet('HIGH','MEDIUM','LOW')][string]$Severity,
    [string]$Category,
    [string]$Evidence,
    [string]$Path = '',
    [Nullable[datetime]]$UsedAt = $null,
    [Nullable[datetime]]$CreatedAt = $null,
    [Nullable[datetime]]$ModifiedAt = $null,
    [Nullable[datetime]]$DeletedAt = $null,
    [string]$Details = ''
  )
  $existing = $null
  if ($Path) {
    $existing = $script:Findings | Where-Object {
      $_.Path -and $_.Path.Equals($Path, [StringComparison]::OrdinalIgnoreCase) -and $_.Category -notlike 'Deleted*' -and $Category -notlike 'Deleted*'
    } | Select-Object -First 1
  }
  if ($existing) {
    if ((Get-SeverityRank $Severity) -lt (Get-SeverityRank $existing.Severity)) {
      $existing.Severity = $Severity
      $existing.Category = $Category
      $existing.Evidence = $Evidence
    }
    if ($UsedAt -and (-not $existing.UsedAt -or $UsedAt -gt $existing.UsedAt)) { $existing.UsedAt = $UsedAt }
    if ($CreatedAt -and (-not $existing.CreatedAt -or $CreatedAt -gt $existing.CreatedAt)) { $existing.CreatedAt = $CreatedAt }
    if ($ModifiedAt -and (-not $existing.ModifiedAt -or $ModifiedAt -gt $existing.ModifiedAt)) { $existing.ModifiedAt = $ModifiedAt }
    if ($DeletedAt -and (-not $existing.DeletedAt -or $DeletedAt -gt $existing.DeletedAt)) { $existing.DeletedAt = $DeletedAt }
    if ($Details -and $existing.Details -notlike "*$Details*") {
      $existing.Details = (($existing.Details, $Details) | Where-Object { $_ }) -join ' | '
    }
    return
  }
  $script:Findings.Add([pscustomobject]@{
    Severity = $Severity
    Category = $Category
    Evidence = $Evidence
    UsedAt = $UsedAt
    CreatedAt = $CreatedAt
    ModifiedAt = $ModifiedAt
    DeletedAt = $DeletedAt
    Path = $Path
    Details = $Details
  }) | Out-Null
}

function Format-Time {
  param($Value)
  if ($null -eq $Value) { return '-' }
  if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
  return '-'
}

function Get-UserDirs {
  $dirs = New-Object System.Collections.Generic.List[string]
  $base = Join-Path $env:SystemDrive 'Users'
  Get-ChildItem -LiteralPath $base -Directory -Force | ForEach-Object {
    if ($_.Name -notin @('Default','Default User','All Users','Public')) {
      $dirs.Add($_.FullName) | Out-Null
    }
  }
  return $dirs
}

function Get-ScanRoots {
  $roots = New-Object System.Collections.Generic.List[object]
  foreach ($user in Get-UserDirs) {
    foreach ($sub in @('Desktop','Downloads','Documents')) {
      $p = Join-Path $user $sub
      if (Test-Path -LiteralPath $p) {
        $roots.Add([pscustomobject]@{ Path = $p; Depth = 5 }) | Out-Null
      }
    }
    foreach ($sub in @('AppData\Roaming\AutoHotkey','AppData\Roaming\Pulover','AppData\Roaming\TinyTask','AppData\Roaming\Keyran','AppData\Roaming\XMouseButtonControl','AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup','AppData\Local\AutoHotkey','AppData\Local\Pulover','AppData\Local\TinyTask','AppData\Local\Keyran','AppData\Local\XMouseButtonControl','AppData\Local\LGHUB','AppData\Local\Razer','AppData\Local\Corsair','AppData\Local\SteelSeries','AppData\Local\Glorious Core','AppData\Local\ROCCAT','AppData\Local\HyperX','AppData\Local\Redragon','AppData\Local\Bloody','AppData\Local\ASUS','AppData\Roaming\Glorious Core','AppData\Roaming\ROCCAT','AppData\Roaming\HyperX','AppData\Roaming\Redragon','AppData\Roaming\Bloody','AppData\Roaming\ASUS')) {
      $p = Join-Path $user $sub
      if (Test-Path -LiteralPath $p) {
        $roots.Add([pscustomobject]@{ Path = $p; Depth = 6 }) | Out-Null
      }
    }
  }
  return $roots | Sort-Object Path -Unique
}

function Test-SkipScanPath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
  return $Path -match '\\(node_modules|\.git|\.gradle|\.m2|\.cache|cache|temp|tmp|logs|shaderpacks|resourcepacks|versions|libraries|assets|screenshots|crash-reports|processedMods)(\\|$)'
}

function Test-SkipInAppConfigPath {
  param([string]$Path)
  if (Test-SkipScanPath $Path) { return $true }
  return $Path -match '\\(depots|backup\\hotkeys|RazerCortex|DataCollectionCache|Program Files|Program Files \(x86\))(\\|$)'
}

function Get-PeripheralVendor {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return 'Unknown peripheral software' }
  $lower = $Name.ToLowerInvariant()
  if ($lower -match 'steelseries|sonar|engine 3') { return 'SteelSeries' }
  if ($lower -match 'razer|synapse|chroma') { return 'Razer' }
  if ($lower -match 'logitech|lghub|g hub|gaming software') { return 'Logitech' }
  if ($lower -match 'corsair|icue|cue') { return 'Corsair' }
  if ($lower -match 'roccat|swarm') { return 'ROCCAT' }
  if ($lower -match 'bloody|a4tech') { return 'Bloody/A4Tech' }
  if ($lower -match 'redragon') { return 'Redragon' }
  if ($lower -match 'glorious|model o') { return 'Glorious' }
  if ($lower -match 'hyperx|ngenuity') { return 'HyperX' }
  if ($lower -match 'asus|armoury|\\rog\\|/rog/') { return 'ASUS Armoury' }
  if ($lower -match 'msi|dragon center') { return 'MSI' }
  if ($lower -match 'cooler master|masterplus') { return 'Cooler Master' }
  if ($lower -match 'alienware|dellinc\.alienwarecommandcenter') { return 'Alienware/Dell' }
  if ($lower -match 'pulsar') { return 'Pulsar' }
  if ($lower -match 'lamzu') { return 'LAMZU' }
  if ($lower -match 'attackshark') { return 'Attack Shark' }
  if ($lower -match 'ajazz') { return 'Ajazz' }
  if ($lower -match 'darmoshark') { return 'Darmoshark' }
  if ($lower -match 'vgn|vxe') { return 'VGN/VXE' }
  if ($lower -match 'keychron') { return 'Keychron' }
  if ($lower -match '\\via\\|/via/|\bvia\b') { return 'VIA' }
  if ($lower -match 'endgame gear') { return 'Endgame Gear' }
  if ($lower -match 'xtrfy|cherry') { return 'Xtrfy/Cherry' }
  if ($lower -match 'turtle beach') { return 'Turtle Beach' }
  if ($lower -match 'zowie') { return 'Zowie' }
  if ($lower -match 'finalmouse') { return 'Finalmouse' }
  if ($lower -match 'microsoft mouse|mouse and keyboard center') { return 'Microsoft Mouse & Keyboard Center' }
  if ($lower -match 'bloody7|bloody') { return 'Bloody' }
  if ($lower -match 'mad catz') { return 'Mad Catz' }
  if ($lower -match 'mars gaming') { return 'Mars Gaming' }
  if ($lower -match 'ayax|noganet') { return 'AYAX/Noganet' }
  if ($lower -match 'krom|kolt') { return 'Krom' }
  if ($lower -match 'blackweb') { return 'BlackWeb' }
  if ($lower -match 'yanpol|bycombo|by-combo') { return 'YanPol/BYCOMBO' }
  if ($lower -match 'motospeed') { return 'MotoSpeed' }
  if ($lower -match 'x-mouse|xmouse') { return 'X-Mouse Button Control' }
  return 'Peripheral software'
}

function Resolve-KnownPathPattern {
  param([string]$Pattern)
  $expanded = [Environment]::ExpandEnvironmentVariables($Pattern)
  if ($expanded.StartsWith('\')) { $expanded = (Join-Path $env:SystemDrive $expanded.TrimStart('\')) }
  if ($expanded -match '\*') {
    return @(Get-Item -Path $expanded -Force -ErrorAction SilentlyContinue)
  }
  return @(Get-Item -LiteralPath $expanded -Force -ErrorAction SilentlyContinue)
}

function Get-KnownPeripheralConfigTargets {
  $targets = @(
    @{ Vendor='Logitech'; Patterns=@('%LOCALAPPDATA%\LGHUB','%APPDATA%\LGHUB','%PROGRAMDATA%\LGHUB','%LOCALAPPDATA%\LGHUB\settings.db','%LOCALAPPDATA%\LGHUB\profiles.db','%LOCALAPPDATA%\Logitech\Logitech Gaming Software','%LOCALAPPDATA%\Logitech\Logitech Gaming Software\settings.json','%APPDATA%\Logitech','%PROGRAMDATA%\Logitech') },
    @{ Vendor='Razer'; Patterns=@('%PROGRAMFILES(X86)%\Razer','%PROGRAMFILES%\Razer','%PROGRAMDATA%\Razer','%LOCALAPPDATA%\Razer','%APPDATA%\Razer','%PROGRAMDATA%\Razer\Synapse3','%PROGRAMDATA%\Razer\Synapse3\Accounts','%LOCALAPPDATA%\Razer\Synapse','%LOCALAPPDATA%\Razer\Synapse\Accounts','%LOCALAPPDATA%\Razer\Synapse3\Log') },
    @{ Vendor='SteelSeries'; Patterns=@('%PROGRAMDATA%\SteelSeries\GG','%APPDATA%\SteelSeries\GG','%LOCALAPPDATA%\SteelSeries\GG','%APPDATA%\SteelSeries\Engine 3','%LOCALAPPDATA%\steelseries-engine-3-client\Local Storage\leveldb','%LOCALAPPDATA%\SteelSeries\SteelSeries Engine 3\Local Storage\leveldb') },
    @{ Vendor='Corsair'; Patterns=@('%APPDATA%\Corsair\CUE','%LOCALAPPDATA%\Corsair\CUE','%PROGRAMDATA%\Corsair\CUE','%APPDATA%\Corsair\CUE\profiles','%LOCALAPPDATA%\Corsair\CUE\profiles','%PROGRAMDATA%\Corsair\CUE\profiles','%APPDATA%\Corsair\CUE\settings','%LOCALAPPDATA%\Corsair\CUE\settings','%PROGRAMDATA%\Corsair\CUE\settings','%APPDATA%\Corsair\CUE\Config.cuecfg','%LOCALAPPDATA%\Corsair\CUE\Config.cuecfg') },
    @{ Vendor='HyperX'; Patterns=@('%LOCALAPPDATA%\Packages\33C30B79.HyperXNGENUITY_*','%APPDATA%\HyperX') },
    @{ Vendor='Glorious'; Patterns=@('%PROGRAMDATA%\Glorious Core','%LOCALAPPDATA%\Glorious Core','%APPDATA%\BY-COMBO2','%APPDATA%\BYCOMBO-2','%APPDATA%\BYCOMBO2','%APPDATA%\BY-COMBO2\Mac','%APPDATA%\BYCOMBO-2\Mac') },
    @{ Vendor='ROCCAT/Turtle Beach'; Patterns=@('%APPDATA%\ROCCAT','%APPDATA%\ROCCAT\SWARM','%APPDATA%\ROCCAT\SWARM\macro','%APPDATA%\ROCCAT\SWARM\custom_macro_list.xml','%APPDATA%\ROCCAT\SWARM\macro_list.dat','%PROGRAMFILES%\ROCCAT','%LOCALAPPDATA%\Turtle Beach') },
    @{ Vendor='Pulsar'; Patterns=@('%LOCALAPPDATA%\Pulsar','%APPDATA%\Pulsar') },
    @{ Vendor='LAMZU'; Patterns=@('%LOCALAPPDATA%\LAMZU') },
    @{ Vendor='ASUS Armoury'; Patterns=@('%PROGRAMDATA%\ASUS','%LOCALAPPDATA%\ASUS','%APPDATA%\ASUS','%PROGRAMDATA%\ASUS\ARMOURY CRATE Config','%USERPROFILE%\Documents\ASUS\ROG\ROG Armoury\common','%USERPROFILE%\Documents\ASUS\ROG\ROG Armoury\common\Macro') },
    @{ Vendor='Cooler Master'; Patterns=@('%PROGRAMFILES(X86)%\Cooler Master','%LOCALAPPDATA%\CoolerMaster','%APPDATA%\CoolerMaster','%PROGRAMDATA%\CoolerMaster') },
    @{ Vendor='Alienware/Dell'; Patterns=@('%PROGRAMDATA%\Alienware','%LOCALAPPDATA%\Packages\DellInc.AlienwareCommandCenter_*') },
    @{ Vendor='MSI'; Patterns=@('%PROGRAMDATA%\MSI','%LOCALAPPDATA%\MSI') },
    @{ Vendor='Redragon'; Patterns=@('%APPDATA%\Redragon','%LOCALAPPDATA%\Redragon') },
    @{ Vendor='Attack Shark'; Patterns=@('%LOCALAPPDATA%\AttackShark') },
    @{ Vendor='Ajazz'; Patterns=@('%LOCALAPPDATA%\Ajazz') },
    @{ Vendor='Darmoshark'; Patterns=@('%LOCALAPPDATA%\Darmoshark') },
    @{ Vendor='VGN/VXE'; Patterns=@('%LOCALAPPDATA%\VGN') },
    @{ Vendor='Keychron/VIA'; Patterns=@('%APPDATA%\VIA','%LOCALAPPDATA%\Keychron') },
    @{ Vendor='Endgame Gear'; Patterns=@('%LOCALAPPDATA%\Endgame Gear') },
    @{ Vendor='Bloody'; Patterns=@('%PROGRAMFILES(X86)%\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros\GunLib','%APPDATA%\Bloody','%LOCALAPPDATA%\Bloody') },
    @{ Vendor='Mad Catz'; Patterns=@('%PROGRAMFILES%\Mad Catz','%PROGRAMFILES(X86)%\Mad Catz','%APPDATA%\Mad Catz','%LOCALAPPDATA%\Mad Catz') },
    @{ Vendor='Mars Gaming'; Patterns=@('%PROGRAMFILES%\Mars Gaming','%PROGRAMFILES(X86)%\Mars Gaming','%APPDATA%\Mars Gaming','%LOCALAPPDATA%\Mars Gaming') },
    @{ Vendor='AYAX/Noganet'; Patterns=@('%PROGRAMFILES%\AYAX GamingMouse','%PROGRAMFILES%\AYAX GamingMouse\record.ini','%PROGRAMFILES(X86)%\AYAX GamingMouse','%APPDATA%\AYAX','%LOCALAPPDATA%\AYAX') },
    @{ Vendor='Krom'; Patterns=@('%LOCALAPPDATA%\VirtualStore\Program Files (x86)\KROM KOLT\Config','%LOCALAPPDATA%\VirtualStore\Program Files (x86)\KROM KOLT\Config\sequence.dat','%PROGRAMFILES(X86)%\KROM KOLT\Config') },
    @{ Vendor='BlackWeb'; Patterns=@('C:\Blackweb Gaming AP\config','C:\Blackweb Gaming AP\config\*.MA32AIY') },
    @{ Vendor='MotoSpeed'; Patterns=@('%PROGRAMFILES(X86)%\MotoSpeed Gaming Mouse\V60\modules','%PROGRAMFILES(X86)%\MotoSpeed Gaming Mouse\V60\modules\Settings','%APPDATA%\MotoSpeed','%LOCALAPPDATA%\MotoSpeed') },
    @{ Vendor='Redragon Documents'; Patterns=@('%USERPROFILE%\Documents\M* Gaming Mouse','%USERPROFILE%\Documents\M* Gaming Mouse\MacroDB','%USERPROFILE%\Documents\M* Gaming Mouse\MacroDB\MacroData.db') },
    @{ Vendor='Microsoft Mouse & Keyboard Center'; Patterns=@('%APPDATA%\Microsoft\Mouse and Keyboard Center','%LOCALAPPDATA%\Microsoft\Mouse and Keyboard Center','%LOCALAPPDATA%\Microsoft\MouseKeyboardCenter') }
  )
  return $targets
}

function Search-InAppMacroConfigs { ... }   # (volledige functie uit je origineel)
function Get-LatestWriteTimeUnderPath { ... }
function Search-KnownMacroProcesses { ... }
function Search-PeripheralSoftware { ... }
function Search-MacroFiles { ... }
function Search-DeletedMacros { ... }
function Search-AhkScriptContent { ... }
function Search-Prefetch { ... }
function Search-RecentJavaLogs { ... }
function Write-CleanSummary { ... }
function Write-RecentMacroActivity { ... }
function Write-FindingTable { ... }

# ==================== START SCRIPT ====================
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

$high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
$medium = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
if ($high -gt 0) { exit 2 }
if ($medium -gt 0) { exit 1 }
exit 0
