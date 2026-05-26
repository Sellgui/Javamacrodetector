param(
  [switch]$NoPause
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Now = Get-Date
$script:ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:MaxFilesPerRoot = 2500

function Write-RainbowText {
  param(
    [Parameter(Mandatory=$true)][string]$Text,
    [int]$Indent = 0
  )

  $colors = @('Red','Yellow','Green','Cyan','Blue','Magenta')
  if ($Indent -gt 0) { Write-Host (' ' * $Indent) -NoNewline }
  for ($i = 0; $i -lt $Text.Length; $i++) {
    $ch = $Text[$i]
    $color = $colors[$i % $colors.Count]
    Write-Host $ch -ForegroundColor $color -NoNewline
  }
  Write-Host
}

function Write-RainbowBlock {
  param([string[]]$Lines)
  foreach ($line in $Lines) { Write-RainbowText -Text $line }
}

function Write-ProgressBar {
  param(
    [int]$Percent,
    [string]$Status
  )

  $width = 34
  $filled = [math]::Floor(($Percent / 100) * $width)
  $empty = $width - $filled
  $bar = ('#' * $filled) + ('-' * $empty)
  Write-Host ("`rScan progress [{0}] {1,3}%  {2}" -f $bar, $Percent, $Status) -ForegroundColor Cyan -NoNewline
  if ($Percent -ge 100) { Write-Host }
}

function Write-BigResultsTitle {
  $title = @(
    ' ____   _____  ____   _   _  _      _____  ____',
    '|  _ \ | ____|/ ___| | | | || |    |_   _|/ ___|',
    '| |_) ||  _|  \___ \ | | | || |      | |  \___ \',
    '|  _ < | |___  ___) || |_| || |___   | |   ___) |',
    '|_| \_\|_____||____/  \___/ |_____|  |_|  |____/'
  )
  Write-RainbowBlock $title
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
    'mouse recorder','keyboard recorder','jitbit'
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
    'steelseries','steelseries gg','sonar','engine 3',
    'razer','synapse','chroma',
    'logitech','lghub','g hub','gaming software',
    'corsair','icue','cue',
    'roccat','swarm',
    'bloody','a4tech',
    'redragon',
    'glorious','model o',
    'hyperx','ngenuity',
    'asus armoury','armoury crate','asus rog',
    'msi center','dragon center',
    'cooler master','masterplus',
    'alienware','dellinc.alienwarecommandcenter',
    'pulsar','lamzu','attackshark','ajazz','darmoshark','vgn','vxe',
    'keychron','via','endgame gear','xtrfy','cherry',
    'turtle beach','zowie','finalmouse',
    'microsoft mouse','mouse and keyboard center',
    'x-mouse','xmouse',
    'mouse manager','mouse recorder','keyboard recorder',
    'macro recorder','button control'
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
  if ($Path -match '\\Macro Detector\\(Macro Detector\.(cmd|ps1)|README\.md)$') { return $true }
  return $false
}

function Add-Finding {
  param(
    [ValidateSet('HIGH','MEDIUM','LOW')][string]$Severity,
    [string]$Category,
    [string]$Evidence,
    [string]$Path = '',
    [Nullable[datetime]]$UsedAt = $null,
    [Nullable[datetime]]$ModifiedAt = $null,
    [Nullable[datetime]]$DeletedAt = $null,
    [string]$Details = ''
  )

  $existing = $null
  if ($Path) {
    $existing = $script:Findings | Where-Object {
      $_.Path -and
      $_.Path.Equals($Path, [StringComparison]::OrdinalIgnoreCase) -and
      $_.Category -notlike 'Deleted*' -and
      $Category -notlike 'Deleted*'
    } | Select-Object -First 1
  }

  if ($existing) {
    if ((Get-SeverityRank $Severity) -lt (Get-SeverityRank $existing.Severity)) {
      $existing.Severity = $Severity
      $existing.Category = $Category
      $existing.Evidence = $Evidence
    }
    if ($UsedAt -and (-not $existing.UsedAt -or $UsedAt -gt $existing.UsedAt)) { $existing.UsedAt = $UsedAt }
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
  if ($Value.PSObject.Properties.Name -contains 'Value' -and $Value.Value -is [datetime]) {
    return $Value.Value.ToString('yyyy-MM-dd HH:mm:ss')
  }
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

function Test-InterestingTextFile {
  param([string]$Path)
  $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
  return $ext -in @('.ahk','.txt','.ini','.json','.cfg','.yml','.yaml','.lua','.js','.bat','.cmd','.ps1','.vbs')
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

    foreach ($sub in @(
      'AppData\Roaming\AutoHotkey',
      'AppData\Roaming\Pulover',
      'AppData\Roaming\TinyTask',
      'AppData\Roaming\Keyran',
      'AppData\Roaming\XMouseButtonControl',
      'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
      'AppData\Local\AutoHotkey',
      'AppData\Local\Pulover',
      'AppData\Local\TinyTask',
      'AppData\Local\Keyran',
      'AppData\Local\XMouseButtonControl',
      'AppData\Local\LGHUB',
      'AppData\Local\Razer',
      'AppData\Local\Corsair',
      'AppData\Local\SteelSeries',
      'AppData\Local\Glorious Core',
      'AppData\Local\ROCCAT',
      'AppData\Local\HyperX',
      'AppData\Local\Redragon',
      'AppData\Local\Bloody',
      'AppData\Local\ASUS',
      'AppData\Roaming\Glorious Core',
      'AppData\Roaming\ROCCAT',
      'AppData\Roaming\HyperX',
      'AppData\Roaming\Redragon',
      'AppData\Roaming\Bloody',
      'AppData\Roaming\ASUS'
    )) {
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
  if ($lower -match 'asus|armoury|rog') { return 'ASUS Armoury' }
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
  if ($lower -match 'x-mouse|xmouse') { return 'X-Mouse Button Control' }
  return 'Peripheral software'
}

function Resolve-KnownPathPattern {
  param([string]$Pattern)
  $expanded = [Environment]::ExpandEnvironmentVariables($Pattern)
  if ($expanded -match '\*') {
    return @(Get-Item -Path $expanded -Force -ErrorAction SilentlyContinue)
  }
  return @(Get-Item -LiteralPath $expanded -Force -ErrorAction SilentlyContinue)
}

function Get-KnownPeripheralConfigTargets {
  $targets = @(
    @{ Vendor='Logitech'; Patterns=@('%LOCALAPPDATA%\LGHUB','%APPDATA%\LGHUB','%PROGRAMDATA%\LGHUB','%LOCALAPPDATA%\LGHUB\settings.db','%LOCALAPPDATA%\LGHUB\profiles.db','%APPDATA%\Logitech','%PROGRAMDATA%\Logitech') },
    @{ Vendor='Razer'; Patterns=@('%PROGRAMDATA%\Razer','%LOCALAPPDATA%\Razer','%APPDATA%\Razer','%PROGRAMDATA%\Razer\Synapse3','%LOCALAPPDATA%\Razer\Synapse','%LOCALAPPDATA%\Razer\Synapse\Accounts') },
    @{ Vendor='SteelSeries'; Patterns=@('%PROGRAMDATA%\SteelSeries\GG','%APPDATA%\SteelSeries\GG','%LOCALAPPDATA%\SteelSeries\GG','%APPDATA%\SteelSeries\Engine 3') },
    @{ Vendor='Corsair'; Patterns=@('%APPDATA%\Corsair\CUE','%LOCALAPPDATA%\Corsair\CUE','%PROGRAMDATA%\Corsair\CUE','%APPDATA%\Corsair\CUE\profiles','%LOCALAPPDATA%\Corsair\CUE\profiles','%PROGRAMDATA%\Corsair\CUE\profiles','%APPDATA%\Corsair\CUE\settings','%LOCALAPPDATA%\Corsair\CUE\settings','%PROGRAMDATA%\Corsair\CUE\settings') },
    @{ Vendor='HyperX'; Patterns=@('%LOCALAPPDATA%\Packages\33C30B79.HyperXNGENUITY_*','%APPDATA%\HyperX') },
    @{ Vendor='Glorious'; Patterns=@('%PROGRAMDATA%\Glorious Core','%LOCALAPPDATA%\Glorious Core') },
    @{ Vendor='ROCCAT/Turtle Beach'; Patterns=@('%APPDATA%\ROCCAT','%PROGRAMFILES%\ROCCAT','%LOCALAPPDATA%\Turtle Beach') },
    @{ Vendor='Pulsar'; Patterns=@('%LOCALAPPDATA%\Pulsar','%APPDATA%\Pulsar') },
    @{ Vendor='LAMZU'; Patterns=@('%LOCALAPPDATA%\LAMZU') },
    @{ Vendor='ASUS Armoury'; Patterns=@('%PROGRAMDATA%\ASUS','%LOCALAPPDATA%\ASUS','%APPDATA%\ASUS','%PROGRAMDATA%\ASUS\ARMOURY CRATE Config') },
    @{ Vendor='Cooler Master'; Patterns=@('%PROGRAMFILES(X86)%\Cooler Master','%APPDATA%\CoolerMaster') },
    @{ Vendor='Alienware/Dell'; Patterns=@('%PROGRAMDATA%\Alienware','%LOCALAPPDATA%\Packages\DellInc.AlienwareCommandCenter_*') },
    @{ Vendor='MSI'; Patterns=@('%PROGRAMDATA%\MSI','%LOCALAPPDATA%\MSI') },
    @{ Vendor='Redragon'; Patterns=@('%APPDATA%\Redragon','%LOCALAPPDATA%\Redragon') },
    @{ Vendor='Attack Shark'; Patterns=@('%LOCALAPPDATA%\AttackShark') },
    @{ Vendor='Ajazz'; Patterns=@('%LOCALAPPDATA%\Ajazz') },
    @{ Vendor='Darmoshark'; Patterns=@('%LOCALAPPDATA%\Darmoshark') },
    @{ Vendor='VGN/VXE'; Patterns=@('%LOCALAPPDATA%\VGN') },
    @{ Vendor='Keychron/VIA'; Patterns=@('%APPDATA%\VIA','%LOCALAPPDATA%\Keychron') },
    @{ Vendor='Endgame Gear'; Patterns=@('%LOCALAPPDATA%\Endgame Gear') },
    @{ Vendor='Microsoft Mouse & Keyboard Center'; Patterns=@('%APPDATA%\Microsoft\Mouse and Keyboard Center','%LOCALAPPDATA%\Microsoft\Mouse and Keyboard Center','%LOCALAPPDATA%\Microsoft\MouseKeyboardCenter') }
  )
  return $targets
}

function Get-LatestWriteTimeUnderPath {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
  $latest = $item.LastWriteTime
  if ($item.PSIsContainer) {
    $child = Get-ChildItem -LiteralPath $Path -Recurse -Depth 4 -Force -File -ErrorAction SilentlyContinue |
      Where-Object { -not (Test-SkipScanPath $_.FullName) } |
      Select-Object -First 600 |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 1
    if ($child -and $child.LastWriteTime -gt $latest) { $latest = $child.LastWriteTime }
  }
  return $latest
}

function Search-KnownMacroProcesses {
  $processNames = @(
    'AutoHotkey','AutoHotkeyU32','AutoHotkeyU64','AutoHotkey32','AutoHotkey64',
    'Pulover','PuloversMacroCreator','MacroRecorder','JitbitMacroRecorder',
    'TinyTask','MiniMouseMacro','MouseRecorder','KeyboardMouseRecorder',
    'Keyran','Razer Synapse','RazerSynapse','Logitech G HUB','lghub',
    'Corsair iCUE','iCUE','SteelSeriesGG','X-Mouse Button Control','XMouseButtonControl'
  )

  Get-CimInstance Win32_Process | ForEach-Object {
    $name = $_.Name
    $cmd = $_.CommandLine
    $match = $false
    foreach ($known in $processNames) {
      if ($name -like "*$known*" -or $cmd -like "*$known*") { $match = $true; break }
    }

    if ($match -or $cmd -match '\.ahk(\s|$|")') {
      $started = $null
      if ($_.CreationDate) { $started = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate) }
      Add-Finding -Severity 'HIGH' -Category 'Running macro process' -Evidence $name -Path ($_.ExecutablePath) -UsedAt $started -Details ($cmd -replace '\s+', ' ')
    }
  }
}

function Search-PeripheralSoftware {
  $runningByVendor = @{}
  Get-CimInstance Win32_Process | ForEach-Object {
    $name = $_.Name
    $cmd = $_.CommandLine
    $path = $_.ExecutablePath
    if (Test-PeripheralSoftwareName "$name $cmd $path") {
      $started = $null
      if ($_.CreationDate) { $started = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate) }
      $vendor = Get-PeripheralVendor "$name $cmd $path"
      if (-not $runningByVendor.ContainsKey($vendor)) {
        $runningByVendor[$vendor] = [pscustomobject]@{
          Vendor = $vendor
          Started = $started
          PrimaryPath = $path
          Count = 0
        }
      }
      $runningByVendor[$vendor].Count++
      if ($started -and (-not $runningByVendor[$vendor].Started -or $started -gt $runningByVendor[$vendor].Started)) {
        $runningByVendor[$vendor].Started = $started
        $runningByVendor[$vendor].PrimaryPath = $path
      }
    }
  }

  foreach ($vendor in $runningByVendor.Keys) {
    $entry = $runningByVendor[$vendor]
    Add-Finding -Severity 'MEDIUM' -Category 'Peripheral software running' -Evidence $entry.Vendor -Path $entry.PrimaryPath -UsedAt $entry.Started -Details "Running processes: $($entry.Count). Mouse/keyboard software may support custom binds or macros."
  }

  $knownConfigsByVendor = @{}
  foreach ($target in Get-KnownPeripheralConfigTargets) {
    foreach ($pattern in $target.Patterns) {
      foreach ($item in Resolve-KnownPathPattern $pattern) {
        if (-not $item) { continue }
        $latest = Get-LatestWriteTimeUnderPath $item.FullName
        if (-not $knownConfigsByVendor.ContainsKey($target.Vendor)) {
          $knownConfigsByVendor[$target.Vendor] = [pscustomobject]@{
            Vendor = $target.Vendor
            Latest = $latest
            PrimaryPath = $item.FullName
            Count = 0
            ImportantFiles = New-Object System.Collections.Generic.List[string]
          }
        }
        $knownConfigsByVendor[$target.Vendor].Count++
        if (-not $item.PSIsContainer) { $knownConfigsByVendor[$target.Vendor].ImportantFiles.Add($item.Name) | Out-Null }
        if ($latest -and (-not $knownConfigsByVendor[$target.Vendor].Latest -or $latest -gt $knownConfigsByVendor[$target.Vendor].Latest)) {
          $knownConfigsByVendor[$target.Vendor].Latest = $latest
          $knownConfigsByVendor[$target.Vendor].PrimaryPath = $item.FullName
        }
      }
    }
  }

  foreach ($vendor in $knownConfigsByVendor.Keys) {
    $entry = $knownConfigsByVendor[$vendor]
    $files = @($entry.ImportantFiles | Select-Object -Unique)
    $fileText = if ($files.Count -gt 0) { " Important files found: $($files -join ', ')." } else { '' }
    Add-Finding -Severity 'MEDIUM' -Category 'Peripheral config locations' -Evidence $entry.Vendor -Path $entry.PrimaryPath -ModifiedAt $entry.Latest -Details "Known config matches: $($entry.Count). These locations can store custom binds, profiles, macros, or cloud/cache data.$fileText"
  }

  $registryVendors = @('Logitech','LGHUB','Razer','Corsair','SteelSeries','ROCCAT','ASUS','Glorious Core','HyperX','MSI','Redragon','Pulsar','LAMZU','AttackShark','Ajazz','Darmoshark','VGN','Keychron','VIA','Alienware','Cooler Master')
  $registryByVendor = @{}
  foreach ($hive in @('HKCU:\Software','HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node')) {
    foreach ($vendor in $registryVendors) {
      $key = Join-Path $hive $vendor
      if (Test-Path -LiteralPath $key) {
        $cleanVendor = Get-PeripheralVendor $vendor
        if (-not $registryByVendor.ContainsKey($cleanVendor)) {
          $registryByVendor[$cleanVendor] = [pscustomobject]@{
            Vendor = $cleanVendor
            PrimaryPath = $key
            Count = 0
          }
        }
        $registryByVendor[$cleanVendor].Count++
      }
    }
  }

  foreach ($vendor in $registryByVendor.Keys) {
    $entry = $registryByVendor[$vendor]
    Add-Finding -Severity 'LOW' -Category 'Peripheral registry keys' -Evidence $entry.Vendor -Path $entry.PrimaryPath -Details "Registry settings keys found: $($entry.Count). Modified time is not shown because standard PowerShell does not expose reliable registry last-write time."
  }

  $roots = New-Object System.Collections.Generic.List[string]
  foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
    if ($base -and (Test-Path -LiteralPath $base)) { $roots.Add($base) | Out-Null }
  }
  foreach ($user in Get-UserDirs) {
    foreach ($sub in @('AppData\Roaming','AppData\Local','AppData\LocalLow')) {
      $p = Join-Path $user $sub
      if (Test-Path -LiteralPath $p) { $roots.Add($p) | Out-Null }
    }
  }

  $presentByVendor = @{}
  foreach ($root in $roots | Sort-Object -Unique) {
    Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
      Select-Object -First 250 |
      Where-Object { Test-PeripheralSoftwareName $_.Name } |
      ForEach-Object {
        $latest = Get-LatestWriteTimeUnderPath $_.FullName
        $vendor = Get-PeripheralVendor $_.Name
        if (-not $presentByVendor.ContainsKey($vendor)) {
          $presentByVendor[$vendor] = [pscustomobject]@{
            Vendor = $vendor
            Latest = $latest
            PrimaryPath = $_.FullName
            Paths = New-Object System.Collections.Generic.List[string]
          }
        }
        $presentByVendor[$vendor].Paths.Add($_.FullName) | Out-Null
        if ($latest -and (-not $presentByVendor[$vendor].Latest -or $latest -gt $presentByVendor[$vendor].Latest)) {
          $presentByVendor[$vendor].Latest = $latest
          $presentByVendor[$vendor].PrimaryPath = $_.FullName
        }
      }
  }

  foreach ($vendor in $presentByVendor.Keys) {
    $entry = $presentByVendor[$vendor]
    if ($knownConfigsByVendor.ContainsKey($entry.Vendor)) { continue }
    $details = "Found locations: $($entry.Paths.Count). Mouse/keyboard software can contain custom binds or macros. Check the app profile settings if this is unexpected."
    Add-Finding -Severity 'MEDIUM' -Category 'Peripheral software present' -Evidence $entry.Vendor -Path $entry.PrimaryPath -ModifiedAt $entry.Latest -Details $details
  }
}

function Search-MacroFiles {
  $allowedExtensions = @('.ahk','.exe','.msi','.bat','.cmd','.ps1','.vbs','.ini','.cfg','.json','.txt','.lua','.js')

  foreach ($root in Get-ScanRoots) {
    Get-ChildItem -LiteralPath $root.Path -Recurse -Depth $root.Depth -Force -File -ErrorAction SilentlyContinue |
      Where-Object { -not (Test-SkipScanPath $_.FullName) } |
      Select-Object -First $script:MaxFilesPerRoot |
      ForEach-Object {
        if ($_.Length -gt 25MB) { return }
        if ($script:ToolRoot -and $_.FullName.StartsWith($script:ToolRoot, [StringComparison]::OrdinalIgnoreCase)) { return }
        if (Test-OwnToolFile $_.FullName) { return }
        if ($_.Extension -and ($allowedExtensions -notcontains $_.Extension.ToLowerInvariant())) { return }
        if (-not (Test-MacroName $_.Name)) { return }

        $sev = if ($_.Extension -ieq '.ahk' -or $_.Name -match '(?i)autohotkey|tinytask|pulover|keyran|xmouse|macro|autoclick|clicker|rapidfire') { 'MEDIUM' } else { 'LOW' }
        Add-Finding -Severity $sev -Category 'Macro-related file' -Evidence $_.Name -Path $_.FullName -ModifiedAt $_.LastWriteTime -Details "Size: $([math]::Round($_.Length / 1KB, 1)) KB"
      }
    }
}

function Search-DeletedMacros {
  $cutoff = (Get-Date).AddDays(-1)
  $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' } | Select-Object -First 4

  foreach ($drive in $drives) {
    $bin = Join-Path $drive.Root '$Recycle.Bin'
    if (-not (Test-Path -LiteralPath $bin)) { continue }

    Get-ChildItem -LiteralPath $bin -Recurse -Force -File -Filter '$I*' -ErrorAction SilentlyContinue |
      Select-Object -First 500 |
      ForEach-Object {
      try {
        $bytes = [IO.File]::ReadAllBytes($_.FullName)
        if ($bytes.Length -lt 26) { return }

        $deletedFileTime = [BitConverter]::ToInt64($bytes, 16)
        if ($deletedFileTime -le 0) { return }
        $deletedAt = [DateTime]::FromFileTimeUtc($deletedFileTime).ToLocalTime()
        if ($deletedAt -lt $cutoff) { return }

        $rawPath = [Text.Encoding]::Unicode.GetString($bytes, 24, $bytes.Length - 24)
        $originalPath = $rawPath.Trim([char]0)
        $name = [IO.Path]::GetFileName($originalPath)
        if (Test-OwnToolFile $originalPath) { return }
        $isMacro = (Test-MacroName $name) -or (Test-MacroName $originalPath)
        $isPeripheral = (Test-PeripheralSoftwareName $name) -or (Test-PeripheralSoftwareName $originalPath)
        if (-not $isMacro -and -not $isPeripheral) { return }

        if ($isPeripheral -and -not $isMacro) {
          $vendor = Get-PeripheralVendor $originalPath
          Add-Finding -Severity 'MEDIUM' -Category 'Deleted peripheral software trace' -Evidence $vendor -Path $originalPath -DeletedAt $deletedAt -Details 'Deleted within the last 24 hours. Source: Windows Recycle Bin metadata.'
        } else {
          Add-Finding -Severity 'MEDIUM' -Category 'Deleted macro trace' -Evidence $name -Path $originalPath -DeletedAt $deletedAt -Details 'Deleted within the last 24 hours. Source: Windows Recycle Bin metadata.'
        }
      } catch {
        return
      }
    }
  }
}

function Search-AhkScriptContent {
  $ahkIndicators = @(
    'SendInput','SendEvent','Click','MouseClick','Loop','SetTimer','Hotkey',
    'GetKeyState','A_PriorHotkey','#IfWinActive','~LButton','~RButton',
    'XButton1','XButton2','WheelUp','WheelDown'
  )

  foreach ($root in Get-ScanRoots) {
    Get-ChildItem -LiteralPath $root.Path -Recurse -Depth $root.Depth -Force -File -Filter *.ahk -ErrorAction SilentlyContinue |
      Where-Object { -not (Test-SkipScanPath $_.FullName) } |
      Select-Object -First 300 |
      Where-Object { $_.Length -le 2MB } |
      ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { return }
        $hits = @()
        foreach ($indicator in $ahkIndicators) {
          if ($content -match [regex]::Escape($indicator)) { $hits += $indicator }
        }
        $severity = if ($hits.Count -ge 3) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding -Severity $severity -Category 'AutoHotkey script evidence' -Evidence $_.Name -Path $_.FullName -ModifiedAt $_.LastWriteTime -Details ("Indicators: " + (($hits | Select-Object -Unique) -join ', '))
      }
  }
}

function Search-Prefetch {
  $prefetch = Join-Path $env:SystemRoot 'Prefetch'
  if (-not (Test-Path -LiteralPath $prefetch)) { return }

  $patterns = @('*AUTOHOTKEY*.pf','*TINYTASK*.pf','*MACRO*.pf','*CLICKER*.pf','*PULOVER*.pf','*KEYRAN*.pf','*XMOUSE*.pf')
  foreach ($pattern in $patterns) {
    Get-ChildItem -LiteralPath $prefetch -Filter $pattern -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
      Add-Finding -Severity 'MEDIUM' -Category 'Windows execution trace' -Evidence $_.Name -Path $_.FullName -UsedAt $_.LastWriteTime -ModifiedAt $_.LastWriteTime -Details 'Prefetch timestamp is a Windows execution trace. Run as administrator for best coverage.'
    }
  }
}

function Search-MinecraftDoubleBinds {
  foreach ($user in Get-UserDirs) {
    $mc = Join-Path $user 'AppData\Roaming\.minecraft'
    if (-not (Test-Path -LiteralPath $mc)) { continue }

    $optionFiles = Get-ChildItem -LiteralPath $mc -Recurse -Force -File -Filter 'options*.txt' -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -notmatch '\\backups?\\' -and $_.Length -le 2MB }

    foreach ($file in $optionFiles) {
      $binds = @{}
      $lines = Get-Content -LiteralPath $file.FullName -ErrorAction SilentlyContinue
      foreach ($line in $lines) {
        if ($line -match '^(key_[^:]+):(.+)$') {
          $action = $matches[1]
          $key = $matches[2].Trim()
          if ([string]::IsNullOrWhiteSpace($key) -or $key -eq 'key.keyboard.unknown') { continue }
          if (-not $binds.ContainsKey($key)) { $binds[$key] = New-Object System.Collections.Generic.List[string] }
          $binds[$key].Add($action) | Out-Null
        }
      }

      $doubleBindHits = New-Object System.Collections.Generic.List[string]
      foreach ($key in $binds.Keys) {
        $actions = $binds[$key] | Select-Object -Unique
        if ($actions.Count -gt 1) {
          $doubleBindHits.Add(("{0} => {1}" -f $key, ($actions -join ', '))) | Out-Null
        }
      }

      if ($doubleBindHits.Count -gt 0) {
        $details = ($doubleBindHits | Sort-Object) -join ' ; '
        Add-Finding -Severity 'HIGH' -Category 'Minecraft Java double binds' -Evidence ("{0} duplicate key assignments" -f $doubleBindHits.Count) -Path $file.FullName -ModifiedAt $file.LastWriteTime -Details $details
      }
    }
  }
}

function Search-RecentJavaLogs {
  foreach ($user in Get-UserDirs) {
    $logRoot = Join-Path $user 'AppData\Roaming\.minecraft\logs'
    if (-not (Test-Path -LiteralPath $logRoot)) { continue }

    Get-ChildItem -LiteralPath $logRoot -Force -File -Filter '*.log' -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 5 |
      ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match '(?i)autohotkey|macro|clicker|tinytask|keyran|xmouse') {
          Add-Finding -Severity 'MEDIUM' -Category 'Minecraft log keyword hit' -Evidence $_.Name -Path $_.FullName -ModifiedAt $_.LastWriteTime -Details 'Keyword found in recent Minecraft Java log.'
        }
      }
  }
}

function Write-CleanSummary {
  $high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
  $medium = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
  $low = @($script:Findings | Where-Object Severity -eq 'LOW').Count
  $deleted = @($script:Findings | Where-Object { $_.DeletedAt }).Count
  $peripheral = @($script:Findings | Where-Object { $_.Category -like '*Peripheral*' }).Count
  $macroFiles = @($script:Findings | Where-Object { $_.Category -like '*macro*' -or $_.Category -like '*AutoHotkey*' -or $_.Category -like '*execution*' }).Count
  $doubleBinds = @($script:Findings | Where-Object { $_.Category -like '*double bind*' }).Count

  $status = if ($high -gt 0) {
    'Direct evidence found. Review HIGH results first.'
  } elseif ($medium -gt 0) {
    'Strong traces found. Review MEDIUM results and timestamps.'
  } elseif ($low -gt 0) {
    'Only weak context was found.'
  } else {
    'No strict macro evidence was found.'
  }

  Write-Host 'Clean summary' -ForegroundColor Cyan
  Write-Host ("    Verdict              : {0}" -f $status)
  Write-Host ("    Result levels        : HIGH={0}  MEDIUM={1}  LOW={2}" -f $high, $medium, $low)
  Write-Host ("    Macro-related traces : {0}" -f $macroFiles)
  Write-Host ("    Peripheral software  : {0}" -f $peripheral)
  Write-Host ("    Deleted in 24 hours  : {0}" -f $deleted)
  Write-Host ("    Double-bind configs  : {0}" -f $doubleBinds)
  Write-Host
}

function Write-FindingTable {
  $ordered = $script:Findings |
    ForEach-Object {
      $rank = Get-SeverityRank $_.Severity
      $signalAt = @($_.DeletedAt, $_.UsedAt, $_.ModifiedAt) | Where-Object { $_ -is [datetime] } | Sort-Object -Descending | Select-Object -First 1
      $_ | Add-Member -NotePropertyName Rank -NotePropertyValue $rank -Force
      $_ | Add-Member -NotePropertyName SignalAt -NotePropertyValue $signalAt -Force
      $_
    } |
    Sort-Object Rank, Category, @{ Expression = 'SignalAt'; Descending = $true }

  if (-not $ordered -or $ordered.Count -eq 0) {
    Write-Host 'No strict macro evidence was found.' -ForegroundColor Green
    Write-Host 'This does not prove the PC never used macros; it means this scan found no direct evidence in the checked locations.' -ForegroundColor DarkGray
    return
  }

  $i = 1
  foreach ($finding in $ordered) {
    $color = switch ($finding.Severity) {
      'HIGH' { 'Red' }
      'MEDIUM' { 'Yellow' }
      default { 'Gray' }
    }

    Write-Host ("[{0}] {1} | {2}" -f $i, $finding.Severity, $finding.Category) -ForegroundColor $color
    Write-Host ("    Evidence : {0}" -f $finding.Evidence)
    Write-Host ("    Used at  : {0}" -f (Format-Time $finding.UsedAt))
    Write-Host ("    Modified : {0}" -f (Format-Time $finding.ModifiedAt))
    Write-Host ("    Deleted  : {0}" -f (Format-Time $finding.DeletedAt))
    if ($finding.Path) { Write-Host ("    Path     : {0}" -f $finding.Path) }
    if ($finding.Details) { Write-Host ("    Details  : {0}" -f $finding.Details) }
    Write-Host
    $i++
  }
}

function Write-Header {
  Clear-Host
  $macroTitle = @(
    ' __  __     ___     ____   ____    ___',
    '|  \/  |   / _ \   / ___| |  _ \  / _ \',
    '| |\/| |  | |_| | | |     | |_| || | | |',
    '| |  | |  |  _  | | |___  |  _ < | |_| |',
    '|_|  |_|  |_| |_|  \____| |_| \_\ \___/'
  )
  $detectorTitle = @(
    ' ____    _____  _____  _____   ____  _____   ___   ____',
    '|  _ \  | ____||_   _|| ____| / ___||_   _| / _ \ |  _ \',
    '| | | | |  _|    | |  |  _|  | |      | |  | | | || |_| |',
    '| |_| | | |___   | |  | |___ | |___   | |  | |_| ||  _ <',
    '|____/  |_____|  |_|  |_____| \____|  |_|   \___/ |_| \_\'
  )

  Write-RainbowBlock $macroTitle
  Write-RainbowBlock $detectorTitle
  Write-Host
  Write-Host 'MACRO DETECTOR' -ForegroundColor Cyan
  Write-Host 'Made by sellgui | i love exaltzz' -ForegroundColor Cyan
  Write-Host ('=' * 86) -ForegroundColor Cyan
  Write-Host 'Only direct macro, AutoHotkey, execution trace, or Minecraft Java double-bind evidence is shown.'
  Write-Host ('Scan time: {0}' -f $script:Now.ToString('yyyy-MM-dd HH:mm:ss'))
  Write-Host ('=' * 86) -ForegroundColor Cyan
  Write-Host
}

Write-Header
Write-ProgressBar -Percent 0 -Status 'Starting scan'
Search-KnownMacroProcesses
Write-ProgressBar -Percent 15 -Status 'Running processes checked'
Search-PeripheralSoftware
Write-ProgressBar -Percent 30 -Status 'Mouse and keyboard software checked'
Search-MacroFiles
Write-ProgressBar -Percent 45 -Status 'Macro file names checked'
Search-AhkScriptContent
Write-ProgressBar -Percent 55 -Status 'Macro files and scripts checked'
Search-DeletedMacros
Write-ProgressBar -Percent 70 -Status 'Deleted traces checked'
Search-Prefetch
Write-ProgressBar -Percent 82 -Status 'Windows execution traces checked'
Search-MinecraftDoubleBinds
Write-ProgressBar -Percent 94 -Status 'Minecraft double binds checked'
Search-RecentJavaLogs
Write-ProgressBar -Percent 100 -Status 'Scan complete'

Write-Host
Write-BigResultsTitle
Write-Host ('=' * 86) -ForegroundColor Cyan
Write-CleanSummary
Write-FindingTable

Write-Host ('=' * 86) -ForegroundColor Cyan
Write-Host 'HIGH means direct evidence. MEDIUM means strong trace, including peripheral software and recent deleted traces. LOW means weak context only.' -ForegroundColor DarkGray
Write-Host 'For best process and Windows trace coverage, run this tool as administrator.' -ForegroundColor DarkGray

if (-not $NoPause) {
  Write-Host
  Read-Host 'Press Enter to exit' | Out-Null
}

$high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
$medium = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
$low = @($script:Findings | Where-Object Severity -eq 'LOW').Count

if ($high -gt 0) { exit 2 }
if ($medium -gt 0 -or $low -gt 0) { exit 1 }
exit 0
