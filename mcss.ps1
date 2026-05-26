param(
    [switch]$NoPause
)

$ErrorActionPreference = 'SilentlyContinue'
Set-Location -LiteralPath $PSScriptRoot

$keywords = @(
    'wurst','impact','aristois','meteor','inertia','future','rusherhack',
    'kami','lambda','salhack','bleachhack','liquidbounce','sigma','novoline',
    'astolfo','exhibition','rise','vape','drip','entropy','whiteout',
    'raven','doomsday','zeroday','flux','tenacity','moon','prestige',
    'horion','zephyr','huzuni','nodus','xray','baritone','schematica',
    'litematica','autoclicker','clicker','ghost','reach','velocity',
    'aimassist','killaura','triggerbot','esp','minimap','freecam',
    'timerresolution','selfdestruct','injector'
)

$extensions = @('.jar','.zip','.rar','.7z','.exe','.dll','.json','.txt','.cfg','.conf')
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Category,
        [int]$Severity,
        [string]$Detection,
        [string]$Location = '',
        [string]$Modified = '',
        [string]$Details = ''
    )
    $findings.Add([pscustomobject]@{
        Category = $Category
        Severity = $Severity
        Detection = $Detection
        Location = $Location
        Modified = $Modified
        Details = $Details
    }) | Out-Null
}

function Label-For {
    param([int]$Severity)
    switch ($Severity) {
        3 { '[HIGH]  ' }
        2 { '[MED]   ' }
        1 { '[LOW]   ' }
        default { '[OK]    ' }
    }
}

function Wait-IfNeeded {
    if (-not $NoPause) {
        Write-Host ''
        Read-Host 'Press Enter to close'
    }
}

function Shorten {
    param(
        [string]$Text,
        [int]$Max
    )
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return '-'
    }
    if ($Text.Length -le $Max) {
        return $Text
    }
    return '...' + $Text.Substring($Text.Length - $Max + 3)
}

function Write-DetectionTable {
    param([object[]]$Rows)

    $levelWidth = 7
    $typeWidth = 18
    $detectWidth = 20
    $dateWidth = 19
    $pathWidth = 76

    $header = "{0,-$levelWidth} {1,-$typeWidth} {2,-$detectWidth} {3,-$dateWidth} {4}" -f 'LEVEL','TYPE','DETECT','MODIFIED','LOCATION / DETAILS'
    Write-Host $header
    Write-Host ('-' * ($levelWidth + $typeWidth + $detectWidth + $dateWidth + $pathWidth + 4))

    foreach ($row in $Rows) {
        $level = (Label-For $row.Severity).Trim()
        $detect = Shorten $row.Detection $detectWidth
        $location = if ($row.Location) { $row.Location } else { $row.Details }
        $location = Shorten $location $pathWidth
        $modified = if ($row.Modified) { $row.Modified } else { '-' }

        "{0,-$levelWidth} {1,-$typeWidth} {2,-$detectWidth} {3,-$dateWidth} {4}" -f `
            $level,
            (Shorten $row.Category $typeWidth),
            $detect,
            $modified,
            $location
    }
}

function Test-Keyword {
    param([string]$Text)
    $lower = $Text.ToLowerInvariant()
    foreach ($keyword in $keywords) {
        $escaped = [regex]::Escape($keyword)
        if ($lower -match "(^|[^a-z0-9])$escaped([^a-z0-9]|$)") {
            return $keyword
        }
    }
    return $null
}

function Severity-For {
    param(
        [string]$Keyword,
        [string]$Path
    )
    $lowerPath = $Path.ToLowerInvariant()
    if (@('injector','selfdestruct','vape','drip','entropy') -contains $Keyword) {
        return 3
    }
    if ($lowerPath.Contains('\.minecraft\mods') -or $lowerPath.Contains('\.minecraft\versions')) {
        return 3
    }
    if (@('baritone','litematica','schematica','minimap') -contains $Keyword) {
        return 2
    }
    return 2
}

Write-Host 'Cheat detector'
Write-Host "Run time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host 'Mode: CMD/PowerShell quick local triage'
Write-Host ''
Write-Host 'Note: no scanner can detect every possible cheat. Use this as a fast'
Write-Host 'checklist, then manually verify anything marked HIGH or MEDIUM.'
Write-Host '------------------------------------------------------------'

try {
    $processHits = 0
    Get-Process | ForEach-Object {
        $name = $_.ProcessName
        $keyword = Test-Keyword $name
        if ($keyword) {
            $processHits++
            Add-Finding 'Processes' 3 $keyword "$name (PID $($_.Id))" '' 'Suspicious process name'
        }
    }
    if ($processHits -eq 0) {
        Add-Finding 'Processes' 0 'none' '' '' 'No known suspicious process names found.'
    }

    $locations = New-Object System.Collections.Generic.List[string]
    if ($env:APPDATA) {
        $locations.Add((Join-Path $env:APPDATA '.minecraft')) | Out-Null
        $locations.Add((Join-Path $env:APPDATA '.minecraft\mods')) | Out-Null
        $locations.Add((Join-Path $env:APPDATA '.minecraft\versions')) | Out-Null
        $locations.Add((Join-Path $env:APPDATA '.minecraft\config')) | Out-Null
        $locations.Add((Join-Path $env:APPDATA 'Badlion Client')) | Out-Null
        $locations.Add((Join-Path $env:APPDATA 'Lunar Client')) | Out-Null
        $locations.Add((Join-Path $env:APPDATA 'Feather Client')) | Out-Null
    }
    if ($env:LOCALAPPDATA) {
        $locations.Add((Join-Path $env:LOCALAPPDATA 'Temp')) | Out-Null
        $locations.Add((Join-Path $env:LOCALAPPDATA 'Programs')) | Out-Null
    }
    $locations.Add((Join-Path $env:USERPROFILE 'Downloads')) | Out-Null
    $locations.Add((Join-Path $env:USERPROFILE 'Desktop')) | Out-Null
    $locations.Add((Join-Path $env:USERPROFILE 'Documents')) | Out-Null

    $fileHits = 0
    $script:litematicaConfigReported = $false
    foreach ($location in ($locations | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $location)) {
            continue
        }

        Get-ChildItem -LiteralPath $location -Recurse -File -Force -ErrorAction SilentlyContinue |
            Select-Object -First 3500 |
            Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() } |
            ForEach-Object {
                $keyword = Test-Keyword $_.Name
                if ($keyword) {
                    if ($keyword -eq 'litematica' -and $_.FullName.ToLowerInvariant().Contains('\.minecraft\config\litematica')) {
                        if (-not $script:litematicaConfigReported) {
                            $script:litematicaConfigReported = $true
                            $fileHits++
                            Add-Finding 'Files' 2 'litematica history' "$($env:APPDATA)\.minecraft\config\litematica" '' 'Config/history folder'
                        }
                        return
                    }
                    $fileHits++
                    $severity = Severity-For $keyword $_.FullName
                    Add-Finding 'Files' $severity $keyword $_.FullName $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') 'Keyword in filename'
                }
            }
    }
    if ($fileHits -eq 0) {
        Add-Finding 'Files' 0 'none' '' '' 'No suspicious cheat keywords found in scanned locations.'
    }

    $javaHits = 0
    Get-CimInstance Win32_Process -Filter "name='javaw.exe' or name='java.exe'" | ForEach-Object {
        $commandLine = [string]$_.CommandLine
        $keyword = Test-Keyword $commandLine
        if ($keyword) {
            $javaHits++
            Add-Finding 'Java command line' 3 $keyword $commandLine '' 'Running Java command contains keyword'
        }
    }
    if ($javaHits -eq 0) {
        Add-Finding 'Java command line' 0 'none' '' '' 'No suspicious running Java command lines found.'
    }

    $established = (netstat -ano | Select-String -Pattern 'ESTABLISHED').Count
    if ($established -gt 80) {
        Add-Finding 'Network' 1 'connection count' '' '' "High established network connection count: $established"
    }
    else {
        Add-Finding 'Network' 0 'connection count' '' '' "Established network connections: $established"
    }

    $maxShown = 120
    $displayFindings = @($findings |
        Sort-Object @{ Expression = 'Severity'; Descending = $true }, Category, Detection, Location |
        Select-Object -First $maxShown)

    Write-Host ''
    Write-DetectionTable $displayFindings

    $high = ($findings | Where-Object Severity -eq 3).Count
    $medium = ($findings | Where-Object Severity -eq 2).Count
    $low = ($findings | Where-Object Severity -eq 1).Count

    Write-Host ''
    Write-Host '------------------------------------------------------------'
    Write-Host "Summary: HIGH=$high MEDIUM=$medium LOW=$low"
    if ($findings.Count -gt $maxShown) {
        Write-Host "Showing first $maxShown findings. Total findings: $($findings.Count)"
    }
    if ($high -gt 0) {
    Write-Host 'Result: investigate immediately. Ask for manual proof and check paths/processes.'
    }
    elseif ($medium -gt 0) {
        Write-Host 'Result: suspicious items found. Verify whether they are allowed on your server.'
    }
    else {
        Write-Host 'Result: no obvious cheat indicators found in this quick scan.'
    }

    Wait-IfNeeded
    exit 0
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Wait-IfNeeded
    exit 1
}
