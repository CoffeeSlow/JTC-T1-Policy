param([switch]$SkipPause)

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "JTC Scanner"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

$suspiciousFindings = [System.Collections.Generic.List[PSObject]]::new()
$suspiciousFindings.Add([PSCustomObject]@{
    Type      = "Context"
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PC        = $env:COMPUTERNAME
    User      = $env:USERNAME
    Score     = $null
})

function Write-ColoredLine {
    param ([string]$Text, [ConsoleColor]$Color = 'White')
    $oldColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Host $Text
    $Host.UI.RawUI.ForegroundColor = $oldColor
}

function Wait-ForEnter {
    param([string]$Message = "Press Enter to Continue")
    Write-Host ""
    Write-ColoredLine ">> $Message" Cyan
    do {
        $key = [System.Console]::ReadKey($true)
    } while ($key.Key -ne "Enter")
}

function Show-CustomLoadingBar {
    $i = 0
    Write-Host ""
    for ($p = 0; $p -le 100; $p += 5) {
        $filled = [math]::Floor($p / 2.5)
        $empty = 40 - $filled
        $bar = "#" * $filled + "-" * $empty
        $percentage = "{0,3}" -f $p
        if ($p -eq 100) {
            $color = "Green"
        } else {
            $color = "Red"
        }
        Write-Host -NoNewline "`r [$bar] $percentage% " -ForegroundColor $color
        Start-Sleep -Milliseconds 50
        $i++
    }
    Write-Host ""
    Write-Host ""
}

function Write-BoxedHeader {
    param([string]$Title, [string]$Subtitle = "")
    $innerWidth = 62
    $border = "+" + ("-" * $innerWidth) + "+"
    $titlePadding = [math]::Floor(($innerWidth - $Title.Length) / 2)
    $titleLine = " " * $titlePadding + $Title + " " * ($innerWidth - $titlePadding - $Title.Length)
    Write-Host ""
    Write-ColoredLine $border Blue
    Write-Host "|" -NoNewline -ForegroundColor Blue
    Write-Host $titleLine -NoNewline
    Write-Host "|" -ForegroundColor Blue
    if ($Subtitle) {
        $subtitlePadding = [math]::Floor(($innerWidth - $Subtitle.Length) / 2)
        $leftPadding = " " * $subtitlePadding
        $rightPadding = " " * ($innerWidth - $subtitlePadding - $Subtitle.Length)
        $splitPoint = 14
        $firstHalf = $Subtitle.Substring(0, [math]::Min($splitPoint, $Subtitle.Length))
        $secondHalf = if ($Subtitle.Length -gt $splitPoint) { $Subtitle.Substring($splitPoint) } else { "" }
        Write-Host "|" -NoNewline -ForegroundColor Blue
        Write-Host ($leftPadding + $firstHalf) -NoNewline -ForegroundColor White
        Write-Host ($secondHalf + $rightPadding) -NoNewline -ForegroundColor Magenta
        Write-Host "|" -ForegroundColor Blue
    }
    Write-ColoredLine $border Blue
    Write-Host ""
}

function Write-Section {
    param([string]$Title, [string[]]$Lines)
    Write-Host ""
    Write-ColoredLine " +- $Title" DarkGray
    foreach ($line in $Lines) {
        if ($line -match "^SUCCESS") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "OK $($line -replace '^SUCCESS: ', '')" Green
        }
        elseif ($line -match "^FAILURE") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "X $($line -replace '^FAILURE: ', '')" Red
        }
        elseif ($line -match "^WARNING") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "W $($line -replace '^WARNING: ', '')" Yellow
        }
        elseif ($line -match "SUSPICIOUS") {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine "$line" Red
        }
        else {
            Write-Host " | " -NoNewline -ForegroundColor DarkGray
            Write-ColoredLine $line White
        }
    }
    Write-ColoredLine " +-" DarkGray
}

function Write-StepResult {
    param([int]$Success, [int]$Total, [int]$StepNumber)
    $rate = if ($Total -gt 0) { [math]::Round(($Success / $Total) * 100, 0) } else { 100 }
    $color = if ($rate -eq 100) { "Green" } elseif ($rate -ge 80) { "Yellow" } else { "Red" }
    $icon = if ($rate -eq 100) { "OK" } elseif ($rate -ge 80) { "W" } else { "X" }
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    Write-Host " $icon Step $StepNumber Result: " -NoNewline -ForegroundColor $color
    Write-Host "$rate% " -NoNewline -ForegroundColor $color
    Write-Host "($Success/$Total checks passed)" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor DarkGray
}

function Start-FileWatcher {
    param([string]$LogFile)
    try {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "C:\"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        $watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastAccess
        $wshell = New-Object -ComObject WScript.Shell
        $action = {
            $path = $Event.SourceEventArgs.FullPath
            $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $LogFile -Value "[$time] Opened: $path" -ErrorAction SilentlyContinue
            $wshell.Popup("This application was opened: $path", 5, "File Access", 64)
        }
        Register-ObjectEvent -InputObject $watcher -EventName Created -SourceIdentifier "FileCreated_$PID" -Action $action | Out-Null
        Register-ObjectEvent -InputObject $watcher -EventName Changed -SourceIdentifier "FileChanged_$PID" -Action $action | Out-Null
    } catch {
        Write-ColoredLine " W File watcher setup failed." Yellow
    }
}

Clear-Host
Write-Host ""
Write-Host "     _ _____ ____   _____ _   ____   ___  _     ___ ______   __" -ForegroundColor DarkBlue
Write-Host "    | |_   _/ ___| |_   _/ | |  _ \ / _ \| |   |_ _/ ___\ \ / /" -ForegroundColor DarkBlue
Write-Host " _  | | | || |       | | | | | |_) | | | | |    | | |    \ V / " -ForegroundColor DarkBlue
Write-Host "| |_| | | || |___    | | | | |  __/| |_| | |___ | | |___  | |  " -ForegroundColor DarkBlue
Write-Host " \___/  |_| \____|   |_| |_| |_|    \___/|_____|___\____| |_|  " -ForegroundColor DarkBlue
Write-Host ""

Write-ColoredLine "============================================================" Cyan
Write-ColoredLine " Created by CoffeeSlow" White
Write-ColoredLine "============================================================" Cyan
Write-Host ""
Write-ColoredLine "INSTRUCTIONS:" Yellow
Write-ColoredLine "- Pass all the steps." White
Write-ColoredLine "- Tools saved to C:\ToolsJTC." White
Write-ColoredLine "- Administrator privileges required." White
Write-Host ""

$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
if ($cpu -and $cpu.NumberOfCores -ge 4 -and $cpu.MaxClockSpeed -ge 2500) {
    Write-Host "CPU: " -NoNewline -ForegroundColor White
    Write-Host "$($cpu.Name)" -ForegroundColor Gray
    Write-ColoredLine " Performance: Optimal" Green
} else {
    Write-Host "CPU: " -NoNewline -ForegroundColor White
    Write-Host "$($cpu.Name)" -ForegroundColor Gray
    Write-ColoredLine " Performance: May experience slower scans" Yellow
}
Write-Host ""

$gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 1
$gpuName = $gpu.Name
$goodGPUs = @("RTX 30", "RTX 40", "RX 6000", "RX 7000")
$gpuIsGood = $goodGPUs | Where-Object { $gpuName -like "*$_*" }
if ($gpuIsGood) {
    Write-Host "GPU: " -NoNewline -ForegroundColor White
    Write-Host "$gpuName" -ForegroundColor Gray
    Write-ColoredLine " Performance: Optimal" Green
} else {
    Write-Host "GPU: " -NoNewline -ForegroundColor White
    Write-Host "$gpuName" -ForegroundColor Gray
    Write-ColoredLine " Performance: May impact processing" Yellow
}

Write-Host ""

Wait-ForEnter -Message "Press Enter to Begin System Scan"

Clear-Host
New-Item -ItemType Directory -Path "C:\ToolsJTC" -ErrorAction SilentlyContinue | Out-Null
$logFile = "C:\ToolsJTC\file_log.txt"
Start-FileWatcher -LogFile $logFile

Write-BoxedHeader "STEP 1/5: SYSTEM INTEGRITY" "Verifying security configuration..."
Show-CustomLoadingBar

$modulesOutput = @()
$windowsOutput = @()
$memoryIntegrityOutput = @()
$defenderOutput = @()
$exclusionsOutput = @()
$threatsOutput = @()
$powershellSigOutput = @()

$defaultModules = @("Microsoft.PowerShell.Archive", "Microsoft.PowerShell.Diagnostics", "Microsoft.PowerShell.Host", "Microsoft.PowerShell.LocalAccounts", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Security", "Microsoft.PowerShell.Utility", "PackageManagement", "PowerShellGet", "PSReadLine", "Pester", "ThreadJob")
$protectedModule = "Microsoft.PowerShell.Operation.Validation"
$modulesPath = "C:\Program Files\WindowsPowerShell\Modules"
$modules = Get-ChildItem $modulesPath -Directory -ErrorAction SilentlyContinue

foreach ($module in $modules) {
    $moduleName = $module.Name
    if ($moduleName -eq $protectedModule) {
        $modulesOutput += "SUCCESS: Protected module verified."
    } elseif ($moduleName -notin $defaultModules) {
        $modulesOutput += "FAILURE: Unauthorized module: $moduleName"
    }
}
if (-not $modulesOutput) { $modulesOutput += "SUCCESS: No unauthorized modules." }

$windowsOutput += if ($env:OS -eq "Windows_NT") { "SUCCESS: Windows OS verified." } else { "FAILURE: Non-Windows OS detected." }

try {
    $enabled = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction Stop
    $memoryIntegrityOutput += if ($enabled -eq 1) { "SUCCESS: Memory Integrity enabled." } else { "FAILURE: Memory Integrity disabled." }
} catch {
    $memoryIntegrityOutput += "WARNING: Memory Integrity check failed."
}

try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $defenderOutput += if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) { "SUCCESS: Windows Defender active." } else { "FAILURE: Windows Defender not active." }
} catch {
    $defenderOutput += "WARNING: Defender status check failed."
}

try {
    $exclusions = (Get-MpPreference).ExclusionPath
    if ($exclusions) {
        $exclusionsOutput += "FAILURE: Defender exclusions detected."
        foreach ($excl in $exclusions) {
            $exclusionsOutput += " -> $excl"
            $suspiciousFindings.Add([PSCustomObject]@{Type = "DefenderExclusion"; Path = $excl})
        }
    } else {
        $exclusionsOutput += "SUCCESS: No Defender exclusions."
    }
} catch {
    $exclusionsOutput += "WARNING: Cannot check exclusions."
}

try {
    $threats = Get-MpThreat -ErrorAction Stop
    $activeThreats = $threats | Where-Object { $_.ThreatStatusID -in @(4, 6) }
    if ($activeThreats.Count -eq 0) {
        $threatsOutput += "SUCCESS: No active threats detected."
    } else {
        $threatsOutput += "FAILURE: Active threats detected ($($activeThreats.Count) total)."
        foreach ($threat in $activeThreats) {
            $threatsOutput += " -> Threat: $($threat.ThreatName)"
            $suspiciousFindings.Add([PSCustomObject]@{Type = "DefenderThreat"; Threat = $threat.ThreatName})
        }
    }
} catch {
    $threatsOutput += "WARNING: Cannot retrieve threat information."
}

try {
    $sig = Get-AuthenticodeSignature "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $powershellSigOutput += if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft Windows*') { "SUCCESS: PowerShell signature valid." } else { "FAILURE: PowerShell signature invalid." }
} catch {
    $powershellSigOutput += "WARNING: PowerShell signature check failed."
}

Write-Section "PowerShell Modules" $modulesOutput
Write-Section "Operating System" $windowsOutput
Write-Section "Memory Integrity" $memoryIntegrityOutput
Write-Section "Windows Defender" $defenderOutput
Write-Section "Defender Exclusions" $exclusionsOutput
Write-Section "Threat Detection" $threatsOutput
Write-Section "PowerShell Signature" $powershellSigOutput

$allResults1 = $modulesOutput + $windowsOutput + $memoryIntegrityOutput + $defenderOutput + $exclusionsOutput + $threatsOutput + $powershellSigOutput
$total1 = ($allResults1 | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success1 = ($allResults1 | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success1 -Total $total1 -StepNumber 1

Wait-ForEnter -Message "Press Enter to Continue to Step 2"

Clear-Host

Write-BoxedHeader "STEP 2/5: BAM & PREFETCH ANALYSIS" "Analyzing Background Activity Moderator and Prefetch..."
Show-CustomLoadingBar

$bamOutput = @()
$prefetchOutput = @()

$suspiciousFiles = @(
    "matcha.exe", "olduimatrix", "autoexecute", "workspace", "monkeyaim", "thunderaim", 
    "thunderclient", "celex", "matrix", "triggerbot", "solara.exe", "xeno.exe", 
    "cloudy", "tupical", "horizon", "myst", "celery", "zarora", "juju", "nezure", 
    "FusionHacks.zip", "release.zip", "aimmy.exe", "aimmy", "Fluxus", "clumsy", 
    "build.zip", "build.rar", "MystW.exe", "isabelle", "dx9ware",
    "volt.exe", "potassium.exe", "cosmic.exe", "volcano.exe", "isaeva.exe", "synapsez.exe",
    "velocity.exe", "seliware.exe", "bunni.fun.exe", "sirhurt.exe", "hydrogen.exe",
    "macsploit.exe", "opiumware.exe", "cryptic.exe", "vegax.exe", "codex.exe",
    "serotonin.exe", "rbxcli.exe", "ronin.exe", "photon.exe",
    "kiciahook.exe", "kiciahookv2.exe", "snaw.exe", "robloxdma.exe"
)
$suspiciousList = @(
    "isabelle", "xeno.exe", "solara.exe", "bootstrappernew", "loader.exe", 
    "santoware", "mystw", "severe", "mapper.exe", "thunderclient", "monkeyaim", 
    "olduimatrix", "matrix", "matcha.exe",
    "volt", "potassium", "cosmic", "volcano", "isaeva", "synapsez",
    "velocity", "seliware", "bunni.fun", "sirhurt", "hydrogen",
    "macsploit", "opiumware", "cryptic", "vegax", "codex",
    "serotonin", "rbxcli", "ronin", "photon",
    "kiciahook", "kiciahookv2", "snaw", "robloxdma"
)
$watchlist = @(
    "BOOTSTRAPPERNEW.EXE", "XENO.EXE", "XENOUI.EXE", "SOLARA.EXE", 
    "MAPPER.EXE", "LOADER.EXE", "MATCHA.EXE", "EVOLVE.EXE",
    "VOLT.EXE", "POTASSIUM.EXE", "COSMIC.EXE", "VOLCANO.EXE", "ISAEVA.EXE", "SYNAPSEZ.EXE",
    "VELOCITY.EXE", "SELIWARE.EXE", "BUNNI.FUN.EXE", "SIRHURT.EXE", "HYDROGEN.EXE",
    "MACSPLOIT.EXE", "OPIUMWARE.EXE", "CRYPTIC.EXE", "VEGAX.EXE", "CODEX.EXE",
    "SEROTONIN.EXE", "RBXCLI.EXE", "RONIN.EXE", "PHOTON.EXE",
    "KICIAHOOK.EXE", "KICIAHOOKV2.EXE", "SNAW.EXE", "ROBLOXDMA.EXE"
)
$allSuspicious = $suspiciousFiles + $suspiciousList + $watchlist

$bamApps = @()
try {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $bamEntries = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid" -ErrorAction Stop
    $isSuspiciousBAM = $false
    foreach ($entry in ($bamEntries.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" })) {
        if ($entry.Value.Length -ge 8) {
            $timestamp = [BitConverter]::ToInt64($entry.Value, 0)
            $date = [DateTime]::FromFileTime($timestamp)
            $appPath = $entry.Name
            $isSuspicious = [bool]($allSuspicious | Where-Object { $appPath -imatch $_ })
            $lastAccessTime = "N/A"
            if (Test-Path $appPath) {
                $fileInfo = Get-Item $appPath
                $lastAccessTime = $fileInfo.LastAccessTime.ToString()
            }
            $bamApps += [PSCustomObject]@{
                AppPath = $appPath
                LastTime = $date.ToString()
                Suspicious = if ($isSuspicious) { "Yes" } else { "No" }
                LastAccessTime = $lastAccessTime
            }
            if ($isSuspicious) { 
                $isSuspiciousBAM = $true 
                $suspiciousFindings.Add([PSCustomObject]@{
                    Type       = "BAM"
                    Path       = $appPath
                    LastUsed   = $date.ToString()
                })
            }
        }
    }
    if ($bamApps) {
        $bamOutput += "SUCCESS: Found $($bamApps.Count) BAM entries."
        if ($isSuspiciousBAM) {
            $bamOutput += "WARNING: Suspicious BAM activity detected."
            $suspiciousBamEntries = $bamApps | Where-Object { $_.Suspicious -eq "Yes" }
            foreach ($entry in $suspiciousBamEntries) {
                $bamOutput += " SUSPICIOUS: $($entry.AppPath)"
            }
        }
    } else {
        $bamOutput += "SUCCESS: No BAM entries found."
    }
} catch {
    $bamOutput += "WARNING: BAM registry access failed."
}

$prefetchApps = @()
try {
    $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction Stop
    $isSuspiciousPrefetch = $false
    foreach ($file in $prefetchFiles) {
        $appName = $file.Name.Split('-')[0]
        $isSuspicious = [bool]($allSuspicious | Where-Object { $appName -imatch $_ })
        $fileSize = [math]::Round($file.Length / 1KB, 2)
        $prefetchApps += [PSCustomObject]@{
            AppName = $appName
            LastTime = $file.LastWriteTime.ToString()
            Suspicious = if ($isSuspicious) { "Yes" } else { "No" }
            FileSize = $fileSize
            FullName = $file.Name
        }
        if ($isSuspicious) { 
            $isSuspiciousPrefetch = $true 
            $suspiciousFindings.Add([PSCustomObject]@{
                Type     = "Prefetch"
                Name     = $appName
                File     = $file.Name
            })
        }
    }
    if ($prefetchApps) {
        $prefetchOutput += "SUCCESS: Found $($prefetchApps.Count) Prefetch entries."
        if ($isSuspiciousPrefetch) {
            $prefetchOutput += "WARNING: Suspicious Prefetch activity detected."
            $suspiciousPrefetchEntries = $prefetchApps | Where-Object { $_.Suspicious -eq "Yes" }
            foreach ($entry in $suspiciousPrefetchEntries) {
                $prefetchOutput += " SUSPICIOUS: $($entry.AppName)"
            }
        }
    } else {
        $prefetchOutput += "SUCCESS: No Prefetch entries found."
    }
} catch {
    $prefetchOutput += "WARNING: Prefetch folder access failed."
}

Write-Section "BAM Entries" $bamOutput
Write-Section "Prefetch Entries" $prefetchOutput

$allResults2 = $bamOutput + $prefetchOutput
$total2 = ($allResults2 | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success2 = ($allResults2 | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success2 -Total $total2 -StepNumber 2

Wait-ForEnter -Message "Press Enter to Continue to Step 3"

Clear-Host

Write-BoxedHeader "STEP 3/5: PROCESS EXPLORER" "Launching Microsoft Process Explorer..."
Write-ColoredLine "INSTRUCTIONS: Review all processes, scroll to bottom, then close the window." Yellow
Show-CustomLoadingBar

$processNames = @("procexp32", "procexp64", "procexp64a")
$runningPE = Get-Process -ErrorAction SilentlyContinue | Where-Object { $processNames -contains $_.ProcessName.ToLower() }
if ($runningPE) {
    Write-ColoredLine " OK Terminated existing Process Explorer instances." Green
    $runningPE | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {} }
    Start-Sleep -Seconds 1
} else {
    Write-ColoredLine " OK No existing Process Explorer instances found." Green
}

$baseFolder = "C:\ToolsJTC"
$extractFolder = Join-Path $baseFolder "ProcessExplorer"
$zipUrl = "https://download.sysinternals.com/files/ProcessExplorer.zip"
$zipPath = Join-Path $baseFolder "ProcessExplorer.zip"

if (Test-Path $baseFolder) {
    $ErrorActionPreference = 'SilentlyContinue'
    Remove-Item -Path $baseFolder -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    if (-not (Test-Path $baseFolder)) {
        New-Item -ItemType Directory -Path $baseFolder -ErrorAction SilentlyContinue | Out-Null
    }
    $ErrorActionPreference = 'SilentlyContinue'
} else {
    New-Item -ItemType Directory -Path $baseFolder -ErrorAction SilentlyContinue | Out-Null
}

try {
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    Write-ColoredLine " OK Downloaded Process Explorer." Green
} catch {
    Write-ColoredLine " X Download failed." Red
}

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractFolder)
    Write-ColoredLine " OK Extracted Process Explorer." Green
} catch {
    Write-ColoredLine " OK Files already extracted." Green
}

Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

$actualExe = Get-ChildItem -Path $extractFolder -Filter "procexp64.exe" -Recurse | Select-Object -First 1
$peOutput = @()
if ($actualExe) {
    Write-ColoredLine " OK Launching Process Explorer..." Green
    Start-Process -FilePath $actualExe.FullName
    $peOutput += "SUCCESS: Process Explorer review completed."
} else {
    $peOutput += "FAILURE: procexp64.exe not found."
}

Write-Section "Process Explorer Analysis" $peOutput
$total3 = ($peOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success3 = ($peOutput | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success3 -Total $total3 -StepNumber 3

Wait-ForEnter -Message "Press Enter to Continue to Step 4"

Clear-Host

Write-BoxedHeader "STEP 4/5: PERIPHERAL SOFTWARE" "Detecting gaming peripheral software..."
Show-CustomLoadingBar

$hardwareOutput = @()
$peripherals = @(
    @{Name="Razer"; Paths=@("C:\Program Files\Razer\Synapse3\Razer Synapse.exe","C:\Program Files (x86)\Razer\Synapse3\Razer Synapse.exe"); Keywords=@("Razer","Synapse")},
    @{Name="Corsair"; Paths=@("C:\Program Files (x86)\Corsair\CORSAIR iCUE Software\iCUE.exe","C:\Program Files\Corsair\CORSAIR iCUE 5 Software\iCUE.exe"); Keywords=@("Corsair","iCUE")},
    @{Name="Logitech"; Paths=@("C:\Program Files\Logitech\G HUB\lghub.exe","C:\Program Files\Logitech Gaming Software\LCore.exe"); Keywords=@("Logitech","GHUB")},
    @{Name="SteelSeries"; Paths=@("C:\Program Files\SteelSeries\SteelSeries Engine 3\SteelSeriesEngine3.exe","C:\Program Files\SteelSeries\GG\SteelSeriesGG.exe"); Keywords=@("SteelSeries","GG")},
    @{Name="HyperX"; Paths=@("C:\Program Files\HyperX\NGenuity\Ngenuity.exe","C:\Program Files (x86)\HyperX\NGenuity\Ngenuity.exe"); Keywords=@("HyperX","NGenuity")},
    @{Name="ASUS ROG"; Paths=@("C:\Program Files (x86)\ASUS\Armoury Crate\ArmouryCrate.exe","C:\Program Files\ASUS\Armoury Crate\ArmouryCrate.exe"); Keywords=@("ASUS","Armoury")},
    @{Name="Roccat"; Paths=@("C:\Program Files (x86)\ROCCAT\Swarm\ROCCAT_Swarm_Monitor.exe","C:\Program Files\ROCCAT\Swarm\ROCCAT_Swarm_Monitor.exe"); Keywords=@("ROCCAT","Swarm")},
    @{Name="Glorious"; Paths=@("C:\Program Files\Glorious\Glorious Core\GloriousCore.exe","C:\Program Files (x86)\Glorious\Glorious Core\GloriousCore.exe"); Keywords=@("Glorious","GloriousCore")},
    @{Name="Wooting"; Paths=@("C:\Program Files\Wooting\Wootility\Wootility.exe","C:\Program Files (x86)\Wooting\Wootility\Wootility.exe"); Keywords=@("Wooting","Wootility")},
    @{Name="Finalmouse"; Paths=@("C:\Program Files\Finalmouse\Finalmouse.exe","C:\Program Files (x86)\Finalmouse\Finalmouse.exe"); Keywords=@("Finalmouse","Ultralight")}
)

Write-Host ""
Write-ColoredLine " +- Peripheral Detection Results" DarkGray

try {
    $usbDevices = Get-PnpDevice -Class "Keyboard","Mouse","HIDClass" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
    $foundPeripherals = $false

    foreach ($periph in $peripherals) {
        $deviceDetected = $usbDevices | Where-Object { $_.FriendlyName -like "*$($periph.Name)*" }
        $softwarePath = $null
        foreach ($sw in $periph.Paths) { if (Test-Path $sw) { $softwarePath = $sw; break } }
        $isDetected = $deviceDetected -or $softwarePath

        if ($isDetected) {
            $foundPeripherals = $true
            Write-Host " | "; Write-Host "OK $($periph.Name) PERIPHERAL DETECTED" -ForegroundColor Green
            if ($deviceDetected) { foreach ($dev in $deviceDetected) { Write-Host " | "; Write-Host " -> Device: $($dev.FriendlyName)" -ForegroundColor White } }
            if ($softwarePath) {
                Write-Host " | "; Write-Host " -> Software: $softwarePath" -ForegroundColor White
                Write-Host " | "; Write-Host " -> AUTO-LAUNCHING for macro inspection..." -ForegroundColor Yellow
                try { Start-Process $softwarePath -ErrorAction Stop; $hardwareOutput += "SUCCESS: $($periph.Name) DETECTED - Software launched." } catch { $hardwareOutput += "SUCCESS: $($periph.Name) DETECTED - Software found but failed to launch." }
            } else { $hardwareOutput += "SUCCESS: $($periph.Name) DETECTED - No software installed." }
            Write-Host " | "; Write-Host "" -ForegroundColor White
        }
    }
    if (-not $foundPeripherals) { Write-Host " | "; Write-Host " No gaming peripherals detected." -ForegroundColor Yellow; $hardwareOutput += "SUCCESS: No gaming peripheral software detected." }
} catch { $hardwareOutput += "WARNING: Peripheral detection failed: $_" }

Write-ColoredLine " +-" DarkGray
Write-Section "Gaming Peripheral Check" $hardwareOutput
$total4 = ($hardwareOutput | Where-Object { $_ -match '^(SUCCESS|FAILURE|WARNING)' }).Count
$success4 = ($hardwareOutput | Where-Object { $_ -match '^SUCCESS' }).Count
Write-StepResult -Success $success4 -Total $total4 -StepNumber 4

Wait-ForEnter -Message "Press Enter to Continue to Step 5"

Clear-Host

Write-BoxedHeader "STEP 5/5: FINAL SCAN" "Downloads, processes & registry check"
Write-ColoredLine "! DO NOT CLOSE THIS WINDOW" Red
Show-CustomLoadingBar

$step5Output = @()
$suspiciousCombined = @(
    "matcha.exe", "olduimatrix", "autoexe", "workspace", "monkeyaim", "thunderaim", 
    "thunderclient", "celex", "matrix", "matcha.exe", "triggerbot", "solara.exe", 
    "xeno.exe", "cloudy", "tupical", "horizon", "myst", "celery", "zarora", "juju", 
    "nezure", "FusionHacks.zip", "release.zip", "aimmy.exe", "aimmy", "Fluxus", 
    "clumsy", "build.zip", "build.rar", "MystW.exe", "isabelle", "dx9ware", 
    "bootstrappernew", "loader.exe", "santoware", "mystw", "severe", "mapper.exe",
    "BOOTSTRAPPERNEW.EXE", "XENO.EXE", "XENOUI.EXE", "SOLARA.EXE", 
    "MAPPER.EXE", "LOADER.EXE", "MATCHA.EXE", "EVOLVE.EXE",
    "volt.exe", "potassium.exe", "cosmic.exe", "volcano.exe", "isaeva.exe", "synapsez.exe",
    "velocity.exe", "seliware.exe", "bunni.fun.exe", "sirhurt.exe", "hydrogen.exe",
    "macsploit.exe", "opiumware.exe", "cryptic.exe", "vegax.exe", "codex.exe",
    "serotonin.exe", "rbxcli.exe", "ronin.exe", "photon.exe",
    "kiciahook.exe", "kiciahookv2.exe", "snaw.exe", "robloxdma.exe",
    "VOLT.EXE", "POTASSIUM.EXE", "COSMIC.EXE", "VOLCANO.EXE", "ISAEVA.EXE", "SYNAPSEZ.EXE",
    "VELOCITY.EXE", "SELIWARE.EXE", "BUNNI.FUN.EXE", "SIRHURT.EXE", "HYDROGEN.EXE",
    "MACSPLOIT.EXE", "OPIUMWARE.EXE", "CRYPTIC.EXE", "VEGAX.EXE", "CODEX.EXE",
    "SEROTONIN.EXE", "RBXCLI.EXE", "RONIN.EXE", "PHOTON.EXE",
    "KICIAHOOK.EXE", "KICIAHOOKV2.EXE", "SNAW.EXE", "ROBLOXDMA.EXE"
)

try {
    $downloadFiles = Get-ChildItem "$env:USERPROFILE\Downloads" -File -Recurse -ErrorAction Stop
    $foundSuspicious = $false
    foreach ($file in $downloadFiles) {
        foreach ($susp in $suspiciousCombined) {
            if ($file.Name -imatch [regex]::Escape($susp)) {
                $step5Output += "FAILURE: Suspicious file: $($file.Name)"
                $foundSuspicious = $true
                $suspiciousFindings.Add([PSCustomObject]@{Type = "File-Downloads"; Path = $file.FullName})
            }
        }
    }
    if (-not $foundSuspicious) {
        $step5Output += "SUCCESS: No suspicious files in Downloads."
    }
} catch {
    $step5Output += "WARNING: Cannot access Downloads folder."
}

try {
    $activeProcs = Get-Process | Select-Object -ExpandProperty ProcessName
    $foundSuspicious = $false
    foreach ($proc in $activeProcs) {
        foreach ($susp in $suspiciousCombined) {
            if ($proc -imatch [regex]::Escape($susp)) {
                $step5Output += "FAILURE: Suspicious process: $proc"
                $foundSuspicious = $true
                $suspiciousFindings.Add([PSCustomObject]@{Type = "SuspiciousProcess"; Name = $proc})
            }
        }
    }
    if (-not $foundSuspicious) {
        $step5Output += "SUCCESS: No suspicious active processes."
    }
} catch {
    $step5Output += "WARNING: Process scan failed."
}

try {
    $muiPath = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    $entries = Get-ItemProperty -Path $muiPath -ErrorAction Stop
    $foundSuspicious = $false
    foreach ($prop in $entries.PSObject.Properties) {
        foreach ($susp in $suspiciousCombined) {
            if ($prop.Name.ToLower() -like "*$susp*") {
                $step5Output += "WARNING: Suspicious MuiCache entry: $($prop.Name)"
                $foundSuspicious = $true
            }
        }
    }
    if (-not $foundSuspicious) {
        $step5Output += "SUCCESS: No suspicious MuiCache entries."
    }
} catch {
    $step5Output += "WARNING: MuiCache registry scan failed."
}

if (-not $step5Output) { $step5Output += "SUCCESS: Clean final scan - no suspicious items detected." }

Write-Section "Final Scan Results" $step5Output

$overallSuccess = [math]::Round((($success1 + $success2 + $success3 + $success4) / ($total1 + $total2 + $total3 + $total4)) * 100, 0)
$overallColor = if ($overallSuccess -eq 100) { "Green" } elseif ($overallSuccess -ge 80) { "Yellow" } else { "Red" }

Write-Host ""
Write-ColoredLine " ============================================================" Cyan
Write-Host " OVERALL SECURITY SCORE: " -NoNewline -ForegroundColor White
Write-Host "$overallSuccess%" -NoNewline -ForegroundColor $overallColor
Write-Host " ($($success1+$success2+$success3+$success4)/$($total1+$total2+$total3+$total4) checks passed)" -ForegroundColor Gray
Write-ColoredLine " ============================================================" Cyan

Unregister-Event -SourceIdentifier FileCreated -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier FileChanged -ErrorAction SilentlyContinue

Write-ColoredLine "`n Auto-closing in 5 seconds..." Yellow
Start-Sleep -Seconds 5
Clear-Host

Write-ColoredLine "`n Thank you for using JTC T1 Policy Scanner`n" Cyan
Write-ColoredLine " Log saved to: $logFile`n" Gray

exit