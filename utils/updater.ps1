param(
    [string]$ScriptPath,
    [string]$ZipUrl,
    [string]$GuiPath,
    [int]$GuiPid = 0
)

# -------------------------------------------------------
#  Zapret GUI - Auto Updater
#  Launched by Zapret-gui.ps1 when the user confirms an update (elevated).
# -------------------------------------------------------

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

function Write-Step {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host $Msg -ForegroundColor $Color
}

if (-not $ScriptPath -or -not $ZipUrl -or -not $GuiPath) {
    Write-Host "[ERROR] Missing required parameters." -ForegroundColor Red
    Write-Host "Usage: updater.ps1 -ScriptPath <path> -ZipUrl <url> -GuiPath <path> [-GuiPid <pid>]" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}
$ScriptPath = $ScriptPath.TrimEnd('\', '/')

# --- run from a temp copy so utils\updater.ps1 itself can be replaced ---
$self = $MyInvocation.MyCommand.Path
if ($self -and $self.StartsWith($ScriptPath, [StringComparison]::OrdinalIgnoreCase)) {
    $tmpSelf = Join-Path $env:TEMP ("zapret_updater_{0}.ps1" -f (Get-Random))
    Copy-Item -LiteralPath $self -Destination $tmpSelf -Force
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmpSelf -ScriptPath $ScriptPath -ZipUrl $ZipUrl -GuiPath $GuiPath -GuiPid $GuiPid
    $code = $LASTEXITCODE
    Remove-Item -LiteralPath $tmpSelf -Force -ErrorAction SilentlyContinue
    exit $code
}

$stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$tempDir   = Join-Path $env:TEMP "zapret_update_$stamp"
$zipFile   = Join-Path $env:TEMP "zapret_update_$stamp.zip"
$backupDir = Join-Path $env:TEMP "zapret_backup_$stamp"
$changed   = New-Object System.Collections.ArrayList     # @{ Rel; Existed }
$leftovers = New-Object System.Collections.ArrayList     # renamed-aside locked files (*.old_*)
$svcState  = @{ Existed = $false; WasRunning = $false }

# ---------- helpers ----------

function Invoke-Sc {
    $ErrorActionPreference = "Continue"
    & sc.exe @args 2>&1 | Out-Null
}

function Stop-ZapretProcesses {
    # closes other GUI instances, bat windows and winws.exe that belong to this folder
    $myPid = $PID
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $parentOfMe = ($procs | Where-Object { $_.ProcessId -eq $myPid } | Select-Object -First 1).ParentProcessId
    $killed = @()
    foreach ($p in $procs) {
        if ($p.ProcessId -eq $myPid -or $p.ProcessId -eq $parentOfMe) { continue }
        $name = [string]$p.Name
        $cl   = [string]$p.CommandLine
        $exe  = [string]$p.ExecutablePath
        $isGui   = ($name -match '^(powershell|pwsh)\.exe$') -and ($cl -match '(?i)-File\s+"?[^"]*zapret-gui\.ps1')
        $isWinws = ($name -ieq 'winws.exe')
        $isBat   = ($name -ieq 'cmd.exe') -and ($cl -match '(?i)\.bat') -and ($cl.IndexOf($ScriptPath, [StringComparison]::OrdinalIgnoreCase) -ge 0)
        $inDir   = $exe -and $exe.StartsWith($ScriptPath + "\", [StringComparison]::OrdinalIgnoreCase) -and ($name -notmatch '^(powershell|pwsh)\.exe$')
        if ($isGui -or $isWinws -or $isBat -or $inDir) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; $killed += "$name($($p.ProcessId))" } catch {}
        }
    }
    return $killed
}

function Stop-ZapretServices {
    $svc = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
    if ($svc) {
        $svcState.Existed = $true
        if ($svc.Status -eq "Running" -or $svc.Status -eq "StartPending") { $svcState.WasRunning = $true }
        if ($svc.Status -ne "Stopped") {
            Invoke-Sc stop zapret
            try { $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(15)) } catch {}
        }
    }
    Get-Process -Name winws -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($drv in @("WinDivert", "WinDivert14")) {
        $d = Get-Service -Name $drv -ErrorAction SilentlyContinue
        if ($d -and $d.Status -ne "Stopped") {
            Invoke-Sc stop $drv
            try { $d.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(8)) } catch {}
        }
    }
}

function Get-ZipWithRetry {
    param([string]$Url, [string]$Dest, [int]$Tries = 3)
    for ($i = 1; $i -le $Tries; $i++) {
        try {
            if (Test-Path $Dest) { Remove-Item $Dest -Force -ErrorAction SilentlyContinue }
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "zapret-gui-updater")
            $wc.DownloadFile($Url, $Dest)
            $wc.Dispose()
            if ((Get-Item $Dest).Length -lt 50KB) { throw "downloaded file is too small" }
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $z = [System.IO.Compression.ZipFile]::OpenRead($Dest)
            $n = $z.Entries.Count
            $z.Dispose()
            if ($n -lt 1) { throw "archive is empty" }
            return
        } catch {
            if ($i -eq $Tries) { throw "Download failed after $Tries attempts: $($_.Exception.Message)" }
            Write-Step "      attempt $i failed ($($_.Exception.Message)), retrying..." "Yellow"
            Start-Sleep -Seconds (2 * $i)
        }
    }
}

function Test-Excluded {
    param([string]$Rel)
    $r = $Rel.Replace('/', '\')
    if ($r -match '^\.git') { return $true }
    if ($r -match '^lists\\[^\\]*-user\.txt$') { return $true }
    if ($r -ieq 'utils\targets.txt') { return $true }
    if ($r -match '^utils\\(test )?results(\\|$)') { return $true }
    if ($r -match '^utils\\[^\\]*\.enabled$') { return $true }
    if ($r -ieq 'lists\ipset-all.txt' -and (Test-Path (Join-Path $ScriptPath $r))) { return $true }
    return $false
}

function Copy-FileSafe {
    param([string]$Src, [string]$Dst)
    $dir = Split-Path $Dst -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    for ($i = 1; $i -le 5; $i++) {
        try {
            if (Test-Path -LiteralPath $Dst) { (Get-Item -LiteralPath $Dst -Force).Attributes = 'Normal' }
            Copy-Item -LiteralPath $Src -Destination $Dst -Force
            return
        } catch { Start-Sleep -Milliseconds 500 }
    }
    # locked file: move it aside (renaming a loaded file is allowed), then copy the new one
    try {
        $aside = "$Dst.old_$(Get-Random)"
        Rename-Item -LiteralPath $Dst -NewName (Split-Path $aside -Leaf) -Force
        [void]$leftovers.Add($aside)
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
    } catch {
        throw "Cannot replace locked file: $Dst"
    }
}

function Restore-Backup {
    Write-Step "      Rolling back changes..." "Yellow"
    for ($i = $changed.Count - 1; $i -ge 0; $i--) {
        $c = $changed[$i]
        $dst = Join-Path $ScriptPath $c.Rel
        try {
            if ($c.Existed) { Copy-FileSafe -Src (Join-Path $backupDir $c.Rel) -Dst $dst }
            else { Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
}

function Start-GuiAgain {
    if (Test-Path -LiteralPath $GuiPath) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$GuiPath`"" -Verb RunAs
    }
}

# ---------- main ----------

try {
    Write-Step "=== Zapret GUI Updater ===" "White"
    Write-Step ""

    Write-Step "[1/7] Closing GUI, zapret windows and winws..."
    if ($GuiPid -gt 0) {
        $g = Get-Process -Id $GuiPid -ErrorAction SilentlyContinue
        if ($g) { try { [void]$g.WaitForExit(8000) } catch {} }
    }
    $k = Stop-ZapretProcesses
    if ($k.Count -gt 0) { Write-Step "      Closed: $($k -join ', ')" "DarkGray" } else { Write-Step "      Nothing to close." "DarkGray" }

    Write-Step "[2/7] Stopping zapret service and WinDivert driver..."
    Stop-ZapretServices
    Start-Sleep -Milliseconds 500
    [void](Stop-ZapretProcesses)
    Write-Step "      Service existed: $($svcState.Existed), was running: $($svcState.WasRunning)" "DarkGray"

    Write-Step "[3/7] Downloading update..."
    Get-ZipWithRetry -Url $ZipUrl -Dest $zipFile
    Write-Step "      Downloaded and verified." "DarkGray"

    Write-Step "[4/7] Extracting..."
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $tempDir)
    $topItems = Get-ChildItem $tempDir
    $topDirs  = @($topItems | Where-Object { $_.PSIsContainer })
    $topFiles = @($topItems | Where-Object { -not $_.PSIsContainer })
    if ($topFiles.Count -eq 0 -and $topDirs.Count -eq 1) { $sourceDir = $topDirs[0].FullName } else { $sourceDir = $tempDir }
    Write-Step "      Extracted to: $sourceDir" "DarkGray"

    Write-Step "[5/7] Replacing files (user lists, targets.txt, test results and settings are kept)..."
    $files = @(Get-ChildItem $sourceDir -Recurse -File)
    $copied = 0; $skippedSame = 0; $skippedExcl = 0
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($sourceDir.Length).TrimStart('\', '/')
        if (Test-Excluded $rel) { $skippedExcl++; continue }
        $dst = Join-Path $ScriptPath $rel
        $existed = Test-Path -LiteralPath $dst
        if ($existed) {
            $cur = Get-Item -LiteralPath $dst -Force
            if ($cur.Length -eq $f.Length -and (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash) {
                $skippedSame++; continue
            }
            $bk = Join-Path $backupDir $rel
            $bkDir = Split-Path $bk -Parent
            if (-not (Test-Path $bkDir)) { New-Item -ItemType Directory -Path $bkDir -Force | Out-Null }
            Copy-Item -LiteralPath $dst -Destination $bk -Force
        }
        [void]$changed.Add(@{ Rel = $rel; Existed = $existed })
        Copy-FileSafe -Src $f.FullName -Dst $dst
        $copied++
    }
    Write-Step "      Replaced/added: $copied, unchanged: $skippedSame, kept (user data): $skippedExcl" "DarkGray"

    Write-Step "[6/7] Cleanup..."
    foreach ($o in $leftovers) { Remove-Item -LiteralPath $o -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -Path $ScriptPath -Recurse -Filter "*.old_*" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $backupDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Step "[7/7] Restoring service state..."
    if ($svcState.WasRunning) {
        Invoke-Sc start zapret
        Start-Sleep -Seconds 2
        $s = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq "Running") { Write-Step "      Service started again." "DarkGray" }
        else { Write-Step "      [WARN] Service did not start - reinstall it from the GUI." "Yellow" }
        Write-Step "      Note: the service keeps the strategy arguments it was installed with; reinstall it from the GUI to use changed strategies." "DarkGray"
    } else {
        Write-Step "      Service was not running - nothing to restore." "DarkGray"
    }

    Write-Step ""
    Write-Step "[OK] Update complete! Restarting GUI..." "Green"
    Start-Sleep -Seconds 1
    Start-GuiAgain

} catch {
    Write-Step ""
    Write-Step "[ERROR] Update failed: $($_.Exception.Message)" "Red"
    if ($changed.Count -gt 0) {
        Restore-Backup
        Write-Step "      Previous files were restored." "Yellow"
    } else {
        Write-Step "      No files were modified." "Yellow"
    }
    foreach ($o in $leftovers) { Remove-Item -LiteralPath $o -Force -ErrorAction SilentlyContinue }
    if ($svcState.WasRunning) { Invoke-Sc start zapret }

    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $backupDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Read-Host "Press Enter to start the GUI again"
    Start-GuiAgain
    exit 1
}
