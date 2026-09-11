Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------------------------
# Auto-elevation
# ---------------------------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# ---------------------------------------------------------------------------
# Hide console window
# ---------------------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'ZapNative').Type) {
    Add-Type -Name ZapNative -Namespace '' -MemberDefinition @'
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]   public static extern bool   ShowWindow(IntPtr h, int n);
'@
}
try { [ZapNative]::ShowWindow([ZapNative]::GetConsoleWindow(), 0) | Out-Null } catch {}

# ---------------------------------------------------------------------------
# Paths  (script lives in utils\)
# ---------------------------------------------------------------------------
$ScriptDir  = if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) { $PSScriptRoot } `
              else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$rootDir    = Split-Path $ScriptDir -Parent
$listsDir   = Join-Path $rootDir  "lists"
$utilsDir   = $ScriptDir
$resultsDir = Join-Path $ScriptDir "test results"
if (-not (Test-Path $resultsDir)) { New-Item -ItemType Directory -Path $resultsDir | Out-Null }

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------
$C = @{
    Primary     = [System.Drawing.Color]::FromArgb(41, 128, 185)
    Success     = [System.Drawing.Color]::FromArgb(39, 174, 96)
    Warning     = [System.Drawing.Color]::FromArgb(243, 156, 18)
    Danger      = [System.Drawing.Color]::FromArgb(231, 76, 60)
    Light       = [System.Drawing.Color]::FromArgb(236, 240, 241)
    White       = [System.Drawing.Color]::White
    DarkPrimary = [System.Drawing.Color]::FromArgb(31, 97, 141)
    DarkSuccess = [System.Drawing.Color]::FromArgb(29, 131, 72)
    DarkWarning = [System.Drawing.Color]::FromArgb(183, 118, 14)
    DarkDanger  = [System.Drawing.Color]::FromArgb(173, 57, 43)
    DarkGray    = [System.Drawing.Color]::FromArgb(52, 73, 94)
    Midnight    = [System.Drawing.Color]::FromArgb(33, 47, 61)
    Steel       = [System.Drawing.Color]::FromArgb(66, 73, 83)
    Slate       = [System.Drawing.Color]::FromArgb(79, 90, 101)
    LogBg       = [System.Drawing.Color]::FromArgb(22, 32, 44)
    RowEven     = [System.Drawing.Color]::FromArgb(48, 65, 82)
    SubText     = [System.Drawing.Color]::FromArgb(100, 130, 160)
    Yellow      = [System.Drawing.Color]::FromArgb(243, 200, 80)
    Cyan        = [System.Drawing.Color]::FromArgb(90, 180, 220)
}

# ---------------------------------------------------------------------------
# PRE-LAUNCH CHECKS
# ---------------------------------------------------------------------------
function Show-FatalError([string]$title, [string]$msg) {
    [System.Windows.Forms.MessageBox]::Show(
        $msg, $title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit
}

if (-not (Test-Path $rootDir)) {
    Show-FatalError "Zapret Test Runner - Setup Error" (
        "Root directory not found:`n$rootDir`n`n" +
        "Make sure the script is placed inside the utils\ subfolder of your zapret installation."
    )
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    Show-FatalError "Zapret Test Runner - Missing Dependency" (
        "curl.exe was not found in PATH.`n`n" +
        "Install curl (e.g.:  winget install curl.curl)`n" +
        "or add the folder containing curl.exe to your system PATH, then re-run."
    )
}

$_svc = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
if ($_svc -and $_svc.Status -eq "Running") {
    $errorMessage = @'
Zapret is running and may conflict.
Close the window and click "Remove Service",
and then run the test again.
'@
    Show-FatalError "Zapret Test Runner - Service Conflict" $errorMessage
}

$_runningWinws = Get-Process -Name "winws" -ErrorAction SilentlyContinue
if ($_runningWinws) {
    $r = [System.Windows.Forms.MessageBox]::Show(
        "winws.exe is currently running (PID: $($_runningWinws.Id -join ', ')).`n`n" +
        "It will be stopped automatically before each config is tested.`n`nContinue?",
        "Zapret Test Runner - winws is running",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { exit }
}

# ---------------------------------------------------------------------------
# Bat file list
# ---------------------------------------------------------------------------
$allBat = @(
    Get-ChildItem -Path $rootDir -Filter "*.bat" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike "service*" -and $_.Name -notlike "!*" } |
    Sort-Object { [Regex]::Replace($_.Name, '(\d+)', { $args[0].Value.PadLeft(8,'0') }) }
)

# ---------------------------------------------------------------------------
# Shared button style helper
# ---------------------------------------------------------------------------
function New-Btn([string]$text, [int]$x, [int]$y, [int]$w, [int]$h, [System.Drawing.Color]$bg) {
    $b = New-Object System.Windows.Forms.Button
    $b.Location  = New-Object System.Drawing.Point($x, $y)
    $b.Size      = New-Object System.Drawing.Size($w, $h)
    $b.Text      = $text
    $b.BackColor = $bg
    $b.ForeColor = $C.White
    $b.FlatStyle = "Flat"
    $b.FlatAppearance.BorderSize = 0
    $b.Font      = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    return $b
}

# ===========================================================================
#  WINDOW 1 - Test Type Selection
# ===========================================================================
$w1 = New-Object System.Windows.Forms.Form
$w1.Text            = "Zapret Test Runner - Step 1: Test Type"
$w1.Size            = New-Object System.Drawing.Size(478, 240)
$w1.MinimumSize     = New-Object System.Drawing.Size(478, 240)
$w1.MaximumSize     = New-Object System.Drawing.Size(478, 240)
$w1.StartPosition   = "CenterScreen"
$w1.FormBorderStyle = "FixedDialog"
$w1.MaximizeBox     = $false
$w1.BackColor       = $C.Midnight
$w1.ForeColor       = $C.Light

$lbl1 = New-Object System.Windows.Forms.Label
$lbl1.Location  = New-Object System.Drawing.Point(20, 22)
$lbl1.Size      = New-Object System.Drawing.Size(440, 22)
$lbl1.Text      = "Select test type:"
$lbl1.Font      = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lbl1.ForeColor = $C.Light
$w1.Controls.Add($lbl1)

$btnW1Std = New-Btn "Standard tests  (HTTP / Ping)" 16 58 430 56 $C.DarkPrimary
$btnW1Std.FlatAppearance.BorderSize  = 2
$btnW1Std.FlatAppearance.BorderColor = $C.Primary
$btnW1Std.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$w1.Controls.Add($btnW1Std)

$btnW1Dpi = New-Btn "DPI Checkers  (TCP 16-20 freeze)" 16 124 430 56 $C.Steel
$btnW1Dpi.FlatAppearance.BorderSize  = 2
$btnW1Dpi.FlatAppearance.BorderColor = $C.Slate
$btnW1Dpi.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$w1.Controls.Add($btnW1Dpi)

$script:chosenType = $null

$btnW1Std.Add_Click({
    $script:chosenType = 'standard'
    $w1.DialogResult  = [System.Windows.Forms.DialogResult]::OK
    $w1.Close()
})
$btnW1Dpi.Add_Click({
    $script:chosenType = 'dpi'
    $w1.DialogResult  = [System.Windows.Forms.DialogResult]::OK
    $w1.Close()
})

$btnW1Std.Add_MouseEnter({ $btnW1Std.BackColor = $C.Primary })
$btnW1Std.Add_MouseLeave({ $btnW1Std.BackColor = if ($script:chosenType -eq 'standard') {$C.Primary} else {$C.DarkPrimary} })
$btnW1Dpi.Add_MouseEnter({ $btnW1Dpi.BackColor = $C.DarkGray })
$btnW1Dpi.Add_MouseLeave({ $btnW1Dpi.BackColor = if ($script:chosenType -eq 'dpi') {$C.DarkGray} else {$C.Steel} })

$r1 = $w1.ShowDialog()
if ($r1 -ne [System.Windows.Forms.DialogResult]::OK -or -not $script:chosenType) { exit }
$testType = $script:chosenType

# ===========================================================================
#  WINDOW 2 - Config Selection
# ===========================================================================
$w2 = New-Object System.Windows.Forms.Form
$w2.Text            = "Zapret Test Runner - Step 2: Select Configs  [$($testType.ToUpper())]"
$w2.Size            = New-Object System.Drawing.Size(576, 600)
$w2.MinimumSize     = New-Object System.Drawing.Size(576, 600)
$w2.MaximumSize     = New-Object System.Drawing.Size(560, 860)
$w2.StartPosition   = "CenterScreen"
$w2.FormBorderStyle = "Sizable"
$w2.MaximizeBox     = $false
$w2.BackColor       = $C.Midnight
$w2.ForeColor       = $C.Light

$lbl2 = New-Object System.Windows.Forms.Label
$lbl2.Location  = New-Object System.Drawing.Point(16, 16)
$lbl2.Size      = New-Object System.Drawing.Size(390, 22)
$lbl2.Text      = "Select configs to test:"
$lbl2.Font      = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lbl2.ForeColor = $C.Light
$w2.Controls.Add($lbl2)

$btnSelAll = New-Btn "Select All" 414 12 64 28 $C.DarkGray
$btnSelAll.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$btnSelAll.FlatAppearance.BorderSize = 1
$btnSelAll.FlatAppearance.BorderColor = $C.Slate
$w2.Controls.Add($btnSelAll)

$btnSelNone = New-Btn "None" 482 12 60 28 $C.DarkGray
$btnSelNone.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$btnSelNone.FlatAppearance.BorderSize = 1
$btnSelNone.FlatAppearance.BorderColor = $C.Slate
$w2.Controls.Add($btnSelNone)

$pConf = New-Object System.Windows.Forms.Panel
$pConf.Location    = New-Object System.Drawing.Point(16, 46)
$pConf.Size        = New-Object System.Drawing.Size(($w2.ClientSize.Width - 32), ($w2.ClientSize.Height - 120))
$pConf.Anchor      = "Top, Bottom, Left, Right"
$pConf.BackColor   = $C.DarkGray
$pConf.AutoScroll  = $true
$pConf.BorderStyle = "None"
$w2.Controls.Add($pConf)

$hdr2 = New-Object System.Windows.Forms.Label
$hdr2.Location  = New-Object System.Drawing.Point(8, 5)
$hdr2.Size      = New-Object System.Drawing.Size(510, 18)
$hdr2.Text      = "    #    Config name"
$hdr2.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$hdr2.ForeColor = $C.SubText
$pConf.Controls.Add($hdr2)

$checkboxes2 = New-Object System.Collections.ArrayList
$cbY2 = 26

for ($i = 0; $i -lt $allBat.Count; $i++) {
    $bat = $allBat[$i]

    $row = New-Object System.Windows.Forms.Panel
    $row.Location  = New-Object System.Drawing.Point(0, $cbY2)
    $row.Size      = New-Object System.Drawing.Size(($pConf.ClientSize.Width - 5), 28)
    $row.Anchor    = "Top, Left, Right"
    $row.BackColor = if ($i % 2 -eq 0) { $C.RowEven } else { $C.DarkGray }
    $pConf.Controls.Add($row)

    $numLbl = New-Object System.Windows.Forms.Label
    $numLbl.Location  = New-Object System.Drawing.Point(8, 6)
    $numLbl.Size      = New-Object System.Drawing.Size(30, 16)
    $numLbl.Text      = "$($i+1)."
    $numLbl.Font      = New-Object System.Drawing.Font("Consolas", 9)
    $numLbl.ForeColor = $C.SubText
    $row.Controls.Add($numLbl)

    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Location  = New-Object System.Drawing.Point(40, 5)
    $cb.Size      = New-Object System.Drawing.Size(($row.Width - 50), 20)
    $cb.Anchor    = "Top, Left, Right"
    $cb.Text      = $bat.Name
    $cb.Checked   = $false
    $cb.Font      = New-Object System.Drawing.Font("Consolas", 10)
    $cb.ForeColor = $C.Light
    $cb.BackColor = [System.Drawing.Color]::Transparent
    $cb.Tag       = $bat
    $row.Controls.Add($cb)
    [void]$checkboxes2.Add($cb)
    $cbY2 += 28
}

$btnStart = New-Btn "Start Tests" 16 ($w2.ClientSize.Height - 58) ($w2.ClientSize.Width - 32) 42 $C.Success
$btnStart.Anchor = "Bottom, Left, Right"
$btnStart.Font   = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$w2.Controls.Add($btnStart)

$btnSelAll.Add_Click({  foreach ($cb in $checkboxes2) { $cb.Checked = $true  } })
$btnSelNone.Add_Click({ foreach ($cb in $checkboxes2) { $cb.Checked = $false } })

$script:selectedBats = @()
$btnStart.Add_Click({
    $sel = @($checkboxes2 | Where-Object { $_.Checked } | ForEach-Object { $_.Tag })
    if ($sel.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select at least one config.", "Error")
        return
    }
    $script:selectedBats = $sel
    $w2.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $w2.Close()
})

$r2 = $w2.ShowDialog()
if ($r2 -ne [System.Windows.Forms.DialogResult]::OK -or $script:selectedBats.Count -eq 0) { exit }
$selFiles = $script:selectedBats

# ===========================================================================
#  WINDOW 3 - Test Runner
# ===========================================================================
$w3 = New-Object System.Windows.Forms.Form
$w3.Text            = "Zapret Test Runner  [$($testType.ToUpper())]  -  Running..."
$w3.Size            = New-Object System.Drawing.Size(760, 620)
$w3.MinimumSize     = New-Object System.Drawing.Size(600, 450)
$w3.StartPosition   = "CenterScreen"
$w3.FormBorderStyle = "Sizable"
$w3.MaximizeBox     = $true
$w3.BackColor       = $C.Midnight

$pProgress = New-Object System.Windows.Forms.Panel
$pProgress.Height    = 42
$pProgress.Dock      = "Top"
$pProgress.BackColor = $C.DarkGray
$w3.Controls.Add($pProgress)

$progBar = New-Object System.Windows.Forms.ProgressBar
$progBar.Location  = New-Object System.Drawing.Point(10, 10)
$progBar.Width     = $pProgress.ClientSize.Width - 130
$progBar.Height    = 22
$progBar.Anchor    = "Top, Left, Right"
$progBar.Style     = "Continuous"
$progBar.ForeColor = $C.Primary
$progBar.BackColor = $C.Steel
$progBar.Minimum   = 0
$progBar.Maximum   = 100
$progBar.Value     = 0
$pProgress.Controls.Add($progBar)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Location  = New-Object System.Drawing.Point(($pProgress.ClientSize.Width - 110), 10)
$lblCount.Size      = New-Object System.Drawing.Size(100, 22)
$lblCount.Anchor    = "Top, Right"
$lblCount.Text      = "0 / $($selFiles.Count)"
$lblCount.Font      = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblCount.ForeColor = $C.Cyan
$lblCount.TextAlign = "MiddleRight"
$pProgress.Controls.Add($lblCount)

$rtb = New-Object System.Windows.Forms.RichTextBox
$rtb.Dock        = "Fill"
$rtb.BackColor   = $C.LogBg
$rtb.ForeColor   = $C.Light
$rtb.Font        = New-Object System.Drawing.Font("Consolas", 9)
$rtb.ReadOnly    = $true
$rtb.ScrollBars  = "Vertical"
$rtb.WordWrap    = $false
$rtb.BorderStyle = "None"
$w3.Controls.Add($rtb)

$colorMap = @{
    Green    = $C.Success
    Red      = $C.Danger
    Yellow   = $C.Warning
    Cyan     = $C.Cyan
    DarkCyan = $C.Cyan
    DarkGray = $C.SubText
    Gray     = $C.SubText
    White    = $C.Light
    Default  = $C.Light
}

function Append-Log([string]$text, [System.Drawing.Color]$col) {
    $rtb.SelectionStart  = $rtb.TextLength
    $rtb.SelectionLength = 0
    $rtb.SelectionColor  = $col
    $rtb.AppendText("$text`n")
    $rtb.ScrollToCaret()
}

function Append-Log-Multipart([string]$json) {
    try {
        $parts = $json | ConvertFrom-Json
        $rtb.SelectionStart  = $rtb.TextLength
        $rtb.SelectionLength = 0
        foreach ($part in $parts) {
            $col = if ($colorMap.ContainsKey($part.Color)) { $colorMap[$part.Color] } else { $C.Light }
            $rtb.SelectionColor = $col
            $rtb.AppendText($part.Text)
        }
        $rtb.AppendText("`n")
        $rtb.ScrollToCaret()
    } catch {
        Append-Log $json $C.Light
    }
}

$msgList   = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$progState = [hashtable]::Synchronized(@{
    Current = 0
    Total   = $selFiles.Count
    Done    = $false
    Error   = ''
})

# ---------------------------------------------------------------------------
#  BACKGROUND SCRIPT  
# ---------------------------------------------------------------------------
$bgScript = {
    param(
        [object[]] $selFiles,
        [string]   $testType,
        [string]   $rootDir,
        [string]   $listsDir,
        [string]   $utilsDir,
        [string]   $resultsDir,
        [object]   $msgList,
        [hashtable]$progState
    )

    function wlog([string]$text, [string]$color = "Default") {
        [void]$msgList.Add([pscustomobject]@{ Text = $text; Color = $color })
    }

    function Get-IpsetStatus {
        $listFile = Join-Path $listsDir "ipset-all.txt"
        if (-not (Test-Path $listFile)) { return "none" }
        $raw = [IO.File]::ReadAllText($listFile)
        if ([string]::IsNullOrWhiteSpace($raw)) { return "any" }
        if ($raw -match '203\.0\.113\.113/32') { return "none" }
        return "loaded"
    }

    function Wait-WinwsReady {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($timer.ElapsedMilliseconds -lt 5000) {
            if (Get-Process -Name "winws" -ErrorAction SilentlyContinue) {
                Start-Sleep -Milliseconds 300
                return $true
            }
            Start-Sleep -Milliseconds 200
        }
        return $false
    }

    function Set-IpsetMode {
        param([string]$mode)
        $listFile   = Join-Path $listsDir "ipset-all.txt"
        $backupFile = Join-Path $listsDir "ipset-all.test-backup.txt"
        if ($mode -eq "any") {
            if (Test-Path $listFile) {
                Copy-Item $listFile $backupFile -Force
            } else {
                "" | Out-File $backupFile -Encoding UTF8
            }
            "" | Out-File $listFile -Encoding UTF8
        } elseif ($mode -eq "restore") {
            if (Test-Path $backupFile) {
                Move-Item $backupFile $listFile -Force
            }
        }
    }

    function New-OrderedDict { New-Object System.Collections.Specialized.OrderedDictionary }
    function Add-OrSet {
        param($dict, $key, $val)
        if ($dict.Contains($key)) { $dict[$key] = $val } else { $dict.Add($key, $val) }
    }

    function Convert-Target {
        param([string]$Name, [string]$Value)
        if ($Value -like "PING:*") {
            $ping = $Value -replace '^PING:\s*', ''
            return New-Object PSObject -Property @{ Name = $Name; Url = $null; PingTarget = $ping }
        } else {
            $pt = $Value -replace "^https?://", "" -replace "/.*$", ""
            return New-Object PSObject -Property @{ Name = $Name; Url = $Value; PingTarget = $pt }
        }
    }

    function Stop-Zapret {
        Get-Process -Name "winws" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    function Get-WinwsSnapshot {
        try {
            return Get-CimInstance Win32_Process -Filter "Name='winws.exe'" |
                Select-Object ProcessId, CommandLine, ExecutablePath
        } catch { return @() }
    }

    function Restore-WinwsSnapshot {
        param($snapshot)
        if (-not $snapshot -or $snapshot.Count -eq 0) { return }
        $current = @()
        try { $current = (Get-WinwsSnapshot).CommandLine } catch { $current = @() }
        wlog "[INFO] Restoring previously running winws instances..." "DarkGray"
        foreach ($p in $snapshot) {
            if (-not $p.ExecutablePath) { continue }
            if ($current -and $current -contains $p.CommandLine) { continue }
            $exe = $p.ExecutablePath
            $processArgs = ""
            if ($p.CommandLine) {
                $quotedExe = '"' + $exe + '"'
                if ($p.CommandLine.StartsWith($quotedExe)) {
                    $processArgs = $p.CommandLine.Substring($quotedExe.Length).Trim()
                } elseif ($p.CommandLine.StartsWith($exe)) {
                    $processArgs = $p.CommandLine.Substring($exe.Length).Trim()
                }
            }
            Start-Process -FilePath $exe -ArgumentList $processArgs -WorkingDirectory (Split-Path $exe -Parent) -WindowStyle Minimized | Out-Null
        }
    }

    # DPI defaults
    $dpiTimeoutSeconds = 5
    $dpiRangeBytes     = 65536
    $defaultMaxParallel = [Math]::Min(16, [Math]::Max(8, [Environment]::ProcessorCount * 2))
    $dpiMaxParallel    = $defaultMaxParallel
    $dpiCustomHost     = $env:MONITOR_HOST
    if ($env:MONITOR_TIMEOUT)      { [int]$dpiTimeoutSeconds = $env:MONITOR_TIMEOUT }
    if ($env:MONITOR_RANGE)        { [int]$dpiRangeBytes     = $env:MONITOR_RANGE }
    if ($env:MONITOR_MAX_PARALLEL) { [int]$dpiMaxParallel    = $env:MONITOR_MAX_PARALLEL }

    $standardCurlTimeout = 4
    $standardMaxParallel = $defaultMaxParallel
    if ($env:TEST_CURL_TIMEOUT) { [int]$standardCurlTimeout = $env:TEST_CURL_TIMEOUT }
    if ($env:TEST_MAX_PARALLEL) { [int]$standardMaxParallel = $env:TEST_MAX_PARALLEL }

    function Get-DpiSuite {
        $url = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json"
        try {
            (Invoke-RestMethod -Uri $url -TimeoutSec $dpiTimeoutSeconds) |
                Select-Object `
                    @{n='Id';       e={$_.id}},
                    @{n='Provider'; e={$_.provider}},
                    @{n='Country';  e={$_.country}},
                    @{n='Host';     e={$_.host}}
        } catch {
            wlog "[WARN] Fetch dpi suite failed." "Yellow"
            @()
        }
    }

    function Build-DpiTargets {
        param([string]$CustomHost)
        $suite = Get-DpiSuite
        $targets = @()
        if ($CustomHost) {
            $targets += @{ Id = "CUSTOM"; Provider = "Custom"; Country = "💡"; Host = $CustomHost }
        } else {
            foreach ($entry in $suite) {
                $targets += @{ Id = $entry.Id; Country = $entry.Country; Provider = $entry.Provider; Host = $entry.Host }
            }
        }
        return $targets
    }

    function Invoke-DpiSuite {
        param(
            [array]$Targets,
            [int]$TimeoutSeconds,
            [int]$RangeBytes,
            [int]$MaxParallel
        )

        $tests = @(
            @{ Label = "HTTP";   Args = @("--http1.1") },
            @{ Label = "TLS1.2"; Args = @("--tlsv1.2", "--tls-max", "1.2") },
            @{ Label = "TLS1.3"; Args = @("--tlsv1.3", "--tls-max", "1.3") }
        )

        $rangeSpec = "0-$($RangeBytes - 1)"
        $warnDetected = $false

        wlog "[INFO] Targets: $($Targets.Count) (custom URL overrides suite). Range: $rangeSpec bytes; Timeout: $($TimeoutSeconds)s" "Cyan"
        wlog "[INFO] Starting DPI TCP 16-20 checks (parallel: $MaxParallel)..." "DarkGray"

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxParallel)
        $runspacePool.Open()

        $payload = New-Object byte[] $RangeBytes
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($payload)

        $payloadFile = New-TemporaryFile
        [IO.File]::WriteAllBytes($payloadFile, $payload)

        $scriptBlock = {
            param($payloadFile, $target, $tests, $rangeSpec, $TimeoutSeconds)

            $warned = $false
            $lines = @()

            foreach ($test in $tests) {
                $curlArgs = @(
                    "--range", $rangeSpec,
                    "-m", $TimeoutSeconds,
                    "--connect-timeout", ([Math]::Min(3, $TimeoutSeconds)),
                    "-w", "%{http_code} %{size_upload} %{size_download} %{time_total}",
                    "-o", "NUL",
                    "-X", "POST",
                    "--data-binary", "@$payloadFile",
                    "-s"
                ) + $test.Args + @("https://$($target.Host)")

                $output = & curl.exe @curlArgs 2>&1
                $exit = $LASTEXITCODE
                $text = ($output | Out-String).Trim()

                $code = "NA"
                $upBytes = 0
                $downBytes = 0
                $time = -1

                if ($text -match '^(?<code>\d{3})\s+(?<up>\d+)\s+(?<down>\d+)\s+(?<time>[\d\.]+)$') {
                    $code = $matches['code']
                    $upBytes = [int64]$matches['up']
                    $downBytes = [int64]$matches['down']
                    $time = [double]$matches['time']
                } elseif (($exit -eq 35) -or ($text -match "not supported|does not support|protocol\s+'.+'\s+not\s+supported|protocol\s+.+\s+not\s+supported|unsupported protocol|TLS.not supported|Unrecognized option|Unknown option|unsupported option|unsupported feature|schannel|SSL")) {
                    $code = "UNSUP"
                } elseif ($text) {
                    $code = "ERR"
                }

                $upKB = [math]::Round($upBytes / 1024, 1)
                $downKB = [math]::Round($downBytes / 1024, 1)
                $status = "OK"
                $color = "Green"

                if ($code -eq "UNSUP") {
                    $status = "UNSUPPORTED"
                    $color = "Yellow"
                } elseif ($exit -ne 0 -or $code -eq "ERR" -or $code -eq "NA") {
                    $status = "FAIL"
                    $color = "Red"
                }

                if (($upBytes -gt 0) -and ($downBytes -eq 0) -and ($time -ge $TimeoutSeconds) -and ($exit -ne 0)) {
                    $status = "LIKELY_BLOCKED"
                    $color = "Yellow"
                    $warned = $true
                }

                $lines += [PSCustomObject]@{
                    TestLabel = $test.Label
                    Code      = $code
                    UpBytes   = $upBytes
                    UpKB      = $upKB
                    DownBytes = $downBytes
                    DownKB    = $downKB
                    Time      = $time
                    Status    = $status
                    Color     = $color
                    Warned    = $warned
                }
            }

            return [PSCustomObject]@{
                TargetId = $target.Id
                Provider = $target.Provider
                Country  = $target.Country
                Lines    = $lines
                Warned   = $warned
            }
        }

        $runspaces = @()
        foreach ($target in $Targets) {
            $powershell = [powershell]::Create().AddScript($scriptBlock)
            [void]$powershell.AddArgument($payloadFile)
            [void]$powershell.AddArgument($target)
            [void]$powershell.AddArgument($tests)
            [void]$powershell.AddArgument($rangeSpec)
            [void]$powershell.AddArgument($TimeoutSeconds)
            $powershell.RunspacePool = $runspacePool

            $runspaces += [PSCustomObject]@{
                Powershell = $powershell
                Handle     = $powershell.BeginInvoke()
                TargetId   = $target.Id
            }
        }

        $results = @()
        foreach ($rs in $runspaces) {
            try {
                $waitMs = (([int]$TimeoutSeconds * 3) + 5) * 1000
                $handle = $rs.Handle
                if ($handle -and $handle.AsyncWaitHandle) {
                    $completed = $handle.AsyncWaitHandle.WaitOne($waitMs)
                    if (-not $completed) {
                        wlog "[WARN] Runspace for [$($rs.TargetId)] timed out after $waitMs ms; stopping runspace..." "Yellow"
                        try { $rs.Powershell.Stop() } catch {}
                    }
                }
            } catch {}

            try {
                $res = $rs.Powershell.EndInvoke($rs.Handle)
                $results += $res

                wlog "" "Default"
                wlog "=== [$($res.Country)][$($res.Provider)] $($res.TargetId) ===" "DarkCyan"
                foreach ($line in $res.Lines) {
                    $msg = "[{0}] code={1} buf_up={2} bytes ({3} KB) buf_down={4} bytes ({5} KB) time={6}s status={7}" -f `
                        $line.TestLabel, $line.Code, $line.UpBytes, $line.UpKB, $line.DownBytes, $line.DownKB, $line.Time, $line.Status
                    wlog $msg $line.Color
                    if ($line.Status -eq "LIKELY_BLOCKED") {
                        wlog "  Pattern matches 16-20KB freeze; censor likely cutting this strategy." "Yellow"
                    }
                }

                if ($res.Warned) {
                    $warnDetected = $true
                } else {
                    wlog "  No 16-20KB freeze pattern for this target." "Green"
                }
            } catch {
                wlog "[WARN] EndInvoke failed for a runspace; treating as failure." "Yellow"
                $results += [PSCustomObject]@{ TargetId = 'UNKNOWN'; Provider = 'UNKNOWN'; Lines = @(); Warned = $false }
            }
            $rs.Powershell.Dispose()
        }
        $runspacePool.Close()
        $runspacePool.Dispose()
        Remove-Item -LiteralPath $payloadFile -Force -ErrorAction SilentlyContinue

        if ($warnDetected) {
            wlog "" "Default"
            wlog "[WARNING] Detected possible DPI TCP 16-20 blocking on one or more targets. Consider changing strategy/SNI/IP." "Red"
        } else {
            wlog "" "Default"
            wlog "[OK] No 16-20KB freeze pattern detected across targets." "Green"
        }

        return $results
    }

    # ---- pre-flight ----
    $runningWinws = Get-Process -Name "winws" -ErrorAction SilentlyContinue
    if ($runningWinws) {
        wlog "[INFO] winws is running (PID: $($runningWinws.Id -join ', ')). Will be stopped before each config." "Yellow"
    }

    $ipsetFlagFile = Join-Path $rootDir "ipset_switched.flag"
    if (Test-Path $ipsetFlagFile) {
        wlog "[INFO] Detected leftover ipset flag. Restoring..." "Yellow"
        Set-IpsetMode -mode "restore"
        Remove-Item $ipsetFlagFile -ErrorAction SilentlyContinue
    }

    $originalIpsetStatus = Get-IpsetStatus
    if ($originalIpsetStatus -ne "any") {
        wlog "[INFO] Current ipset status: $originalIpsetStatus" "Cyan"
        if ($testType -eq 'dpi') {
            wlog "[WARNING] Ipset will be switched to 'any' for accurate DPI tests." "Yellow"
            wlog "[WARNING] If you close the window, ipset will be restored on next run." "Yellow"
        }
    }

    $dpiTargets = @()
    if ($testType -eq 'dpi') {
        $dpiTargets = Build-DpiTargets -CustomHost $dpiCustomHost
    }

    $targetList = @()
    $maxNameLen = 10
    if ($testType -eq 'standard') {
        $targetsFile = Join-Path $utilsDir "targets.txt"
        $rawTargets  = New-OrderedDict
        if (Test-Path $targetsFile) {
            Get-Content $targetsFile | ForEach-Object {
                if ($_ -match '^\s*(\w+)\s*=\s*"(.+)"\s*$') {
                    Add-OrSet -dict $rawTargets -key $matches[1] -val $matches[2]
                }
            }
        }
        if ($rawTargets.Count -eq 0) {
            wlog "[INFO] targets.txt missing or empty. Using defaults." "DarkGray"
            Add-OrSet $rawTargets "Discord Main"           "https://discord.com"
            Add-OrSet $rawTargets "Discord Gateway"        "https://gateway.discord.gg"
            Add-OrSet $rawTargets "Discord CDN"            "https://cdn.discordapp.com"
            Add-OrSet $rawTargets "Discord Updates"        "https://updates.discord.com"
            Add-OrSet $rawTargets "YouTube Web"            "https://www.youtube.com"
            Add-OrSet $rawTargets "YouTube Short"          "https://youtu.be"
            Add-OrSet $rawTargets "YouTube Image"          "https://i.ytimg.com"
            Add-OrSet $rawTargets "YouTube Video Redirect" "https://redirector.googlevideo.com"
            Add-OrSet $rawTargets "Google Main"            "https://www.google.com"
            Add-OrSet $rawTargets "Google Gstatic"         "https://www.gstatic.com"
            Add-OrSet $rawTargets "Cloudflare Web"         "https://www.cloudflare.com"
            Add-OrSet $rawTargets "Cloudflare CDN"         "https://cdnjs.cloudflare.com"
            Add-OrSet $rawTargets "Cloudflare DNS 1.1.1.1" "PING:1.1.1.1"
            Add-OrSet $rawTargets "Cloudflare DNS 1.0.0.1" "PING:1.0.0.1"
            Add-OrSet $rawTargets "Google DNS 8.8.8.8"     "PING:8.8.8.8"
            Add-OrSet $rawTargets "Google DNS 8.8.4.4"     "PING:8.8.4.4"
            Add-OrSet $rawTargets "Quad9 DNS 9.9.9.9"      "PING:9.9.9.9"
        } else {
            wlog "[INFO] Loaded targets from targets.txt  ($($rawTargets.Count))" "DarkGray"
        }
        foreach ($k in $rawTargets.Keys) {
            $targetList += Convert-Target -Name $k -Value $rawTargets[$k]
        }
        $maxNameLen = ($targetList | ForEach-Object { $_.Name.Length } | Measure-Object -Maximum).Maximum
        if (-not $maxNameLen -or $maxNameLen -lt 10) { $maxNameLen = 10 }
    }

    $env:NO_UPDATE_CHECK = "1"
    $originalWinws = Get-WinwsSnapshot

    wlog "" "Default"
    wlog "============================================================" "Cyan"
    wlog "             ZAPRET CONFIG TESTS" "Cyan"
    wlog "             Mode: $($testType.ToUpper())" "Cyan"
    wlog "             Total configs: $($selFiles.Count)" "Cyan"
    wlog "============================================================" "Cyan"

    $globalResults = @()

    try {
        if (($originalIpsetStatus -ne "any") -and ($testType -eq 'dpi')) {
            wlog "[WARNING] Switching ipset to 'any' for accurate DPI tests..." "Yellow"
            Set-IpsetMode -mode "any"
            "" | Out-File -FilePath $ipsetFlagFile -Encoding UTF8
        }
        wlog "[WARNING] Tests may take several minutes. Please wait..." "Yellow"

        $configNum = 0
        foreach ($file in $selFiles) {
            $configNum++

            wlog "" "Default"
            wlog "------------------------------------------------------------" "DarkCyan"
            wlog "  [$configNum/$($selFiles.Count)] $($file.Name)" "Yellow"
            wlog "------------------------------------------------------------" "DarkCyan"

            Stop-Zapret

            wlog "  > Starting config..." "Cyan"
            $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$($file.FullName)`"" `
                        -WorkingDirectory $rootDir -PassThru -WindowStyle Minimized

            if (-not (Wait-WinwsReady)) {
                wlog "  > Strategy failed to start (winws process not found). Skipping..." "Red"
                if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
                $progState.Current = $configNum
                continue
            }

            if ($testType -eq 'standard') {
                $curlTimeoutSeconds = $standardCurlTimeout
                $maxParallel        = $standardMaxParallel
                $runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxParallel)
                $runspacePool.Open()

                $stdScriptBlock = {
                    param($t, $curlTimeoutSeconds)
                    $httpPieces = @()
                    if ($t.Url) {
                        $tests = @(
                            @{ Label = "HTTP";   Args = @("--http1.1") },
                            @{ Label = "TLS1.2"; Args = @("--tlsv1.2", "--tls-max", "1.2") },
                            @{ Label = "TLS1.3"; Args = @("--tlsv1.3", "--tls-max", "1.3") }
                        )
                        $baseArgs = @("-I", "-s", "-m", $curlTimeoutSeconds, "--connect-timeout", ([Math]::Min(2, $curlTimeoutSeconds)), "-o", "NUL", "-w", "%{http_code}", "--show-error")
                        foreach ($test in $tests) {
                            try {
                                $curlArgs = $baseArgs + $test.Args
                                $stderr = $null
                                $output = & curl.exe @curlArgs $t.Url 2>&1 | ForEach-Object {
                                    if ($_ -is [System.Management.Automation.ErrorRecord]) {
                                        $stderr += $_.Exception.Message + " "
                                    } else { $_ }
                                }
                                $httpCode = ($output | Out-String).Trim()

                                $dnsHijack = ($stderr -match "Could not resolve host|certificate|SSL certificate problem|self[- ]?signed|certificate verify failed|unable to get local issuer certificate")
                                if ($dnsHijack) {
                                    $httpPieces += "$($test.Label):SSL  "
                                    continue
                                }

                                $unsupported = (($LASTEXITCODE -eq 35) -or ($stderr -match "does not support|not supported|protocol\s+'?.+'?\s+not\s+supported|unsupported protocol|TLS.*not supported|Unrecognized option|Unknown option|unsupported option|unsupported feature|schannel"))
                                if ($unsupported) {
                                    $httpPieces += "$($test.Label):UNSUP"
                                    continue
                                }

                                $httpPieces += if ($LASTEXITCODE -eq 0) { "$($test.Label):OK   " } else { "$($test.Label):ERROR" }
                            } catch {
                                $httpPieces += "$($test.Label):ERROR"
                            }
                        }
                    }

                    $pingResult = "n/a"
                    if ($t.PingTarget) {
                        $ping = $null
                        try {
                            $ping = New-Object System.Net.NetworkInformation.Ping
                            $reply = $ping.Send($t.PingTarget, 1000)
                            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                                $pingResult = "{0:N0} ms" -f $reply.RoundtripTime
                            } else {
                                $pingResult = "Timeout"
                            }
                        } catch {
                            $pingResult = "Timeout"
                        } finally {
                            if ($ping) { $ping.Dispose() }
                        }
                    }

                    return New-Object PSObject -Property @{
                        Name       = $t.Name
                        HttpTokens = $httpPieces
                        PingResult = $pingResult
                        IsUrl      = [bool]$t.Url
                    }
                }

                $runspaces = @()
                foreach ($target in $targetList) {
                    $ps = [powershell]::Create().AddScript($stdScriptBlock)
                    [void]$ps.AddArgument($target)
                    [void]$ps.AddArgument($curlTimeoutSeconds)
                    $ps.RunspacePool = $runspacePool
                    $runspaces += [PSCustomObject]@{ Powershell = $ps; Handle = $ps.BeginInvoke() }
                }

                wlog "  > Running tests..." "DarkGray"

                $targetResults = @()
                foreach ($rs in $runspaces) {
                    try {
                        $waitMs = (([int]$curlTimeoutSeconds * 3) + 5) * 1000
                        if ($rs.Handle -and $rs.Handle.AsyncWaitHandle) {
                            $ok = $rs.Handle.AsyncWaitHandle.WaitOne($waitMs)
                            if (-not $ok) {
                                wlog "[WARN] Runspace timed out." "Yellow"
                                try { $rs.Powershell.Stop() } catch {}
                            }
                        }
                    } catch {}
                    try { $targetResults += $rs.Powershell.EndInvoke($rs.Handle) }
                    catch {
                        wlog "[WARN] EndInvoke failed; treating as failure." "Yellow"
                        $targetResults += [PSCustomObject]@{ Name = 'UNKNOWN'; HttpTokens = @('HTTP:ERROR'); PingResult = 'Timeout'; IsUrl = $true }
                    }
                    $rs.Powershell.Dispose()
                }
                $runspacePool.Close(); $runspacePool.Dispose()

                $targetLookup = @{}
                foreach ($res in $targetResults) { $targetLookup[$res.Name] = $res }

                foreach ($target in $targetList) {
                    $res = $targetLookup[$target.Name]
                    if (-not $res) { continue }
                    $prefix = "  $($target.Name.PadRight($maxNameLen))   "
                    if ($res.IsUrl -and $res.HttpTokens) {
                        $parts = @()
                        $parts += [pscustomobject]@{ Text = $prefix; Color = "Default" }
                        foreach ($tok in $res.HttpTokens) {
                            $tc = "Green"
                            if ($tok -match "UNSUP") { $tc = "Yellow" }
                            elseif ($tok -match "SSL|ERROR") { $tc = "Red" }
                            $parts += [pscustomobject]@{ Text = " $tok"; Color = $tc }
                        }
                        $pingCol = if ($res.PingResult -eq "Timeout") { "Yellow" } else { "Cyan" }
                        $parts += [pscustomobject]@{ Text = " | Ping: "; Color = "DarkGray" }
                        $parts += [pscustomobject]@{ Text = "$($res.PingResult)"; Color = $pingCol }
                        [void]$msgList.Add([pscustomobject]@{ Text = ($parts | ConvertTo-Json -Compress); Color = "MULTIPART" })
                    } else {
                        $pingCol = if ($res.PingResult -eq "Timeout") { "Red" } else { "Cyan" }
                        wlog "$prefix Ping: $($res.PingResult)" $pingCol
                    }
                }

                $globalResults += @{ Config = $file.Name; Type = 'standard'; Results = $targetResults }

            } else {
                # DPI mode
                wlog "  > Running DPI checkers..." "DarkGray"
                $dpiResults = Invoke-DpiSuite -Targets $dpiTargets `
                    -TimeoutSeconds $dpiTimeoutSeconds `
                    -RangeBytes     $dpiRangeBytes `
                    -MaxParallel    $dpiMaxParallel
                $globalResults += @{ Config = $file.Name; Type = 'dpi'; Results = $dpiResults }
            }

            Stop-Zapret
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
            $progState.Current = $configNum
        }

        # ---- Analytics ----
        wlog "" "Default"
        wlog "All tests finished." "Green"
        wlog "" "Default"
        wlog "=== ANALYTICS ===" "Cyan"

        $analytics = @{}
        foreach ($res in $globalResults) {
            if ($res.Type -eq 'standard') {
                foreach ($tr in $res.Results) {
                    $cfg = $res.Config
                    if (-not $analytics.ContainsKey($cfg)) { $analytics[$cfg] = @{ OK = 0; ERROR = 0; UNSUP = 0; PingOK = 0; PingFail = 0 } }
                    if ($tr.IsUrl) {
                        foreach ($tok in $tr.HttpTokens) {
                            if ($tok -match "OK")    { $analytics[$cfg].OK++ }
                            elseif ($tok -match "SSL|ERROR") { $analytics[$cfg].ERROR++ }
                            elseif ($tok -match "UNSUP") { $analytics[$cfg].UNSUP++ }
                        }
                    }
                    if ($tr.PingResult -ne "Timeout" -and $tr.PingResult -ne "n/a") { $analytics[$cfg].PingOK++ } else { $analytics[$cfg].PingFail++ }
                }
            } elseif ($res.Type -eq 'dpi') {
                foreach ($tr in $res.Results) {
                    $cfg = $res.Config
                    if (-not $analytics.ContainsKey($cfg)) { $analytics[$cfg] = @{ OK = 0; FAIL = 0; UNSUPPORTED = 0; LIKELY_BLOCKED = 0 } }
                    foreach ($line in $tr.Lines) {
                        switch ($line.Status) {
                            "OK"             { $analytics[$cfg].OK++ }
                            "FAIL"           { $analytics[$cfg].FAIL++ }
                            "UNSUPPORTED"    { $analytics[$cfg].UNSUPPORTED++ }
                            "LIKELY_BLOCKED" { $analytics[$cfg].LIKELY_BLOCKED++ }
                        }
                    }
                }
            }
        }

        $maxConfigLen = ($analytics.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        foreach ($cfg in $analytics.Keys) {
            $a = $analytics[$cfg]
            $configPadded = $cfg.PadRight($maxConfigLen)
            if ($a.ContainsKey('PingOK')) {
                wlog ("{0} : HTTP OK: {1,3}, ERR: {2,3}, UNSUP: {3,3}, Ping OK: {4,3}, Fail: {5,3}" -f `
                    $configPadded, $a.OK, $a.ERROR, $a.UNSUP, $a.PingOK, $a.PingFail) "Yellow"
            } else {
                wlog ("{0} : OK: {1,3}, FAIL: {2,3}, UNSUP: {3,3}, BLOCKED: {4,3}" -f `
                    $configPadded, $a.OK, $a.FAIL, $a.UNSUPPORTED, $a.LIKELY_BLOCKED) "Yellow"
            }
        }

        # Best config
        $bestConfig = $null; $maxScore = 0; $maxPing = -1
        foreach ($cfg in $analytics.Keys) {
            $a = $analytics[$cfg]; $score = $a.OK; $pingScore = 0
            if ($a.ContainsKey('PingOK')) { $pingScore = $a.PingOK }
            if ($score -gt $maxScore) {
                $maxScore = $score; $maxPing = $pingScore; $bestConfig = $cfg
            } elseif ($score -eq $maxScore -and $pingScore -gt $maxPing) {
                $maxPing = $pingScore; $bestConfig = $cfg
            }
        }
        wlog "" "Default"
        wlog "Best config: $bestConfig" "Green"
        wlog "" "Default"

        # Save to file
        $dateStr    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $resultFile = Join-Path $resultsDir "test_results_$dateStr.txt"
        $resultLines = New-Object System.Collections.Generic.List[string]
        foreach ($res in $globalResults) {
            [void]$resultLines.Add("Config: $($res.Config) (Type: $($res.Type))")
            if ($res.Type -eq 'standard') {
                foreach ($tr in $res.Results) {
                    [void]$resultLines.Add("  $($tr.Name) : $($tr.HttpTokens -join ' ') | Ping: $($tr.PingResult)")
                }
            } elseif ($res.Type -eq 'dpi') {
                foreach ($tr in $res.Results) {
                    if ($tr.Country) {
                        [void]$resultLines.Add("  Target: [$($tr.Country)] $($tr.TargetId) ($($tr.Provider))")
                    } else {
                        [void]$resultLines.Add("  Target: $($tr.TargetId) ($($tr.Provider))")
                    }
                    foreach ($l in $tr.Lines) {
                        [void]$resultLines.Add("    $($l.TestLabel): code=$($l.Code)  up=$($l.UpKB) KB  down=$($l.DownKB) KB  time=$($l.Time)s  status=$($l.Status)")
                    }
                }
            }
            [void]$resultLines.Add("")
        }
        [void]$resultLines.Add("=== ANALYTICS ===")
        foreach ($cfg in $analytics.Keys) {
            $a = $analytics[$cfg]
            $configPadded = $cfg.PadRight($maxConfigLen)
            if ($a.ContainsKey('PingOK')) {
                [void]$resultLines.Add(("{0} : HTTP OK: {1,3}, ERR: {2,3}, UNSUP: {3,3}, Ping OK: {4,3}, Fail: {5,3}" -f `
                    $configPadded, $a.OK, $a.ERROR, $a.UNSUP, $a.PingOK, $a.PingFail))
            } else {
                [void]$resultLines.Add(("{0} : OK: {1,3}, FAIL: {2,3}, UNSUP: {3,3}, BLOCKED: {4,3}" -f `
                    $configPadded, $a.OK, $a.FAIL, $a.UNSUPPORTED, $a.LIKELY_BLOCKED))
            }
        }
        [void]$resultLines.Add("Best strategy: $bestConfig")
        $resultLines | Set-Content $resultFile -Encoding UTF8

        wlog "Results saved to $resultFile" "Green"
        $progState.Current = $selFiles.Count

    } catch {
        wlog "[ERROR] $($_.Exception.Message)" "Red"
        $progState.Error = $_.Exception.Message
    } finally {
        Stop-Zapret
        Restore-WinwsSnapshot -snapshot $originalWinws
        if ($originalIpsetStatus -ne "any") {
            wlog "[INFO] Restoring original ipset mode..." "DarkGray"
            Set-IpsetMode -mode "restore"
        }
        Remove-Item -Path $ipsetFlagFile -ErrorAction SilentlyContinue
        $progState.Done = $true
    }
}

# ---------------------------------------------------------------------------
# Launch background runspace
# ---------------------------------------------------------------------------
$bgRS = [runspacefactory]::CreateRunspace()
$bgRS.ApartmentState = "STA"
$bgRS.ThreadOptions  = "ReuseThread"
$bgRS.Open()

$bgPS = [powershell]::Create()
$bgPS.Runspace = $bgRS
[void]$bgPS.AddScript($bgScript)
[void]$bgPS.AddArgument($selFiles)
[void]$bgPS.AddArgument($testType)
[void]$bgPS.AddArgument($rootDir)
[void]$bgPS.AddArgument($listsDir)
[void]$bgPS.AddArgument($utilsDir)
[void]$bgPS.AddArgument($resultsDir)
[void]$bgPS.AddArgument($msgList)
[void]$bgPS.AddArgument($progState)
[void]$bgPS.BeginInvoke()

# ---------------------------------------------------------------------------
# UI poll timer
# ---------------------------------------------------------------------------
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 80

$timer.Add_Tick({
    $snapshot = $null
    [System.Threading.Monitor]::Enter($msgList.SyncRoot)
    try {
        if ($msgList.Count -gt 0) {
            $snapshot = $msgList.ToArray()
            $msgList.Clear()
        }
    } finally { [System.Threading.Monitor]::Exit($msgList.SyncRoot) }

    if ($snapshot) {
        foreach ($m in $snapshot) {
            if ($m.Color -eq "MULTIPART") {
                Append-Log-Multipart $m.Text
            } else {
                $col = if ($colorMap.ContainsKey($m.Color)) { $colorMap[$m.Color] } else { $C.Light }
                Append-Log $m.Text $col
            }
        }
    }

    $cur   = $progState.Current
    $total = $progState.Total
    if ($total -gt 0) {
        $pct = [math]::Min(100, [int]($cur / $total * 100))
        $progBar.Value = $pct
        $lblCount.Text = "$cur / $total"
    }

    if ($progState.Done) {
        $timer.Stop()
        if ($progState.Error) {
            $w3.Text = "Zapret Test Runner  -  ERROR  (close window to exit)"
        } else {
            $progBar.Value = 100
            $lblCount.Text = "$($selFiles.Count) / $($selFiles.Count)"
            $w3.Text = "Zapret Test Runner  -  Done! (close window to exit)"
        }
        try { $bgPS.Dispose() } catch {}
        try { $bgRS.Close(); $bgRS.Dispose() } catch {}
    }
})

$w3.Add_FormClosing({
    if (-not $progState.Done) {
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Tests are still running. Close anyway?",
            "Confirm close",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($r -ne [System.Windows.Forms.DialogResult]::Yes) {
            $_.Cancel = $true
            return
        }
        $timer.Stop()
        try { $bgPS.Stop(); $bgPS.Dispose() } catch {}
        try { $bgRS.Close(); $bgRS.Dispose() } catch {}
    }
})

$w3.Add_Shown({ $timer.Start() })
[void]$w3.ShowDialog()