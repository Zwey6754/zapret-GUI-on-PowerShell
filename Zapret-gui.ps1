Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

Add-Type -Name Win -Namespace Native -MemberDefinition '[DllImport("Kernel32.dll")]public static extern IntPtr GetConsoleWindow();[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'
[Native.Win]::ShowWindow([Native.Win]::GetConsoleWindow(), 0) | Out-Null

$LOCAL_VERSION = "1.10.4"
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

$colors = @{
    Primary = [System.Drawing.Color]::FromArgb(41, 128, 185)
    Success = [System.Drawing.Color]::FromArgb(39, 174, 96)
    Warning = [System.Drawing.Color]::FromArgb(243, 156, 18)
    Danger = [System.Drawing.Color]::FromArgb(231, 76, 60)
    Dark = [System.Drawing.Color]::FromArgb(44, 62, 80)
    Light = [System.Drawing.Color]::FromArgb(236, 240, 241)
    White = [System.Drawing.Color]::White
    DarkPrimary = [System.Drawing.Color]::FromArgb(31, 97, 141)
    DarkSuccess = [System.Drawing.Color]::FromArgb(29, 131, 72)
    DarkWarning = [System.Drawing.Color]::FromArgb(183, 118, 14)
    DarkDanger = [System.Drawing.Color]::FromArgb(173, 57, 43)
    DarkGray = [System.Drawing.Color]::FromArgb(52, 73, 94)
    Midnight = [System.Drawing.Color]::FromArgb(33, 47, 61)
    Steel = [System.Drawing.Color]::FromArgb(66, 73, 83)
    Slate = [System.Drawing.Color]::FromArgb(79, 90, 101)
}

function Get-ServiceStatus {
    param([string]$ServiceName)
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) { return $svc.Status.ToString() }
    } catch {}
    return "NOT FOUND"
}

function Get-CurrentConfig {
    try {
        $regValue = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\zapret" -Name "zapret-discord-youtube" -ErrorAction SilentlyContinue)."zapret-discord-youtube"
        if ($regValue) { return $regValue }
    } catch {}
    return $null
}

function Get-ServiceInfo {
    $info = @{
        Installed = $false
        Running = $false
        Config = $null
        Status = "Not installed"
    }
    
    $service = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
    if ($service) {
        $info.Installed = $true
        $info.Running = ($service.Status -eq "Running")
        $info.Config = Get-CurrentConfig
        $info.Status = if ($info.Running) { "Running [$($info.Config)]" } else { "Stopped [$($info.Config)]" }
    }
    
    return $info
}

function Update-StatusBar {
    param([string]$Message, [string]$Type = "Info")
    $statusLabel.Text = "  $Message"
    
    $statusIcon.Text = "●"
    
    switch ($Type) {
        "Success" { 
            $statusLabel.ForeColor = $colors.Light
            $statusIcon.ForeColor = $colors.Success
            $statusPanel.BackColor = $colors.DarkSuccess
        }
        "Warning" { 
            $statusLabel.ForeColor = $colors.Light
            $statusIcon.ForeColor = $colors.Warning
            $statusPanel.BackColor = $colors.DarkWarning
        }
        "Error"   { 
            $statusLabel.ForeColor = $colors.Light
            $statusIcon.ForeColor = $colors.Danger
            $statusPanel.BackColor = $colors.DarkDanger
        }
        "Info"    { 
            $statusLabel.ForeColor = $colors.Light
            $statusIcon.ForeColor = $colors.Primary
            $statusPanel.BackColor = $colors.DarkPrimary
        }
        "Service" { 
            $statusLabel.ForeColor = $colors.Light
            $statusIcon.ForeColor = $colors.Steel
            $statusPanel.BackColor = $colors.Dark
        }
        default   { 
            $statusLabel.ForeColor = $colors.Light
            $statusIcon.ForeColor = $colors.Primary
            $statusPanel.BackColor = $colors.DarkPrimary
        }
    }
    [System.Windows.Forms.Application]::DoEvents()
}

function Update-ServiceStatusBar {
    $serviceInfo = Get-ServiceInfo
    if ($serviceInfo.Installed) {
        if ($serviceInfo.Running) {
            Update-StatusBar "Service: $($serviceInfo.Status)" "Success"
        } else {
            Update-StatusBar "Service: $($serviceInfo.Status)" "Warning"
        }
    } else {
        Update-StatusBar "Service: Not installed" "Info"
    }
}

function Show-Progress {
    try { $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor; [System.Windows.Forms.Application]::DoEvents() } catch {}
}

function Hide-Progress {
    try { $form.Cursor = [System.Windows.Forms.Cursors]::Default } catch {}
}

function Test-GameFilterRange {
    # Same rules as service.bat (:validate_game_filter_range):
    # comma-separated ports / ranges, 1..65535, start <= end, spaces ignored.
    # Returns the normalized string, or $null if invalid.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $clean = $Text -replace '\s', ''
    if (-not $clean) { return $null }
    foreach ($item in $clean.Split(',')) {
        if ($item -notmatch '^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?$') { return $null }
        $parts = $item.Split('-')
        $start = [int]$parts[0]
        $end   = if ($parts.Count -gt 1) { [int]$parts[1] } else { $start }
        if ($start -gt 65535 -or $end -gt 65535 -or $start -gt $end) { return $null }
    }
    return $clean
}

function Get-GameFilterSettings {
    # utils\game_filter.enabled formats:
    #   new (1.10.4+):  mode=all|tcp|udp|disabled / tcp=<ports> / udp=<ports>
    #   legacy:         a single word: all | tcp | udp
    $default = "1024-65535"
    $s = @{ Mode = "disabled"; TCPRange = $default; UDPRange = $default }
    $flagFile = Join-Path $ScriptPath "utils\game_filter.enabled"
    if (-not (Test-Path $flagFile)) { return $s }

    $tcpCandidate = $null
    $udpCandidate = $null
    foreach ($line in @(Get-Content $flagFile -ErrorAction SilentlyContinue)) {
        $line = ($line + "").Trim()
        if (-not $line) { continue }
        $key = $line
        $val = $null
        $eq = $line.IndexOf('=')
        if ($eq -ge 0) {
            $key = $line.Substring(0, $eq)
            $val = $line.Substring($eq + 1)
        }
        switch ($key.Trim().ToLower()) {
            "mode" { $s.Mode = ($val + "").Trim().ToLower() }
            "all"  { $s.Mode = "all" }
            "tcp"  { if ([string]::IsNullOrEmpty($val)) { $s.Mode = "tcp" } else { $tcpCandidate = $val } }
            "udp"  { if ([string]::IsNullOrEmpty($val)) { $s.Mode = "udp" } else { $udpCandidate = $val } }
        }
    }

    $v = Test-GameFilterRange $tcpCandidate
    if ($v) { $s.TCPRange = $v }
    $v = Test-GameFilterRange $udpCandidate
    if ($v) { $s.UDPRange = $v }
    return $s
}

function Get-GameFilterStatus {
    $g   = Get-GameFilterSettings
    $tcp = $g.TCPRange
    $udp = $g.UDPRange
    switch ($g.Mode) {
        "all" { return @{Status="enabled (TCP+UDP)"; Mode="all"; Filter=$tcp; FilterTCP=$tcp; FilterUDP=$udp; TCPRange=$tcp; UDPRange=$udp} }
        "tcp" { return @{Status="enabled (TCP)";     Mode="tcp"; Filter=$tcp; FilterTCP=$tcp; FilterUDP="12"; TCPRange=$tcp; UDPRange=$udp} }
        "udp" { return @{Status="enabled (UDP)";     Mode="udp"; Filter=$udp; FilterTCP="12"; FilterUDP=$udp; TCPRange=$tcp; UDPRange=$udp} }
        default { return @{Status="disabled";        Mode="disabled"; Filter="12"; FilterTCP="12"; FilterUDP="12"; TCPRange=$tcp; UDPRange=$udp} }
    }
}

function Save-GameFilterSettings {
    param([string]$Mode, [string]$TCPRange, [string]$UDPRange)
    $utilsPath = Join-Path $ScriptPath "utils"
    if (-not (Test-Path $utilsPath)) { New-Item -ItemType Directory -Path $utilsPath -Force | Out-Null }
    $flagFile = Join-Path $utilsPath "game_filter.enabled"
    # same file format as service.bat (:save_game_filter_settings)
    $content = "mode=$Mode`r`ntcp=$TCPRange`r`nudp=$UDPRange`r`n"
    Write-Utf8NoBom -FilePath $flagFile -Content $content
}

function Get-IPSetStatus {
    $listFile = Join-Path $ScriptPath "lists\ipset-all.txt"
    if (-not (Test-Path $listFile)) { return "any" }
    $content = Get-Content $listFile -ErrorAction SilentlyContinue
    if ($content.Count -eq 0) { return "any" }
    if ($content -match "^203\.0\.113\.113/32$") { return "none" }
    return "loaded"
}

function Get-UpdateCheckStatus {
    $flagFile = Join-Path $ScriptPath "utils\check_updates.enabled"
    if (Test-Path $flagFile) { return "enabled" }
    return "disabled"
}

function Write-Utf8NoBom {
    param([string]$FilePath, [string]$Content)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($FilePath, $Content, $utf8NoBom)
}

function Initialize-UserLists {
    $listsPath = Join-Path $ScriptPath "lists"
    if (-not (Test-Path $listsPath)) { New-Item -ItemType Directory -Path $listsPath -Force | Out-Null }

    $defaults = @{
        "ipset-exclude-user.txt"  = "203.0.113.113/32"
        "list-general-user.txt"   = "domain.example.abc"
        "list-exclude-user.txt"   = "domain.example.abc"
    }
    foreach ($fileName in $defaults.Keys) {
        $filePath = Join-Path $listsPath $fileName
        if (-not (Test-Path $filePath)) {
            Write-Utf8NoBom -FilePath $filePath -Content $defaults[$fileName]
        }
    }
}

function Open-UserListEditor {
    param(
        [string]$FilePath,
        [string]$Title,
        [string]$IsIP,
        [string]$DefaultContent,
        [string]$HintText,
        [string]$Description
    )

    # Load raw content as-is - no filtering
    $currentText = ""
    if (Test-Path $FilePath) {
        $currentText = (Get-Content $FilePath -Encoding UTF8 -Raw)
        if ($null -eq $currentText) { $currentText = "" }
        $currentText = $currentText.TrimEnd()
    }

    $script:editorModified = $false

    #  Editor form 
    $ef = New-Object System.Windows.Forms.Form
    $ef.Text = "User List Editor - $Title"
    $ef.Size = New-Object System.Drawing.Size(560, 620)
    $ef.StartPosition = "CenterScreen"
    $ef.BackColor = $colors.Midnight
    $ef.FormBorderStyle = "Sizable"
    $ef.MinimumSize = New-Object System.Drawing.Size(420, 440)

    #  Top description panel (2 lines) 
    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = "Top"
    $topPanel.Height = 62
    $topPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 40, 54)
    $ef.Controls.Add($topPanel)

    $descLbl = New-Object System.Windows.Forms.Label
    $descLbl.Location = New-Object System.Drawing.Point(12, 8)
    $descLbl.Size = New-Object System.Drawing.Size(530, 22)
    $descLbl.Text = $Description
    $descLbl.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $descLbl.ForeColor = [System.Drawing.Color]::FromArgb(200, 210, 220)
    $topPanel.Controls.Add($descLbl)

    $hintLbl = New-Object System.Windows.Forms.Label
    $hintLbl.Location = New-Object System.Drawing.Point(12, 33)
    $hintLbl.Size = New-Object System.Drawing.Size(530, 20)
    $hintLbl.Text = $HintText
    $hintLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $hintLbl.ForeColor = [System.Drawing.Color]::FromArgb(130, 150, 170)
    $topPanel.Controls.Add($hintLbl)

    #  Bottom panel 
    $bottomPanel = New-Object System.Windows.Forms.Panel
    $bottomPanel.Dock = "Bottom"
    $bottomPanel.Height = 56
    $bottomPanel.BackColor = [System.Drawing.Color]::FromArgb(36, 47, 61)
    $ef.Controls.Add($bottomPanel)

    # Save button
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Location = New-Object System.Drawing.Point(10, 10)
    $btnSave.Size = New-Object System.Drawing.Size(120, 36)
    $btnSave.Text = "Save  (Ctrl+S)"
    $btnSave.BackColor = $colors.Success
    $btnSave.ForeColor = $colors.White
    $btnSave.FlatStyle = "Flat"
    $btnSave.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnSave.Cursor = [System.Windows.Forms.Cursors]::Hand
    $bottomPanel.Controls.Add($btnSave)

    # Reset to defaults button
    $btnReset = New-Object System.Windows.Forms.Button
    $btnReset.Location = New-Object System.Drawing.Point(140, 10)
    $btnReset.Size = New-Object System.Drawing.Size(140, 36)
    $btnReset.Text = "Reset to Default"
    $btnReset.BackColor = $colors.DarkWarning
    $btnReset.ForeColor = $colors.White
    $btnReset.FlatStyle = "Flat"
    $btnReset.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnReset.Cursor = [System.Windows.Forms.Cursors]::Hand
    $bottomPanel.Controls.Add($btnReset)

    # Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Location = New-Object System.Drawing.Point(290, 10)
    $btnClose.Size = New-Object System.Drawing.Size(100, 36)
    $btnClose.Text = "Close"
    $btnClose.BackColor = $colors.Slate
    $btnClose.ForeColor = $colors.White
    $btnClose.FlatStyle = "Flat"
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnClose.Cursor = [System.Windows.Forms.Cursors]::Hand
    $bottomPanel.Controls.Add($btnClose)

    # Status label
    $statusLbl = New-Object System.Windows.Forms.Label
    $statusLbl.Location = New-Object System.Drawing.Point(400, 16)
    $statusLbl.Size = New-Object System.Drawing.Size(150, 24)
    $statusLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $statusLbl.ForeColor = [System.Drawing.Color]::FromArgb(130, 150, 170)
    $statusLbl.TextAlign = "MiddleLeft"
    $lineCountInit = ($currentText -split "`n" | Where-Object { $_.Trim() -ne "" }).Count
    $statusLbl.Text = "$lineCountInit lines"
    $bottomPanel.Controls.Add($statusLbl)

    #  Main text area 
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = "Fill"
    $rtb.Text = $currentText
    $rtb.Font = New-Object System.Drawing.Font("Consolas", 11)
    $rtb.BackColor = [System.Drawing.Color]::FromArgb(40, 52, 68)
    $rtb.ForeColor = [System.Drawing.Color]::FromArgb(220, 230, 240)
    $rtb.BorderStyle = "None"
    $rtb.ScrollBars = "Vertical"
    $rtb.WordWrap = $false
    $rtb.AcceptsTab = $false
    $rtb.Padding = New-Object System.Windows.Forms.Padding(6)
    $ef.Controls.Add($rtb)
    $rtb.BringToFront()

    # Track changes
    $rtb.Add_TextChanged({
        $script:editorModified = $true
        $lc = ($rtb.Lines | Where-Object { $_.Trim() -ne "" }).Count
        $statusLbl.Text = "$lc lines  *"
        $statusLbl.ForeColor = $colors.Warning
    })

    #  Save logic 
    $doSave = {
        $lines = $rtb.Lines | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        if ($lines.Count -eq 0) {
            Write-Utf8NoBom -FilePath $FilePath -Content $DefaultContent
            $rtb.Text = $DefaultContent
            $count = 1
        } else {
            Write-Utf8NoBom -FilePath $FilePath -Content ($lines -join "`r`n")
            $count = $lines.Count
        }
        $script:editorModified = $false
        $statusLbl.Text = "$count lines  [saved]"
        $statusLbl.ForeColor = $colors.Success
        Update-StatusBar "Saved $Title ($count lines)" "Success"
    }

    $btnSave.Add_Click({ & $doSave })

    # Ctrl+S
    $ef.KeyPreview = $true
    $ef.Add_KeyDown({
        if ($_.Control -and $_.KeyCode -eq [System.Windows.Forms.Keys]::S) { & $doSave }
    })

    # Reset to defaults
    $btnReset.Add_Click({
        $r = [System.Windows.Forms.MessageBox]::Show(
            "Reset this list to its default value?`n`nAll your changes will be lost.",
            "Reset to Default",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
            $rtb.Text = $DefaultContent
            $script:editorModified = $true
            $statusLbl.Text = "reset - save to apply"
            $statusLbl.ForeColor = $colors.Warning
        }
    })

    $btnClose.Add_Click({ $ef.Close() })

    # Warn on unsaved close
    $ef.Add_FormClosing({
        if ($script:editorModified) {
            $r = [System.Windows.Forms.MessageBox]::Show(
                "You have unsaved changes.`n`nSave before closing?",
                "Unsaved Changes",
                [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {
                & $doSave
            } elseif ($r -eq [System.Windows.Forms.DialogResult]::Cancel) {
                $_.Cancel = $true
            }
        }
    })

    $ef.ShowDialog() | Out-Null
}

function Open-UserListsEditor {
    $listsPath = Join-Path $ScriptPath "lists"

    # List definitions with user-friendly text
    $fileMap = @(
        @{
            File    = "list-general-user.txt"
            IsIP    = "false"
            Default = "domain.example.abc"
            Label   = "Add domains to bypass  (list-general-user.txt)"
            Desc    = "Domains to bypass DPI - added to the main bypass list"
            Hint    = "One domain per line, e.g.:  discord.com     youtube.com     example.ru"
        },
        @{
            File    = "list-exclude-user.txt"
            IsIP    = "false"
            Default = "domain.example.abc"
            Label   = "Exclude domains from bypass  (list-exclude-user.txt)"
            Desc    = "Domains to exclude from bypass - these will NOT be processed by zapret"
            Hint    = "One domain per line, e.g.:  ads.example.com     tracker.site"
        },
        @{
            File    = "ipset-exclude-user.txt"
            IsIP    = "true"
            Default = "203.0.113.113/32"
            Label   = "Exclude IP addresses from bypass  (ipset-exclude-user.txt)"
            Desc    = "IP addresses / subnets to exclude from bypass (CIDR format)"
            Hint    = "One IP or subnet per line, e.g.:  1.2.3.4/32     10.0.0.0/8     192.168.1.1/32"
        }
    )

    #  Picker 
    $pf = New-Object System.Windows.Forms.Form
    $pf.Text = "User Lists"
    $pf.Size = New-Object System.Drawing.Size(480, 290)
    $pf.StartPosition = "CenterScreen"
    $pf.BackColor = $colors.Midnight
    $pf.FormBorderStyle = "FixedDialog"
    $pf.MaximizeBox = $false

    $headerLbl = New-Object System.Windows.Forms.Label
    $headerLbl.Location = New-Object System.Drawing.Point(15, 14)
    $headerLbl.Size = New-Object System.Drawing.Size(440, 22)
    $headerLbl.Text = "Which list do you want to edit?"
    $headerLbl.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $headerLbl.ForeColor = $colors.Light
    $pf.Controls.Add($headerLbl)

    $subLbl = New-Object System.Windows.Forms.Label
    $subLbl.Location = New-Object System.Drawing.Point(15, 38)
    $subLbl.Size = New-Object System.Drawing.Size(440, 18)
    $subLbl.Text = "Double-click or select and press Open"
    $subLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $subLbl.ForeColor = [System.Drawing.Color]::FromArgb(120, 140, 160)
    $pf.Controls.Add($subLbl)

    $lb = New-Object System.Windows.Forms.ListBox
    $lb.Location = New-Object System.Drawing.Point(15, 62)
    $lb.Size = New-Object System.Drawing.Size(440, 120)
    $lb.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lb.BackColor = [System.Drawing.Color]::FromArgb(52, 73, 94)
    $lb.ForeColor = [System.Drawing.Color]::FromArgb(220, 230, 240)
    $lb.BorderStyle = "None"
    $lb.ItemHeight = 26
    foreach ($entry in $fileMap) { $lb.Items.Add($entry.Label) | Out-Null }
    $lb.SelectedIndex = 0
    $pf.Controls.Add($lb)

    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Location = New-Object System.Drawing.Point(255, 200)
    $btnOK.Size = New-Object System.Drawing.Size(95, 36)
    $btnOK.Text = "Open"
    $btnOK.BackColor = $colors.Primary
    $btnOK.ForeColor = $colors.White
    $btnOK.FlatStyle = "Flat"
    $btnOK.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnOK.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $pf.Controls.Add($btnOK)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(360, 200)
    $btnCancel.Size = New-Object System.Drawing.Size(95, 36)
    $btnCancel.Text = "Cancel"
    $btnCancel.BackColor = $colors.Slate
    $btnCancel.ForeColor = $colors.White
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $btnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $pf.Controls.Add($btnCancel)

    $pf.AcceptButton = $btnOK
    $pf.CancelButton = $btnCancel
    $lb.Add_DoubleClick({ $pf.DialogResult = [System.Windows.Forms.DialogResult]::OK; $pf.Close() })

    $result = $pf.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $idx = $lb.SelectedIndex
    if ($idx -lt 0) { return }
    $def      = $fileMap[$idx]
    $filePath = Join-Path $listsPath $def.File

    # Ensure file exists with default content if missing
    if (-not (Test-Path $listsPath)) { New-Item -ItemType Directory -Path $listsPath -Force | Out-Null }
    if (-not (Test-Path $filePath)) {
        Write-Utf8NoBom -FilePath $filePath -Content $def.Default
    }

    Open-UserListEditor `
        -FilePath        $filePath `
        -Title           $def.File `
        -IsIP            $def.IsIP `
        -DefaultContent  $def.Default `
        -HintText        $def.Hint `
        -Description     $def.Desc
}

function Update-StatusDisplay {
    $serviceInfo = Get-ServiceInfo
    $gameStatus = Get-GameFilterStatus
    $btnGameFilter.Text = "Game Filter [$($gameStatus.Status)]"
    $ipsetStatus = Get-IPSetStatus
    $btnIPSet.Text = "IPSet Filter [$ipsetStatus]"
    $updateStatus = Get-UpdateCheckStatus
    $btnAutoUpdate.Text = "Auto-Update [$updateStatus]"
    
    if ($serviceInfo.Installed) {
        $btnStopService.Enabled = $serviceInfo.Running
        $btnStartService.Enabled = -not $serviceInfo.Running
        $btnStopService.BackColor = if ($serviceInfo.Running) { $colors.Danger } else { $colors.Slate }
        $btnStartService.BackColor = if (-not $serviceInfo.Running) { $colors.Success } else { $colors.Slate }
    } else {
        $btnStopService.Enabled = $false
        $btnStartService.Enabled = $false
        $btnStopService.BackColor = $colors.Slate
        $btnStartService.BackColor = $colors.Slate
    }
}

function Stop-ZapretService {
    param([bool]$Silent = $false)
    try {
        $zapretRunning = (Get-ServiceStatus "zapret") -eq "Running"
        if ($zapretRunning) {
            if (-not $Silent) { Update-StatusBar "Stopping Zapret service..." "Warning" }
            sc.exe stop zapret | Out-Null
            Start-Sleep -Milliseconds 500
        }
        $winwsProcess = Get-Process -Name winws -ErrorAction SilentlyContinue
        if ($winwsProcess) {
            Stop-Process -Name winws -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 300
        }
        return $zapretRunning
    } catch { return $false }
}

function Start-ZapretService {
    param([bool]$Silent = $false)
    try {
        $serviceInfo = Get-ServiceInfo
        if (-not $serviceInfo.Installed) {
            if (-not $Silent) {
                Update-StatusBar "Service not installed. Use Install first." "Error"
                [System.Windows.Forms.MessageBox]::Show(
                    "Service is not installed.`nPlease use 'Install Service' first.",
                    "Service Not Found",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
            return $false
        }
        
        if (-not $Silent) { Update-StatusBar "Starting Zapret service..." "Info" }
        sc.exe start zapret | Out-Null
        Start-Sleep -Milliseconds 500
        
        Start-Sleep -Seconds 2
        $newStatus = Get-ServiceStatus "zapret"
        if ($newStatus -eq "Running") {
            if (-not $Silent) { Update-StatusBar "Service started successfully!" "Success" }
            return $true
        } else {
            if (-not $Silent) { Update-StatusBar "Service failed to start" "Error" }
            return $false
        }
    } catch { 
        if (-not $Silent) { Update-StatusBar "Error starting service: $($_.Exception.Message)" "Error" }
        return $false 
    }
}

function Restart-ZapretService {
    $serviceInfo = Get-ServiceInfo
    if (-not $serviceInfo.Installed) {
        Update-StatusBar "Service not installed" "Error"
        return
    }
    
    Update-StatusBar "Restarting service..." "Warning"
    $stopped = Stop-ZapretService -Silent $true
    if ($stopped) {
        Start-Sleep -Seconds 1
        $started = Start-ZapretService -Silent $true
        if ($started) {
            Update-StatusBar "Service restarted successfully!" "Success"
        } else {
            Update-StatusBar "Failed to restart service" "Error"
        }
    } else {
        Update-StatusBar "Failed to stop service" "Error"
    }
    Update-ServiceStatusBar
    Update-StatusDisplay
}

function Parse-BatFileNew {
    param(
        [string]$FilePath,
        [string]$BinPath,
        [string]$ListsPath,
        [string]$GameFilter,
        [string]$GameFilterTCP = "12",
        [string]$GameFilterUDP = "12"
    )
    
    try {
        $content = Get-Content $FilePath -Raw -Encoding Default
        
        $content = $content -replace '(?m)^\s*::', ''
        $content = $content -replace '(?m)^\s*rem\s.*$', ''
        $content = $content -replace '\^\s*[\r\n]+\s*', ' '
        # batch escape: ^! -> ! (cmd.exe delayed-expansion escape, not needed once we bypass cmd.exe)
        $content = $content -replace '\^!', '!'
        
        $allMatches = [regex]::Matches($content, 'winws\.exe["\s]+(.*?)(?=[\r\n]+[^-\s]|$)', 
            [System.Text.RegularExpressions.RegexOptions]::Singleline)
        
        if ($allMatches.Count -eq 0) {
            return $null
        }
        
        $argsLine = ($allMatches | Sort-Object {$_.Groups[1].Value.Length} -Descending | Select-Object -First 1).Groups[1].Value.Trim()
        $argsLine = $argsLine -replace '^["'']\s*', ''
        $argsLine = $argsLine -replace '%BIN%', ($BinPath.TrimEnd('\') + '\')
        $argsLine = $argsLine -replace '%LISTS%', ($ListsPath.TrimEnd('\') + '\')
        $argsLine = $argsLine -replace '%GameFilter%', $GameFilter
        $argsLine = $argsLine -replace '%GameFilterTCP%', $GameFilterTCP
        $argsLine = $argsLine -replace '%GameFilterUDP%', $GameFilterUDP
        
        $argsLine = $argsLine -replace '"@([^"]+)"', {
            param($m)
            $p = $m.Groups[1].Value
            $f = Join-Path $ScriptPath $p
            return "`"$f`""
        }
        
        $argsLine = $argsLine -replace '"((?!.*:)[^"]+\.txt)"', {
            param($m)
            $p = $m.Groups[1].Value
            if ($p -notmatch '^[a-zA-Z]:') {
                $f = Join-Path $ScriptPath $p
                return "`"$f`""
            }
            return $m.Value
        }
        
        $argsLine = $argsLine -replace '\s+', ' '
        $argsLine = $argsLine.Trim()
        
        return $argsLine
    } catch {
        return $null
    }
}

function Test-WinwsExe {
    param([string]$BinPath)
    
    $winwsPath = Join-Path $BinPath "winws.exe"
    if (Test-Path $winwsPath) {
        return $winwsPath
    }
    
    $possiblePaths = @(
        $winwsPath
        (Join-Path $ScriptPath "winws.exe")
        (Join-Path (Join-Path $ScriptPath "..") "winws.exe")
        (Join-Path (Join-Path $ScriptPath "bin") "winws.exe")
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    return $null
}

function Install-ZapretService {
    Update-StatusBar "Preparing to install service..." "Info"
    
    $batFiles = @()
    if (Test-Path (Join-Path $ScriptPath "*.bat")) {
        $batFiles = Get-ChildItem -LiteralPath $ScriptPath -Filter "*.bat" | 
                    Where-Object { $_.Name -notlike "service*" -and $_.Name -notlike "!*" } |
                    Sort-Object { [Regex]::Replace($_.Name, '(\d+)', { $args[0].Value.PadLeft(8, '0') }) }
    }
    
    if ($batFiles.Count -eq 0) {
        $parentPath = Split-Path $ScriptPath -Parent
        if (Test-Path (Join-Path $parentPath "*.bat")) {
            $batFiles = Get-ChildItem -Path $parentPath -Filter "*.bat" | 
                        Where-Object { $_.Name -notlike "service*" -and $_.Name -notlike "!*" } |
                        Sort-Object Name
        }
    }
    
    if ($batFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No configuration files (.bat) found!`n`nMake sure:" +
            "`n1. You have extracted the archive completely" +
            "`n2. Configuration files are in the same folder" +
            "`n3. Files have .bat extension",
            "Error", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        Update-StatusBar "Installation cancelled - no config files" "Error"
        return
    }
    
    $selectForm = New-Object System.Windows.Forms.Form
    $selectForm.Text = "Select Configuration File"
    $selectForm.Size = New-Object System.Drawing.Size(600, 450)
    $selectForm.StartPosition = "CenterScreen"
    $selectForm.BackColor = $colors.Midnight
    $selectForm.FormBorderStyle = "FixedDialog"
    $selectForm.MaximizeBox = $false
    
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 15)
    $label.Size = New-Object System.Drawing.Size(550, 25)
    $label.Text = "Choose a configuration strategy:"
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $label.ForeColor = $colors.Light
    $selectForm.Controls.Add($label)
    
    $listBox = New-Object System.Windows.Forms.ListBox
    $listBox.Location = New-Object System.Drawing.Point(20, 45)
    $listBox.Size = New-Object System.Drawing.Size(550, 300)
    $listBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $listBox.BackColor = $colors.DarkGray
    $listBox.ForeColor = $colors.Light
    foreach ($file in $batFiles) { 
        $listBox.Items.Add($file.Name) | Out-Null 
    }
    $listBox.SelectedIndex = 0
    $selectForm.Controls.Add($listBox)
    
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(340, 360)
    $okButton.Size = New-Object System.Drawing.Size(110, 40)
    $okButton.Text = "Install"
    $okButton.BackColor = $colors.Success
    $okButton.ForeColor = $colors.White
    $okButton.FlatStyle = "Flat"
    $okButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $okButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $selectForm.Controls.Add($okButton)
    
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(460, 360)
    $cancelButton.Size = New-Object System.Drawing.Size(110, 40)
    $cancelButton.Text = "Cancel"
    $cancelButton.BackColor = $colors.Danger
    $cancelButton.ForeColor = $colors.White
    $cancelButton.FlatStyle = "Flat"
    $cancelButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $cancelButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $selectForm.Controls.Add($cancelButton)
    
    $selectForm.AcceptButton = $okButton
    $selectForm.CancelButton = $cancelButton
    
    if ($selectForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Update-StatusBar "Installation cancelled" "Warning"
        return
    }
    
    $selectedFile = Join-Path $batFiles[$listBox.SelectedIndex].DirectoryName $listBox.SelectedItem
    $binPath = Join-Path $ScriptPath "bin"
    $listsPath = Join-Path $ScriptPath "lists"
    $gameStatus = Get-GameFilterStatus
    $gameFilter = $gameStatus.Filter
    $gameFilterTCP = $gameStatus.FilterTCP
    $gameFilterUDP = $gameStatus.FilterUDP
    
    $winwsPath = Test-WinwsExe -BinPath $binPath
    if (-not $winwsPath) {
        [System.Windows.Forms.MessageBox]::Show(
            "winws.exe not found!`n`nMake sure:" +
            "`n1. You have extracted ALL files from the archive" +
            "`n2. winws.exe is in the 'bin' folder" +
            "`n3. Antivirus didn't delete the file",
            "Error", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        Update-StatusBar "Installation failed - winws.exe not found" "Error"
        return
    }
    
    Update-StatusBar "Parsing configuration file..." "Info"
    $cmdLine = Parse-BatFileNew -FilePath $selectedFile -BinPath $binPath -ListsPath $listsPath -GameFilter $gameFilter -GameFilterTCP $gameFilterTCP -GameFilterUDP $gameFilterUDP
    
    if ([string]::IsNullOrWhiteSpace($cmdLine)) {
        Update-StatusBar "Failed to parse configuration!" "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Cannot parse configuration file: $($listBox.SelectedItem)`n`n" +
            "File format may be incorrect or corrupted.",
            "Parse Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    netsh interface tcp set global timestamps=enabled | Out-Null
    
    Update-StatusBar "Removing old service..." "Info"
    Stop-ZapretService -Silent $true | Out-Null
    Start-Sleep -Milliseconds 500
    
    $existingService = Get-Service -Name "zapret" -ErrorAction SilentlyContinue
    if ($existingService) {
        sc.exe delete zapret 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
    }
    
    Update-StatusBar "Creating service via SC.EXE..." "Info"
    
    $serviceBinPath = "`"$winwsPath`" $cmdLine"
    
    $scCommand = "sc.exe create zapret binPath= `"$serviceBinPath`" DisplayName= `"zapret`" start= auto"
    Write-Host "SC Command: $scCommand"
    
    $result = cmd.exe /c $scCommand 2>&1
    Write-Host "SC Result: $result"
    
    if ($LASTEXITCODE -ne 0) {
        Update-StatusBar "Trying alternative method..." "Warning"
        
        try {
            $fullCommand = "`"$winwsPath`" $cmdLine"
            New-Service -Name "zapret" `
                       -BinaryPathName $fullCommand `
                       -DisplayName "zapret" `
                       -Description "Zapret DPI bypass software" `
                       -StartupType Automatic `
                       -ErrorAction Stop | Out-Null
            Update-StatusBar "Service created via New-Service" "Success"
        } catch {
            Update-StatusBar "All methods failed: $($_.Exception.Message)" "Error"
            
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to create service!`n`n" +
                "Error: $($_.Exception.Message)`n`n" +
                "Try to:" +
                "`n1. Run 'service_new.bat' manually" +
                "`n2. Check Windows Event Viewer" +
                "`n3. Ensure you have admin rights",
                "Service Creation Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }
    } else {
        Update-StatusBar "Service created via SC.EXE" "Success"
    }
    
    sc.exe description zapret "Zapret DPI bypass software" 2>&1 | Out-Null
    
    $configName = [System.IO.Path]::GetFileNameWithoutExtension($listBox.SelectedItem)
    reg add "HKLM\System\CurrentControlSet\Services\zapret" /v zapret-discord-youtube /t REG_SZ /d $configName /f 2>&1 | Out-Null
    
    Update-StatusBar "Starting service..." "Info"
    sc.exe start zapret 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    
    $serviceStatus = Get-ServiceStatus "zapret"
    if ($serviceStatus -eq "Running") {
        Update-StatusBar "Service installed and running!" "Success"
        
        try {
            Start-Process $winwsPath -ArgumentList $cmdLine -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            $process = Get-Process -Name winws -ErrorAction SilentlyContinue
            if ($process) {
                Update-StatusBar "winws.exe also started directly" "Success"
            }
        } catch {
            Write-Host "Note: Direct winws.exe start failed (may already be running)"
        }
    } else {
        Update-StatusBar "Service created but not running" "Warning"
        
        try {
            Start-Process $winwsPath -ArgumentList $cmdLine -WindowStyle Hidden
            Start-Sleep -Seconds 2
            $process = Get-Process -Name winws -ErrorAction SilentlyContinue
            if ($process) {
                Update-StatusBar "Service started directly" "Success"
            }
        } catch {
            Update-StatusBar "Failed to start service directly" "Error"
        }
    }
    
    Update-ServiceStatusBar
    Update-StatusDisplay
}

function Show-GameFilterDialog {
    $cur = Get-GameFilterStatus

    $gf = New-Object System.Windows.Forms.Form
    $gf.Text = "Game Filter"
    $gf.ClientSize = New-Object System.Drawing.Size(460, 395)
    $gf.StartPosition = "CenterScreen"
    $gf.FormBorderStyle = "FixedDialog"
    $gf.MaximizeBox = $false
    $gf.MinimizeBox = $false
    $gf.BackColor = $colors.Midnight

    $lblMode = New-Object System.Windows.Forms.Label
    $lblMode.Location = New-Object System.Drawing.Point(20, 15)
    $lblMode.Size = New-Object System.Drawing.Size(420, 24)
    $lblMode.Text = "Game filter mode:"
    $lblMode.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblMode.ForeColor = $colors.Light
    $gf.Controls.Add($lblMode)

    $radioDefs = @(
        @{ Key = "disabled"; Text = "Disabled" },
        @{ Key = "all";      Text = "TCP and UDP" },
        @{ Key = "tcp";      Text = "TCP only" },
        @{ Key = "udp";      Text = "UDP only" }
    )
    $radios = @{}
    $ry = 45
    foreach ($rd in $radioDefs) {
        $rb = New-Object System.Windows.Forms.RadioButton
        $rb.Location = New-Object System.Drawing.Point(30, $ry)
        $rb.Size = New-Object System.Drawing.Size(400, 26)
        $rb.Text = $rd.Text
        $rb.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $rb.ForeColor = $colors.Light
        $rb.Checked = ($cur.Mode -eq $rd.Key)
        $gf.Controls.Add($rb)
        $radios[$rd.Key] = $rb
        $ry += 30
    }

    $lblTcp = New-Object System.Windows.Forms.Label
    $lblTcp.Location = New-Object System.Drawing.Point(20, 175)
    $lblTcp.Size = New-Object System.Drawing.Size(420, 22)
    $lblTcp.Text = "TCP ports:"
    $lblTcp.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblTcp.ForeColor = $colors.Light
    $gf.Controls.Add($lblTcp)

    $txtTcp = New-Object System.Windows.Forms.TextBox
    $txtTcp.Location = New-Object System.Drawing.Point(20, 200)
    $txtTcp.Size = New-Object System.Drawing.Size(420, 26)
    $txtTcp.Font = New-Object System.Drawing.Font("Consolas", 10)
    $txtTcp.BackColor = $colors.DarkGray
    $txtTcp.ForeColor = $colors.Light
    $txtTcp.BorderStyle = "FixedSingle"
    $txtTcp.Text = $cur.TCPRange
    $gf.Controls.Add($txtTcp)

    $lblUdp = New-Object System.Windows.Forms.Label
    $lblUdp.Location = New-Object System.Drawing.Point(20, 240)
    $lblUdp.Size = New-Object System.Drawing.Size(420, 22)
    $lblUdp.Text = "UDP ports:"
    $lblUdp.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblUdp.ForeColor = $colors.Light
    $gf.Controls.Add($lblUdp)

    $txtUdp = New-Object System.Windows.Forms.TextBox
    $txtUdp.Location = New-Object System.Drawing.Point(20, 265)
    $txtUdp.Size = New-Object System.Drawing.Size(420, 26)
    $txtUdp.Font = New-Object System.Drawing.Font("Consolas", 10)
    $txtUdp.BackColor = $colors.DarkGray
    $txtUdp.ForeColor = $colors.Light
    $txtUdp.BorderStyle = "FixedSingle"
    $txtUdp.Text = $cur.UDPRange
    $gf.Controls.Add($txtUdp)

    $lblHint = New-Object System.Windows.Forms.Label
    $lblHint.Location = New-Object System.Drawing.Point(20, 300)
    $lblHint.Size = New-Object System.Drawing.Size(420, 40)
    $lblHint.Text = "Ports / ranges separated by commas. Example: 1024-1934,1936-65535`n(default: 1024-65535, e.g. skip 1935 to exclude RTMP)"
    $lblHint.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $lblHint.ForeColor = [System.Drawing.Color]::Silver
    $gf.Controls.Add($lblHint)

    $btnDefaults = New-Object System.Windows.Forms.Button
    $btnDefaults.Location = New-Object System.Drawing.Point(20, 345)
    $btnDefaults.Size = New-Object System.Drawing.Size(120, 36)
    $btnDefaults.Text = "Default ports"
    $btnDefaults.BackColor = $colors.DarkGray
    $btnDefaults.ForeColor = $colors.Light
    $btnDefaults.FlatStyle = "Flat"
    $btnDefaults.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnDefaults.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnDefaults.Add_Click({
        $txtTcp.Text = "1024-65535"
        $txtUdp.Text = "1024-65535"
    })
    $gf.Controls.Add($btnDefaults)

    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Location = New-Object System.Drawing.Point(240, 345)
    $btnSave.Size = New-Object System.Drawing.Size(95, 36)
    $btnSave.Text = "Save"
    $btnSave.BackColor = $colors.Success
    $btnSave.ForeColor = $colors.White
    $btnSave.FlatStyle = "Flat"
    $btnSave.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnSave.Cursor = [System.Windows.Forms.Cursors]::Hand
    $script:gfResult = $null
    $btnSave.Add_Click({
        $tcp = Test-GameFilterRange $txtTcp.Text
        $udp = Test-GameFilterRange $txtUdp.Text
        if (-not $tcp -or -not $udp) {
            [System.Windows.Forms.MessageBox]::Show(
                "Invalid port list.`n`nUse ports/ranges 1-65535 separated by commas,`nfor example: 1024-1934,1936-65535",
                "Game Filter",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            return
        }
        $mode = "disabled"
        foreach ($k in $radios.Keys) { if ($radios[$k].Checked) { $mode = $k } }
        $script:gfResult = @{ Mode = $mode; TCP = $tcp; UDP = $udp }
        $gf.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $gf.Close()
    })
    $gf.Controls.Add($btnSave)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(345, 345)
    $btnCancel.Size = New-Object System.Drawing.Size(95, 36)
    $btnCancel.Text = "Cancel"
    $btnCancel.BackColor = $colors.Danger
    $btnCancel.ForeColor = $colors.White
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $gf.Controls.Add($btnCancel)
    $gf.CancelButton = $btnCancel

    $dlgResult = $gf.ShowDialog()
    $gf.Dispose()
    if ($dlgResult -ne [System.Windows.Forms.DialogResult]::OK -or -not $script:gfResult) { return }

    $r = $script:gfResult
    Save-GameFilterSettings -Mode $r.Mode -TCPRange $r.TCP -UDPRange $r.UDP

    $labels = @{ disabled = "disabled"; all = "TCP+UDP"; tcp = "TCP only"; udp = "UDP only" }
    $msg = "Game filter: $($labels[$r.Mode])"
    if ($r.Mode -ne "disabled") {
        if ($r.Mode -ne "udp") { $msg += " | TCP $($r.TCP)" }
        if ($r.Mode -ne "tcp") { $msg += " | UDP $($r.UDP)" }
    }
    Update-StatusBar "$msg - restart service to apply" "Warning"
    Update-StatusDisplay
}

function Toggle-IPSet {
    $listFile = Join-Path $ScriptPath "lists\ipset-all.txt"
    $backupFile = "$listFile.backup"
    $currentStatus = Get-IPSetStatus
    
    switch ($currentStatus) {
        "loaded" {
            if (Test-Path $listFile) { Copy-Item $listFile $backupFile -Force }
            "203.0.113.113/32" | Out-File -FilePath $listFile -Encoding ASCII
            Update-StatusBar "IPSet: NONE mode - Restart service to apply" "Warning"
        }
        "none" {
            "" | Out-File -FilePath $listFile -Encoding ASCII
            Update-StatusBar "IPSet: ANY mode - Restart service to apply" "Warning"
        }
        "any" {
            if (Test-Path $backupFile) {
                Copy-Item $backupFile $listFile -Force
                Update-StatusBar "IPSet: LOADED mode - Restart service to apply" "Success"
            } else {
                Update-StatusBar "No backup - Update IPSet list first" "Error"
            }
        }
    }
    Update-StatusDisplay
}

function Toggle-AutoUpdate {
    $flagFile = Join-Path $ScriptPath "utils\check_updates.enabled"
    if (Test-Path $flagFile) {
        Remove-Item $flagFile -Force
        Update-StatusBar "Auto-update disabled" "Success"
    } else {
        $utilsPath = Join-Path $ScriptPath "utils"
        if (-not (Test-Path $utilsPath)) { New-Item -ItemType Directory -Path $utilsPath -Force | Out-Null }
        "ENABLED" | Out-File -FilePath $flagFile -Encoding ASCII
        Update-StatusBar "Auto-update enabled" "Success"
    }
    Update-StatusDisplay
}

function Update-IPSetList {
    Update-StatusBar "Downloading IPSet list..." "Info"
    $listFile = Join-Path $ScriptPath "lists\ipset-all.txt"
    $listsDir = Join-Path $ScriptPath "lists"
    $url = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt"
    
    if (-not (Test-Path $listsDir)) { 
        New-Item -ItemType Directory -Path $listsDir -Force | Out-Null 
        Update-StatusBar "Created lists directory" "Info"
    }
    
    try {
        Invoke-WebRequest -Uri $url -OutFile $listFile -TimeoutSec 10 -UseBasicParsing
        $lineCount = (Get-Content $listFile | Measure-Object -Line).Lines
        Update-StatusBar "IPSet list updated! ($lineCount entries)" "Success"
    } catch {
        Update-StatusBar "Failed to download: $($_.Exception.Message)" "Error"
    }
}

$script:HostsKeepLines = 21   # lines at the top of the hosts file that are never touched

function Merge-HostsContent {
    # Keeps the first $KeepLines lines of the current hosts text, replaces everything below with $NewLines.
    param([string]$CurrentText, [string[]]$NewLines, [int]$KeepLines = 21)

    $cur = New-Object 'System.Collections.Generic.List[string]'
    if ($CurrentText) { foreach ($l in ($CurrentText -split "\r?\n")) { $cur.Add($l.TrimEnd()) } }
    while ($cur.Count -gt 0 -and $cur[$cur.Count - 1] -eq "") { $cur.RemoveAt($cur.Count - 1) }

    $new = New-Object 'System.Collections.Generic.List[string]'
    foreach ($l in $NewLines) { $new.Add(([string]$l).TrimEnd()) }
    while ($new.Count -gt 0 -and $new[$new.Count - 1] -eq "") { $new.RemoveAt($new.Count - 1) }

    $head = New-Object 'System.Collections.Generic.List[string]'
    $tail = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $cur.Count; $i++) {
        if ($i -lt $KeepLines) { $head.Add($cur[$i]) } else { $tail.Add($cur[$i]) }
    }

    $upToDate = ($tail.Count -eq $new.Count)
    if ($upToDate) {
        for ($i = 0; $i -lt $new.Count; $i++) {
            if ($tail[$i] -ne $new[$i]) { $upToDate = $false; break }
        }
    }

    $all = @($head.ToArray()) + @($new.ToArray())
    return @{
        UpToDate     = $upToDate
        Text         = (($all -join "`r`n") + "`r`n")
        KeptLines    = $head.Count
        RemovedLines = $tail.Count
        NewLines     = $new.Count
    }
}

function Show-HostsUpdateDialog {
    $script:hostsChoice = "cancel"

    $hf = New-Object System.Windows.Forms.Form
    $hf.Text = "Update Hosts"
    $hf.ClientSize = New-Object System.Drawing.Size(430, 270)
    $hf.StartPosition = "CenterScreen"
    $hf.FormBorderStyle = "FixedDialog"
    $hf.MaximizeBox = $false
    $hf.MinimizeBox = $false
    $hf.BackColor = $colors.Midnight

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point(15, 15)
    $lbl.Size = New-Object System.Drawing.Size(400, 22)
    $lbl.Text = "Hosts file needs an update. How to apply it?"
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lbl.ForeColor = $colors.Light
    $hf.Controls.Add($lbl)

    $btnAutoH = New-Object System.Windows.Forms.Button
    $btnAutoH.Location = New-Object System.Drawing.Point(15, 48)
    $btnAutoH.Size = New-Object System.Drawing.Size(400, 44)
    $btnAutoH.Text = "Auto  (write new data into hosts)"
    $btnAutoH.BackColor = $colors.Success
    $btnAutoH.ForeColor = $colors.White
    $btnAutoH.FlatStyle = "Flat"
    $btnAutoH.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnAutoH.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnAutoH.Add_Click({ $script:hostsChoice = "auto"; $hf.Close() })
    $hf.Controls.Add($btnAutoH)

    $btnManualH = New-Object System.Windows.Forms.Button
    $btnManualH.Location = New-Object System.Drawing.Point(15, 100)
    $btnManualH.Size = New-Object System.Drawing.Size(400, 44)
    $btnManualH.Text = "Manual  (open new data and the hosts folder)"
    $btnManualH.BackColor = $colors.Primary
    $btnManualH.ForeColor = $colors.White
    $btnManualH.FlatStyle = "Flat"
    $btnManualH.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnManualH.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnManualH.Add_Click({ $script:hostsChoice = "manual"; $hf.Close() })
    $hf.Controls.Add($btnManualH)

    $hint = New-Object System.Windows.Forms.Label
    $hint.Location = New-Object System.Drawing.Point(15, 154)
    $hint.Size = New-Object System.Drawing.Size(400, 62)
    $hint.Text = "Auto keeps the first $($script:HostsKeepLines) lines of your hosts file and REPLACES everything below them with the new data. Any custom entries below line $($script:HostsKeepLines) will be removed. A backup is saved next to the hosts file (hosts.zapret-*.bak)."
    $hint.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $hint.ForeColor = [System.Drawing.Color]::Silver
    $hf.Controls.Add($hint)

    $btnCancelH = New-Object System.Windows.Forms.Button
    $btnCancelH.Location = New-Object System.Drawing.Point(15, 222)
    $btnCancelH.Size = New-Object System.Drawing.Size(400, 34)
    $btnCancelH.Text = "Cancel"
    $btnCancelH.BackColor = $colors.Slate
    $btnCancelH.ForeColor = $colors.White
    $btnCancelH.FlatStyle = "Flat"
    $btnCancelH.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnCancelH.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancelH.Add_Click({ $script:hostsChoice = "cancel"; $hf.Close() })
    $hf.Controls.Add($btnCancelH)
    $hf.CancelButton = $btnCancelH

    $hf.ShowDialog() | Out-Null
    $hf.Dispose()
    return $script:hostsChoice
}

function Update-HostsFile {
    Update-StatusBar "Checking hosts file..." "Info"
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsUrl  = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts"
    $tempFile  = "$env:TEMP\zapret_hosts.txt"
    try {
        Invoke-WebRequest -Uri $hostsUrl -OutFile $tempFile -TimeoutSec 15 -UseBasicParsing
        $newText  = [System.IO.File]::ReadAllText($tempFile, [System.Text.Encoding]::UTF8)
        $newLines = @($newText -split "\r?\n")

        # sanity check: must contain at least one real "IP host" entry, otherwise never touch hosts
        $entries = @($newLines | Where-Object { $_ -match '^\s*[0-9A-Fa-f:.]+\s+\S+' -and $_ -notmatch '^\s*#' })
        if ($entries.Count -lt 1) { throw "Downloaded file does not look like a hosts file" }

        $curText = ""
        if (Test-Path $hostsFile) { $curText = [System.IO.File]::ReadAllText($hostsFile, [System.Text.Encoding]::UTF8) }
        $merge = Merge-HostsContent -CurrentText $curText -NewLines $newLines -KeepLines $script:HostsKeepLines

        if ($merge.UpToDate) {
            Update-StatusBar "Hosts file up to date!" "Success"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }

        Update-StatusBar "Hosts file needs update" "Warning"
        $choice = Show-HostsUpdateDialog

        if ($choice -eq "manual") {
            Start-Process notepad.exe -ArgumentList $tempFile
            Start-Sleep -Milliseconds 300
            Start-Process explorer.exe -ArgumentList "/select,`"$hostsFile`""
            Update-StatusBar "Manual mode: copy the new data into hosts" "Info"
            return
        }
        if ($choice -ne "auto") {
            Update-StatusBar "Hosts update cancelled" "Info"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            return
        }

        # backup (keep the 3 newest)
        $stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
        $backup = "$hostsFile.zapret-$stamp.bak"
        if (Test-Path $hostsFile) { Copy-Item $hostsFile $backup -Force }
        Get-ChildItem -Path (Split-Path $hostsFile -Parent) -Filter "hosts.zapret-*.bak" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -Skip 3 |
            Remove-Item -Force -ErrorAction SilentlyContinue

        if (Test-Path $hostsFile) {
            $item = Get-Item $hostsFile -Force
            if ($item.IsReadOnly) { $item.IsReadOnly = $false }
        }
        [System.IO.File]::WriteAllText($hostsFile, $merge.Text, (New-Object System.Text.UTF8Encoding($false)))
        ipconfig /flushdns 2>&1 | Out-Null
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        Update-StatusBar "Hosts updated: kept $($merge.KeptLines) lines, wrote $($merge.NewLines) new (replaced $($merge.RemovedLines) old)" "Success"
    } catch {
        Update-StatusBar "Hosts update failed: $($_.Exception.Message)" "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Could not update the hosts file automatically.`n`n$($_.Exception.Message)`n`nAntivirus software often blocks changes to hosts. You can retry and choose 'Manual'.",
            "Update Hosts",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
}

function Check-Updates {
    param([bool]$AutoCheck = $false)

    if (-not $AutoCheck) {
        Update-StatusBar "Checking for updates..." "Info"
    }

    $versionUrl  = "https://raw.githubusercontent.com/Zwey6754/zapret-GUI-on-PowerShell/main/.service/version.txt"
    $apiUrl      = "https://api.github.com/repos/Zwey6754/zapret-GUI-on-PowerShell/releases/latest"
    $updaterPath = Join-Path $ScriptPath "utils\updater.ps1"

    try {
        $githubVersion = (Invoke-WebRequest -Uri $versionUrl -UseBasicParsing -TimeoutSec 5).Content.Trim()

        if ($LOCAL_VERSION -eq $githubVersion) {
            if (-not $AutoCheck) {
                Update-StatusBar "Latest version installed: $LOCAL_VERSION" "Success"
                [System.Windows.Forms.MessageBox]::Show(
                    "You have the latest version!`n`nCurrent: $LOCAL_VERSION",
                    "Up to Date",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            return
        }

        Update-StatusBar "Update available: $githubVersion" "Warning"

        #  Choice dialog 
        $choiceForm = New-Object System.Windows.Forms.Form
        $choiceForm.Text = "Update Available"
        $choiceForm.Size = New-Object System.Drawing.Size(420, 250)
        $choiceForm.StartPosition = "CenterScreen"
        $choiceForm.BackColor = $colors.Midnight
        $choiceForm.FormBorderStyle = "FixedDialog"
        $choiceForm.MaximizeBox = $false

        $msgLbl = New-Object System.Windows.Forms.Label
        $msgLbl.Location = New-Object System.Drawing.Point(15, 15)
        $msgLbl.Size = New-Object System.Drawing.Size(380, 50)
        $msgLbl.Text = "New version available!`n`nCurrent: $LOCAL_VERSION      Latest: $githubVersion"
        $msgLbl.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $msgLbl.ForeColor = $colors.Light
        $choiceForm.Controls.Add($msgLbl)

        $sepLbl = New-Object System.Windows.Forms.Label
        $sepLbl.Location = New-Object System.Drawing.Point(15, 68)
        $sepLbl.Size = New-Object System.Drawing.Size(380, 18)
        $sepLbl.Text = "How do you want to update?"
        $sepLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $sepLbl.ForeColor = [System.Drawing.Color]::FromArgb(130, 150, 170)
        $choiceForm.Controls.Add($sepLbl)

        # Auto-update button
        $btnAuto = New-Object System.Windows.Forms.Button
        $btnAuto.Location = New-Object System.Drawing.Point(15, 96)
        $btnAuto.Size = New-Object System.Drawing.Size(375, 44)
        $btnAuto.Text = "Auto-install  (download and replace files)"
        $btnAuto.BackColor = $colors.Success
        $btnAuto.ForeColor = $colors.White
        $btnAuto.FlatStyle = "Flat"
        $btnAuto.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $btnAuto.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btnAuto.DialogResult = [System.Windows.Forms.DialogResult]::Yes
        $choiceForm.Controls.Add($btnAuto)

        # Open page button
        $btnPage = New-Object System.Windows.Forms.Button
        $btnPage.Location = New-Object System.Drawing.Point(15, 150)
        $btnPage.Size = New-Object System.Drawing.Size(375, 44)
        $btnPage.Text = "Open release page  (download manually in browser)"
        $btnPage.BackColor = $colors.Primary
        $btnPage.ForeColor = $colors.White
        $btnPage.FlatStyle = "Flat"
        $btnPage.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $btnPage.Cursor = [System.Windows.Forms.Cursors]::Hand
        $btnPage.DialogResult = [System.Windows.Forms.DialogResult]::No
        $choiceForm.Controls.Add($btnPage)

        # Cancel on X
        $choiceForm.CancelButton = $null
        $script:updateChoice = "cancel"
        $btnAuto.Add_Click({ $script:updateChoice = "auto";   $choiceForm.Close() })
        $btnPage.Add_Click({ $script:updateChoice = "page";   $choiceForm.Close() })
        $choiceForm.Add_FormClosing({ if ($script:updateChoice -eq "cancel") {} })

        $choiceForm.ShowDialog() | Out-Null

        if ($script:updateChoice -eq "cancel") {
            Update-StatusBar "Update postponed" "Info"
            return
        }

        if ($script:updateChoice -eq "page") {
            $releasePageUrl = "https://github.com/Zwey6754/zapret-GUI-on-PowerShell/releases/latest"
            Start-Process $releasePageUrl
            Update-StatusBar "Release page opened in browser" "Info"
            return
        }

        #  Auto-install path 
        Update-StatusBar "Fetching release info..." "Info"
        try {
            $releaseInfo = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -TimeoutSec 10
      $zipAsset = $releaseInfo.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
if ($zipAsset) {
    $zipUrl = $zipAsset.browser_download_url
} else {
    # fallback на zipball если в релизе нет .zip asset
    $zipUrl = $releaseInfo.zipball_url
	}
}
catch {
            Update-StatusBar "Failed to get release info" "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "Could not fetch release info from GitHub.`nCheck your internet connection.",
                "Update Failed",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }

        if (-not (Test-Path $updaterPath)) {
            Update-StatusBar "updater.ps1 not found in utils\" "Error"
            [System.Windows.Forms.MessageBox]::Show(
                "utils\updater.ps1 not found.`nMake sure it is present in the utils folder.",
                "Updater Missing",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }

        Update-StatusBar "Launching updater..." "Info"
        $guiPath = $PSCommandPath
        if (-not $guiPath) { $guiPath = Join-Path $ScriptPath "zapret-gui.ps1" }

        Start-Process powershell.exe -ArgumentList (
            "-NoProfile -ExecutionPolicy Bypass -File `"$updaterPath`"",
            "-ScriptPath `"$ScriptPath`"",
            "-ZipUrl `"$zipUrl`"",
            "-GuiPath `"$guiPath`"",
            "-GuiPid $PID"
        ) -Verb RunAs

        # Close this GUI so updater can replace files freely
        $form.Close()

    } catch {
        if (-not $AutoCheck) {
            Update-StatusBar "Check failed: $($_.Exception.Message)" "Error"
        }
    }
}

function Remove-ZapretService {
    Update-StatusBar "Removing services..." "Info"
    
    $servicesToRemove = @("zapret", "WinDivert", "WinDivert14", "GoodbyeDPI", "discordfix_zapret", "winws1", "winws2")
    
    foreach ($service in $servicesToRemove) {
        sc.exe stop $service 2>&1 | Out-Null
        sc.exe delete $service 2>&1 | Out-Null
        Write-Host "Attempted to remove service: $service"
    }
    
    Get-Process -Name winws -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Update-StatusBar "Services removed successfully!" "Success"
    Update-ServiceStatusBar
    Update-StatusDisplay
    return "Success"
}

function Show-ServiceStatus {
    $serviceInfo = Get-ServiceInfo
    $message = "Zapret Service Status:`n`n"
    
    if ($serviceInfo.Installed) {
        $message += "Service: Installed`n"
        $message += "Status: $($serviceInfo.Status)`n"
        $message += "Config: $($serviceInfo.Config)`n"
    } else {
        $message += "Service: Not installed`n"
    }
    
    $message += "`nWinDivert64.sys: "
    $winDivertPath = Join-Path $ScriptPath "bin\WinDivert64.sys"
    if (Test-Path $winDivertPath) {
        $message += "Found`n"
    } else {
        $message += "Not found`n"
    }
    
    $winwsProcess = Get-Process -Name winws -ErrorAction SilentlyContinue
    $message += "winws.exe process: "
    if ($winwsProcess) {
        $message += "Running ($($winwsProcess.Count) instances)`n"
    } else {
        $message += "Not running`n"
    }
    
    [System.Windows.Forms.MessageBox]::Show($message, "Service Status", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

$script:VpnAdapterRegex = '(?i)(tap-windows|\btap\d*\b|\btun\d*\b|wintun|wireguard|openvpn|nordlynx|tailscale|zerotier|hamachi|radmin|\bvpn\b|warp|amnezia|outline|hiddify|sing-?box|xray|v2ray|clash|mihomo|nekoray|nekobox|throne|\bhapp\b|proton|mullvad|windscribe|surfshark|fortinet|forticlient|anyconnect|globalprotect|pangp|softether|sstp|pritunl|cloudflare)'
$script:VmAdapterRegex  = '(?i)(hyper-v|vethernet|vmware|virtualbox|virtual ?adapter|\bwsl\b|npcap|loopback|teredo|isatap|6to4|wan miniport|bluetooth|docker|host-only)'
$script:KnownPublicDns  = @('1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112','77.88.8.8','77.88.8.1','208.67.222.222','208.67.220.220','94.140.14.14','94.140.15.15')

function Get-AdapterKind {
    param($Adapter)
    $txt = "$($Adapter.Name) $($Adapter.InterfaceDescription)"
    if ($txt -match $script:VpnAdapterRegex) { return "vpn" }
    if ($txt -match $script:VmAdapterRegex)  { return "vm" }
    if (-not $Adapter.HardwareInterface)     { return "virtual" }
    return "physical"
}

function Get-NetworkDiagnostics {
    $r = @()
    $r += "--- Network adapter ---"
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
        $up = @($adapters | Where-Object { $_.Status -eq "Up" })
        $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
        $ifMetric = @{}
        Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $ifMetric[[int]$_.InterfaceIndex] = [int]$_.InterfaceMetric }

        $ranked = @($routes | ForEach-Object {
            $m = 0; if ($ifMetric.ContainsKey([int]$_.InterfaceIndex)) { $m = $ifMetric[[int]$_.InterfaceIndex] }
            [pscustomobject]@{ Index = [int]$_.InterfaceIndex; Metric = ([int]$_.RouteMetric + $m); Next = $_.NextHop }
        } | Sort-Object Metric)

        if ($ranked.Count -eq 0) {
            $r += "[X] No IPv4 default route - no internet connection through any adapter"
        } else {
            $primary = $adapters | Where-Object { $_.InterfaceIndex -eq $ranked[0].Index } | Select-Object -First 1
            if ($primary) {
                $kind = Get-AdapterKind $primary
                $label = "$($primary.Name) ($($primary.InterfaceDescription)), $($primary.LinkSpeed), metric $($ranked[0].Metric), gateway $($ranked[0].Next)"
                switch ($kind) {
                    "physical" { $r += "[OK] Primary adapter: $label" }
                    "vpn"      { $r += "[!] Primary adapter is a VPN/tunnel: $label"
                                 $r += "    -> traffic goes through the tunnel and is NOT processed by zapret; disconnect VPN/proxy-TUN" }
                    "vm"       { $r += "[!] Primary adapter is a virtual (VM/WSL) adapter: $label"
                                 $r += "    -> check metrics: the real Ethernet/Wi-Fi adapter should be primary" }
                    default    { $r += "[!] Primary adapter is not a physical NIC: $label" }
                }
                if ($primary.Status -ne "Up") { $r += "[X] Primary adapter status: $($primary.Status)" }
            } else {
                $r += "[?] Default route interface #$($ranked[0].Index) not found among adapters"
            }

            if ($ranked.Count -gt 1) {
                $names = @($ranked | ForEach-Object {
                    $n = (Get-NetAdapter -InterfaceIndex $_.Index -ErrorAction SilentlyContinue).Name
                    if (-not $n) { $n = "#$($_.Index)" }
                    "$n=$($_.Metric)"
                })
                $r += "[!] Several default routes (lowest metric wins): $($names -join ', ')"
                $physUp = @($up | Where-Object { (Get-AdapterKind $_) -eq "physical" })
                if ($physUp.Count -gt 1) {
                    $r += "    -> two physical adapters are up (e.g. Ethernet + Wi-Fi); disable the unused one to avoid traffic flipping between them"
                }
            }

            # IP config of primary
            if ($primary) {
                $ipif = Get-NetIPInterface -InterfaceIndex $primary.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($ipif) {
                    $r += "[i] IPv4 config: $(if($ipif.Dhcp -eq 'Enabled'){'DHCP'}else{'static'}), MTU $($ipif.NlMtu)"
                    if ($ipif.NlMtu -lt 1400) { $r += "[!] Low MTU ($($ipif.NlMtu)) on primary adapter - can break large TLS/QUIC packets"; $r += "    -> typical for VPN/PPPoE leftovers; normal value is 1500 (PPPoE: 1492)" }
                }
            }
        }

        # other active adapters
        $others = @($up | Where-Object { -not $primary -or $_.InterfaceIndex -ne $primary.InterfaceIndex })
        foreach ($a in $others) {
            $k = Get-AdapterKind $a
            if ($k -eq "vpn") { $r += "[!] Active VPN/tunnel adapter: $($a.Name) ($($a.InterfaceDescription))" }
            elseif ($k -eq "physical") { $r += "[i] Other active adapter: $($a.Name) ($($a.InterfaceDescription))" }
        }
        $disabledVpn = @($adapters | Where-Object { $_.Status -ne "Up" -and (Get-AdapterKind $_) -eq "vpn" })
        if ($disabledVpn.Count -gt 0) {
            $r += "[i] Inactive VPN/tunnel adapters installed: $((($disabledVpn | ForEach-Object { $_.Name }) -join ', '))"
        }
    } catch {
        $r += "[?] Network adapter check failed: $($_.Exception.Message)"
    }
    $r += ""
    return $r
}

function Get-DnsDiagnostics {
    $r = @()
    $r += "--- DNS ---"
    try {
        $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
        $ifMetric = @{}
        Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $ifMetric[[int]$_.InterfaceIndex] = [int]$_.InterfaceMetric }
        $best = $routes | ForEach-Object {
            $m = 0; if ($ifMetric.ContainsKey([int]$_.InterfaceIndex)) { $m = $ifMetric[[int]$_.InterfaceIndex] }
            [pscustomobject]@{ Index = [int]$_.InterfaceIndex; Metric = ([int]$_.RouteMetric + $m); Next = [string]$_.NextHop }
        } | Sort-Object Metric | Select-Object -First 1

        $targets = @()
        if ($best) { $targets = @(Get-NetAdapter -InterfaceIndex $best.Index -ErrorAction SilentlyContinue) }
        $targets += @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and (-not $best -or $_.InterfaceIndex -ne $best.Index) -and (Get-AdapterKind $_) -eq "physical" })

        foreach ($a in $targets) {
            if (-not $a) { continue }
            $isPrimary = ($best -and $a.InterfaceIndex -eq $best.Index)
            $servers = @((Get-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
            $reg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($a.InterfaceGuid)" -ErrorAction SilentlyContinue
            $static = ($reg -and $reg.NameServer)
            $tag = if ($isPrimary) { "primary" } else { "secondary" }
            if ($servers.Count -eq 0) {
                $r += "[!] $($a.Name) ($tag): no IPv4 DNS servers configured"
                continue
            }
            $r += "[i] $($a.Name) ($tag): $($servers -join ', ') [$(if($static){'static'}else{'DHCP'})]"
            foreach ($s in $servers) {
                if ($s -match '^127\.' -or $s -eq '::1') {
                    $r += "[!] Local DNS resolver $s on $($a.Name) - a DNS proxy/filter (AdGuard, Acrylic, dnscrypt, VPN client...) is in use"
                    $r += "    -> it can bypass or break encrypted DNS; make sure it works and does not block discord/youtube domains"
                } elseif ($script:KnownPublicDns -contains $s) {
                    $r += "[OK] $s is a well-known public DNS"
                } elseif ($isPrimary -and $best -and $s -eq $best.Next) {
                    $r += "[i] $s is the router/gateway DNS (forwards to your ISP unless changed)"
                } elseif ($s -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)') {
                    $r += "[i] $s is a private-network DNS"
                } else {
                    $r += "[!] $s looks like an ISP/unknown DNS - ISP DNS can spoof blocked domains"
                    $r += "    -> use a public DNS with DoH (1.1.1.1 / 8.8.8.8 / 9.9.9.9)"
                }
            }
        }

        # NRPT rules (usually from VPN / corporate clients)
        $nrpt = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue)
        if ($nrpt.Count -gt 0) { $r += "[!] DNS policy (NRPT) rules present: $($nrpt.Count) - set by VPN/corporate software, can redirect DNS queries" }

        # Resolution sanity: names must resolve to real public addresses
        foreach ($d in @("discord.com", "www.youtube.com", "gateway.discord.gg")) {
            try {
                $ans = @(Resolve-DnsName -Name $d -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq "A" })
                if ($ans.Count -eq 0) {
                    $r += "[X] DNS: $d does not resolve"
                } else {
                    $ips = @($ans | ForEach-Object { $_.IPAddress })
                    if (@($ips | Where-Object { $_ -match '^(0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)' }).Count -gt 0) {
                        $r += "[X] DNS: $d resolves to a private/blackhole address ($($ips -join ', ')) - DNS spoofing or local filter"
                    } else {
                        $r += "[OK] DNS: $d -> $((@($ips | Select-Object -First 2)) -join ', ')"
                    }
                }
            } catch {
                $r += "[X] DNS: $d failed to resolve ($($_.Exception.Message.Split([char]10)[0]))"
            }
        }
    } catch {
        $r += "[?] DNS check failed: $($_.Exception.Message)"
    }
    $r += ""
    return $r
}

function Get-Ipv6Diagnostics {
    $r = @()
    $r += "--- IPv6 ---"
    try {
        $dc = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents
        if ($null -eq $dc) { $dc = 0 }
        if (($dc -band 0xFF) -eq 0xFF) {
            $r += "[OK] IPv6 disabled system-wide (DisabledComponents=0x$('{0:X}' -f $dc)) - all traffic uses IPv4"
        } else {
            $v6 = @(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {
                $_.IPAddress -notmatch '^(fe80|::1|fc|fd)' -and $_.AddressState -eq "Preferred" })
            $v6route = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue)
            $bound = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled })
            if ($v6.Count -gt 0 -and $v6route.Count -gt 0) {
                $a = Get-NetAdapter -InterfaceIndex $v6[0].InterfaceIndex -ErrorAction SilentlyContinue
                $r += "[!] Working global IPv6 on $($a.Name) ($($v6[0].IPAddress))"
                $r += "    -> sites may open over IPv6 and behave differently from IPv4; if YouTube/Discord fail only sometimes, disable IPv6 on the adapter"
                if (($dc -band 0x20) -eq 0x20) { $r += "[OK] IPv4 is preferred over IPv6 (DisabledComponents has 0x20)" }
                else { $r += "[i] IPv4 is not forced; the simple fix is DisabledComponents=0x20 (prefer IPv4) or unticking IPv6 on the adapter" }
            } elseif ($bound.Count -gt 0) {
                $r += "[OK] IPv6 enabled but no global IPv6 route - traffic uses IPv4"
            } else {
                $r += "[OK] IPv6 is not bound to any adapter"
            }
        }
        $teredo = Get-NetTeredoState -ErrorAction SilentlyContinue
        if ($teredo -and $teredo.State -notin @("Dormant", "Offline", "Disabled")) {
            $r += "[!] Teredo tunnel is active ($($teredo.State)) - IPv6-over-IPv4 tunnel can bypass zapret"
        }
    } catch {
        $r += "[?] IPv6 check failed: $($_.Exception.Message)"
    }
    $r += ""
    return $r
}

function Get-InterferenceDiagnostics {
    param($AllServices)
    $r = @()
    $r += "--- VPN, proxy, bypass tools ---"

    # system proxy / PAC / WinHTTP / env
    try {
        $is = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($is.ProxyEnable -eq 1) {
            $r += "[!] System proxy enabled: $($is.ProxyServer)"
            $r += "    -> traffic goes to the proxy, zapret only sees the connection to the proxy"
        } else { $r += "[OK] No system proxy" }
        if ($is.AutoConfigURL) { $r += "[!] Proxy auto-config (PAC) script set: $($is.AutoConfigURL)" }
        $wh = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings -ErrorAction SilentlyContinue).WinHttpSettings
        if ($wh -and $wh.Length -gt 8 -and (($wh[8] -band 2) -eq 2)) { $r += "[!] WinHTTP proxy configured (used by system services/updates)" }
        $envProxy = @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") | Where-Object { [Environment]::GetEnvironmentVariable($_) }
        if ($envProxy) { $r += "[!] Proxy environment variables set: $($envProxy -join ', ')" }
    } catch { $r += "[?] Proxy check failed" }

    # VPN / proxy-core / bypass processes
    try {
        $procNames = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName.ToLower() } | Sort-Object -Unique)
        $vpnProcs = @('v2rayn','v2ray','xray','sing-box','singbox','clash','clash-verge','verge-mihomo','mihomo','nekoray','nekobox','nekoray_core','throne','happ','hiddify','hiddify-core','amnezia','amneziavpn','amneziawg','outline','proxifier','psiphon','psiphon3','lantern','tor','openvpn','openvpn-gui','wireguard','wg','tailscale','tailscaled','zerotier-one','nordvpn','expressvpn','windscribe','protonvpn','mullvad-vpn','surfshark','cloudflarewarp','warp-svc','warp-cli','hamachi-2-ui','radmin_vpn','vpnui','forticlient','vpnagent','globalprotect')
        $bypassProcs = @('goodbyedpi','byedpi','ciadpi','spoofdpi','powertunnel','dpitunnel','zapret','nfqws')
        $foundV = @($vpnProcs | Where-Object { $procNames -contains $_ })
        $foundB = @($bypassProcs | Where-Object { $procNames -contains $_ })
        if ($foundV.Count -gt 0) { $r += "[!] VPN/proxy-core processes running: $($foundV -join ', ')"; $r += "    -> they capture traffic before zapret; close them (or exclude Discord/YouTube from their rules)" }
        else { $r += "[OK] No VPN/proxy-core processes found" }
        if ($foundB.Count -gt 0) { $r += "[X] Other DPI-bypass tools running: $($foundB -join ', ')" }

        $ownBin = (Join-Path $ScriptPath "bin").ToLower()
        $foreign = @(Get-CimInstance Win32_Process -Filter "Name='winws.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and -not $_.ExecutablePath.ToLower().StartsWith($ownBin) })
        if ($foreign.Count -gt 0) { $r += "[X] winws.exe running from another folder: $($foreign[0].ExecutablePath)" }
    } catch { $r += "[?] Process check failed" }

    # WinDivert registered from a different location
    try {
        $wd = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDivert" -ErrorAction SilentlyContinue
        if ($wd -and $wd.ImagePath) {
            $img = ([string]$wd.ImagePath) -replace '^\\\?\?\\', ''
            if (-not $img.ToLower().StartsWith((Join-Path $ScriptPath "bin").ToLower())) {
                $r += "[!] WinDivert driver is registered from another location: $img"
                $r += "    -> left over from another zapret/GoodbyeDPI copy; remove services (Remove Services) and reinstall"
            }
        }
    } catch {}

    # VPN services (running vs just installed)
    $vpnKeywords = @(
        "vpn", "wireguard", "openvpn", "nordvpn", "expressvpn", "windscribe",
        "mullvad", "protonvpn", "surfshark", "privateinternetaccess",
        "ipvanish", "cyberghost", "hotspotshield", "tunnelbear", "hideme",
        "hide\.me", "torguard", "astrill", "purevpn", "zenmate", "nekoray", "throne", "happservice",
        "tailscale", "zerotier", "hamachi", "radmin", "amnezia", "outline", "hiddify", "psiphon",
        "warp-svc", "cloudflarewarp", "anyconnect", "forticlient", "globalprotect", "pangps", "softether",
        "v2ray", "xray", "sing-box", "singbox", "clash", "mihomo", "tap0901", "wintun", "lantern"
    )
    $runningVpn = @(); $stoppedVpn = @()
    foreach ($svc in $AllServices) {
        $combined = "$($svc.Name)|$($svc.DisplayName)".ToLower()
        foreach ($kw in $vpnKeywords) {
            if ($combined -match $kw) {
                $label = $svc.DisplayName
                if ($svc.Status -eq "Running") { if ($runningVpn -notcontains $label) { $runningVpn += $label } }
                else { if ($stoppedVpn -notcontains $label) { $stoppedVpn += $label } }
                break
            }
        }
    }
    if ($runningVpn.Count -gt 0) {
        $r += "[!] VPN services RUNNING: $($runningVpn -join ', ')"
        $r += "    -> disable VPN while using zapret for best results"
    }
    if ($stoppedVpn.Count -gt 0) { $r += "[i] VPN services installed but stopped: $($stoppedVpn -join ', ')" }
    if ($runningVpn.Count -eq 0 -and $stoppedVpn.Count -eq 0) { $r += "[OK] No VPN services detected" }

    # Hosts file overrides (non-comment lines only)
    try {
        $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
        if (Test-Path $hostsFile) {
            $active = @(Get-Content $hostsFile -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
            $bad = @($active | Where-Object { $_ -match '(youtube|youtu\.be|googlevideo|ytimg|ggpht|discord)' })
            if ($bad.Count -gt 0) { $r += "[!] Hosts file overrides YouTube/Discord domains ($($bad.Count) lines) - may break or redirect them" }
            else { $r += "[OK] Hosts file: no YouTube/Discord overrides" }
        }
    } catch {}
    $r += ""

    $r += "--- Security software ---"
    $secPatterns = @(
        @{Pattern = "kaspersky|^avp"; Name = "Kaspersky"}, @{Pattern = "ekrn|eset"; Name = "ESET"},
        @{Pattern = "avast|aswbidsagent"; Name = "Avast"}, @{Pattern = "avgsvc|^avg"; Name = "AVG"},
        @{Pattern = "vsserv|bitdefender"; Name = "Bitdefender"}, @{Pattern = "norton|symantec"; Name = "Norton"},
        @{Pattern = "mfemms|mcafee"; Name = "McAfee"}, @{Pattern = "drweb|spider"; Name = "Dr.Web"},
        @{Pattern = "cmdagent|comodo"; Name = "Comodo"}, @{Pattern = "sophos"; Name = "Sophos"},
        @{Pattern = "f-secure|fsma"; Name = "F-Secure"}, @{Pattern = "360|qihoo"; Name = "360 Security"},
        @{Pattern = "mbam|malwarebytes"; Name = "Malwarebytes"}, @{Pattern = "webroot|wrsvc"; Name = "Webroot"},
        @{Pattern = "panda"; Name = "Panda"}, @{Pattern = "trend ?micro|tmbmsrv|ds_agent"; Name = "Trend Micro"}
    )
    $secFound = @()
    foreach ($svc in $AllServices) {
        if ($svc.Status -ne "Running") { continue }
        $combined = "$($svc.Name) $($svc.DisplayName)".ToLower()
        foreach ($p in $secPatterns) {
            if ($combined -match $p.Pattern -and $secFound -notcontains $p.Name) { $secFound += $p.Name }
        }
    }
    if ($secFound.Count -gt 0) {
        $r += "[!] Third-party security software running: $($secFound -join ', ')"
        $r += "    -> its web/network filtering can block WinDivert or modify traffic; add the zapret folder to exclusions"
    } else { $r += "[OK] No third-party network-filtering security software detected" }

    try {
        $hvci = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue).Enabled
        if ($hvci -eq 1) {
            $r += "[!] Memory integrity (HVCI) is ON - it can block the WinDivert driver from loading"
            $r += "    -> if winws fails to start, turn off Core isolation > Memory integrity"
        }
    } catch {}
    $r += ""
    return $r
}

function Run-Diagnostics {
    Show-Progress
    Update-StatusBar "Running diagnostics..." "Info"

    $report = @()
    $report += "=== DIAGNOSTICS REPORT ==="
    $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += ""

    #  Zapret itself 
    $report += "--- Zapret ---"
    $serviceInfo = Get-ServiceInfo
    if ($serviceInfo.Installed) {
        $report += "[OK] Service installed: $($serviceInfo.Config)"
        $report += "[$(if($serviceInfo.Running){'OK'}else{'X'})] Service status: $(if($serviceInfo.Running){'Running'}else{'Stopped'})"
    } else {
        $report += "[X] Service not installed"
    }

    $winwsProc = Get-Process -Name winws -ErrorAction SilentlyContinue
    $report += "[$(if($winwsProc){'OK'}else{'X'})] winws.exe: $(if($winwsProc){'Running (' + @($winwsProc).Count + ')'}else{'Not running'})"

    $binPath = Join-Path $ScriptPath "bin"
    if (Test-Path "$binPath\*.sys") {
        $report += "[OK] WinDivert64.sys found"
    } else {
        $report += "[X] WinDivert64.sys NOT found"
    }

    $wdStatus = (sc.exe query WinDivert 2>&1 | Out-String)
    if ($wdStatus -match "RUNNING|STOP_PENDING") {
        if (-not $winwsProc) {
            $report += "[!] WinDivert active but winws.exe not running - possible conflict"
        } else {
            $report += "[OK] WinDivert service active"
        }
    }

    $bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
    if ($bfe -and $bfe.Status -eq "Running") {
        $report += "[OK] Base Filtering Engine running"
    } else {
        $report += "[X] Base Filtering Engine NOT running (required for zapret)"
    }

    # TCP timestamps (registry first: locale-independent)
    $tcpTimestampReg = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "Tcp1323Opts" -ErrorAction SilentlyContinue)."Tcp1323Opts"
    $tcpTsNetsh = netsh interface tcp show global 2>&1 | Out-String
    $tcpTsEnabled = ($tcpTimestampReg -band 2) -eq 2 -or
                    $tcpTsNetsh -match "(?i)timestamp[s]?\s*[:\-]\s*enabled" -or
                    $tcpTsNetsh -match "(?i)enabled\s+.*timestamp"
    if ($tcpTsEnabled) {
        $report += "[OK] TCP Timestamps enabled"
    } else {
        $report += "[!] TCP Timestamps disabled - enabling..."
        netsh interface tcp set global timestamps=enabled 2>&1 | Out-Null
        $report += "    -> attempted to enable automatically"
    }

    # Encrypted DNS
    try {
        $dohCount = (Get-ChildItem -Recurse -Path "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\" -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DohFlags -gt 0 } |
            Measure-Object).Count
        if ($dohCount -gt 0) {
            $report += "[OK] Encrypted DNS (DoH) configured"
        } else {
            $report += "[!] No encrypted DNS found - configure DoH in browser or Windows settings"
        }
    } catch {
        $report += "[?] DNS/DoH check failed"
    }
    $report += ""

    #  Network / DNS / IPv6 
    $report += Get-NetworkDiagnostics
    $report += Get-DnsDiagnostics
    $report += Get-Ipv6Diagnostics

    #  Conflicting software 
    $allServiceObjects = Get-Service -ErrorAction SilentlyContinue
    $report += "--- Conflicts ---"
    $conflictChecks = @(
        @{Pattern="killer";                     Name="Killer Network"},
        @{Pattern="smartbyte";                  Name="SmartByte"},
        @{Pattern="adguard";                    Name="AdGuard"},
        @{Pattern="epwd|tracssrvwrapper";        Name="Check Point VPN"},
        @{Pattern="intelcns|intel.*connect";    Name="Intel Connectivity"}
    )
    $foundConflicts = @()
    foreach ($svc in $allServiceObjects) {
        $combined = "$($svc.Name) $($svc.DisplayName)".ToLower()
        foreach ($c in $conflictChecks) {
            if ($combined -match $c.Pattern -and $foundConflicts -notcontains $c.Name) {
                $foundConflicts += $c.Name
            }
        }
    }
    if ($foundConflicts.Count -gt 0) {
        $report += "[X] Conflicting software found: $($foundConflicts -join ', ')"
    } else {
        $report += "[OK] No known conflicting software"
    }

    $bypassServiceNames = @("GoodbyeDPI","discordfix_zapret","winws1","winws2")
    $foundBypass = $allServiceObjects | Where-Object { $bypassServiceNames -contains $_.Name }
    if ($foundBypass) {
        $report += "[X] Conflicting bypass services: $($foundBypass.Name -join ', ')"
    } else {
        $report += "[OK] No competing bypass services"
    }
    $report += ""

    $report += Get-InterferenceDiagnostics -AllServices $allServiceObjects

    #  Summary 
    $nErr  = @($report | Where-Object { $_ -match '^\[X\]' }).Count
    $nWarn = @($report | Where-Object { $_ -match '^\[!\]' }).Count
    $report += "--- Summary ---"
    if ($nErr -eq 0 -and $nWarn -eq 0) { $report += "[OK] Nothing found that should interfere with zapret" }
    else { $report += "$(if($nErr -gt 0){'[X]'}else{'[!]'}) Problems: $nErr, warnings: $nWarn" }
    $report += ""
    $report += "=== END REPORT ==="

    #  Build window 
    $diagForm = New-Object System.Windows.Forms.Form
    $diagForm.Text = "Diagnostics Report"
    $diagForm.Size = New-Object System.Drawing.Size(720, 740)
    $diagForm.StartPosition = "CenterScreen"
    $diagForm.BackColor = $colors.Midnight
    $diagForm.FormBorderStyle = "FixedDialog"
    $diagForm.MaximizeBox = $false

    $textBox = New-Object System.Windows.Forms.RichTextBox
    $textBox.ReadOnly = $true
    $textBox.ScrollBars = "Vertical"
    $textBox.Location = New-Object System.Drawing.Point(12, 12)
    $textBox.Size = New-Object System.Drawing.Size(680, 630)
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $textBox.BackColor = $colors.DarkGray
    $textBox.ForeColor = $colors.Light
    $textBox.BorderStyle = "None"
    $textBox.WordWrap = $true
    $diagForm.Controls.Add($textBox)

    foreach ($line in $report) {
        $col = switch -Regex ($line) {
            "^\[OK\]"   { $colors.Success }
            "^\[X\]"    { $colors.Danger  }
            "^\[!\]"    { $colors.Warning }
            "^\[\?\]"   { $colors.Primary }
            "^\[i\]"    { [System.Drawing.Color]::FromArgb(150, 170, 190) }
            "^\s+"      { [System.Drawing.Color]::FromArgb(120, 140, 160) }
            "^---"      { $colors.White }
            "^==="      { [System.Drawing.Color]::FromArgb(150, 170, 190) }
            default     { $colors.Light   }
        }
        $textBox.SelectionStart  = $textBox.TextLength
        $textBox.SelectionLength = 0
        $textBox.SelectionColor  = $col
        $textBox.AppendText("$line`n")
    }

    $btnClearCache = New-Object System.Windows.Forms.Button
    $btnClearCache.Location = New-Object System.Drawing.Point(12, 654)
    $btnClearCache.Size = New-Object System.Drawing.Size(180, 36)
    $btnClearCache.Text = "Clear Discord Cache"
    $btnClearCache.BackColor = $colors.DarkGray
    $btnClearCache.ForeColor = $colors.Light
    $btnClearCache.FlatStyle = "Flat"
    $btnClearCache.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnClearCache.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnClearCache.Add_Click({ Clear-DiscordCache; $diagForm.Close() })
    $diagForm.Controls.Add($btnClearCache)

    $btnCopyReport = New-Object System.Windows.Forms.Button
    $btnCopyReport.Location = New-Object System.Drawing.Point(204, 654)
    $btnCopyReport.Size = New-Object System.Drawing.Size(130, 36)
    $btnCopyReport.Text = "Copy report"
    $btnCopyReport.BackColor = $colors.DarkGray
    $btnCopyReport.ForeColor = $colors.Light
    $btnCopyReport.FlatStyle = "Flat"
    $btnCopyReport.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnCopyReport.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCopyReport.Add_Click({
        try { [System.Windows.Forms.Clipboard]::SetText(($report -join "`r`n")); Update-StatusBar "Report copied to clipboard" "Success" } catch {}
    })
    $diagForm.Controls.Add($btnCopyReport)

    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Location = New-Object System.Drawing.Point(562, 654)
    $closeBtn.Size = New-Object System.Drawing.Size(130, 36)
    $closeBtn.Text = "Close"
    $closeBtn.BackColor = $colors.Primary
    $closeBtn.ForeColor = $colors.White
    $closeBtn.FlatStyle = "Flat"
    $closeBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $closeBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $closeBtn.Add_Click({ $diagForm.Close() })
    $diagForm.Controls.Add($closeBtn)

    Hide-Progress
    Update-StatusBar "Diagnostics complete" "Success"
    $diagForm.ShowDialog() | Out-Null
}

function Clear-DiscordCache {
    Update-StatusBar "Clearing Discord cache..." "Info"

    $variants = @(
        @{ Process = "Discord";            Dir = "$env:APPDATA\discord" },
        @{ Process = "DiscordPTB";         Dir = "$env:APPDATA\discordptb" },
        @{ Process = "DiscordCanary";      Dir = "$env:APPDATA\discordcanary" },
        @{ Process = "DiscordDevelopment"; Dir = "$env:APPDATA\discorddevelopment" }
    )

    $clearedCount = 0
    $foundAny = $false
    foreach ($v in $variants) {
        if (-not (Test-Path $v.Dir)) { continue }
        $foundAny = $true

        $proc = Get-Process -Name $v.Process -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Name $v.Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }

        foreach ($sub in @("Cache", "Code Cache", "GPUCache")) {
            $path = Join-Path $v.Dir $sub
            if (Test-Path $path) {
                try {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    $clearedCount++
                } catch {
                    Write-Host "Failed to clear: $path"
                }
            }
        }
    }

    if (-not $foundAny) {
        Update-StatusBar "No Discord installations found" "Info"
    } elseif ($clearedCount -gt 0) {
        Update-StatusBar "Discord cache cleared ($clearedCount folders)" "Success"
    } else {
        Update-StatusBar "No Discord cache found" "Info"
    }
}

function ConvertTo-IpUInt64 {
    param([System.Net.IPAddress]$Ip)
    $b = $Ip.GetAddressBytes()
    [Array]::Reverse($b)
    return [uint64][BitConverter]::ToUInt32($b, 0)
}

function Test-IpInIpset {
    # IPv4 membership check against lines of ipset-all.txt (CIDR or single IPs). IPv6 lines are skipped.
    param([System.Net.IPAddress]$Ip, [string[]]$Lines)
    $n = ConvertTo-IpUInt64 $Ip
    $full = [uint64]4294967295
    foreach ($l in $Lines) {
        $l = ([string]$l).Trim()
        if (-not $l -or $l.StartsWith("#") -or $l.Contains(":")) { continue }
        $p = $l.Split("/")
        $addr = $null
        if (-not [System.Net.IPAddress]::TryParse($p[0], [ref]$addr)) { continue }
        $bits = 32
        if ($p.Count -gt 1) { $bits = [int]$p[1] }
        if ($bits -le 0) { return $true }
        $mask = ($full -shl (32 - $bits)) -band $full
        if (($n -band $mask) -eq ((ConvertTo-IpUInt64 $addr) -band $mask)) { return $true }
    }
    return $false
}

function Test-PortInRanges {
    param([int]$Port, [string]$Ranges)
    foreach ($item in ($Ranges -split ",")) {
        $parts = $item.Trim().Split("-")
        if ($parts.Count -eq 1 -and $parts[0] -match '^\d+$') { if ([int]$parts[0] -eq $Port) { return $true } }
        elseif ($parts.Count -eq 2 -and $parts[0] -match '^\d+$' -and $parts[1] -match '^\d+$') {
            if ($Port -ge [int]$parts[0] -and $Port -le [int]$parts[1]) { return $true }
        }
    }
    return $false
}

function Test-StunProbe {
    # Sends STUN binding requests over UDP; returns how many got a valid answer and the average RTT.
    param($Targets, [int]$Attempts = 2, [int]$TimeoutMs = 1500)
    $ok = 0; $total = 0; $times = @()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    foreach ($t in $Targets) {
        for ($i = 0; $i -lt $Attempts; $i++) {
            $total++
            $udp = $null
            try {
                $tx = New-Object byte[] 12
                $rng.GetBytes($tx)
                $req = [byte[]](@(0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42) + $tx)
                $udp = New-Object System.Net.Sockets.UdpClient
                $udp.Client.ReceiveTimeout = $TimeoutMs
                $udp.Connect($t.Ip, $t.Port)
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                [void]$udp.Send($req, $req.Length)
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $resp = $udp.Receive([ref]$ep)
                $sw.Stop()
                $match = ($resp.Length -ge 20 -and $resp[0] -eq 0x01 -and $resp[1] -eq 0x01)
                if ($match) { for ($k = 0; $k -lt 12; $k++) { if ($resp[8 + $k] -ne $tx[$k]) { $match = $false; break } } }
                if ($match) { $ok++; $times += $sw.Elapsed.TotalMilliseconds }
            } catch {
            } finally {
                if ($udp) { $udp.Close() }
            }
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
    $rng.Dispose()
    $avg = $null
    if ($times.Count -gt 0) { $avg = [math]::Round((($times | Measure-Object -Average).Average), 1) }
    return @{ Ok = $ok; Total = $total; AvgMs = $avg }
}

function Invoke-AutoFakes {
    param($FakeType, $BinFiles)

    $binPath    = Join-Path $ScriptPath "bin"
    $activePath = Join-Path $binPath $FakeType.ActiveFile
    $isDiscord  = ($FakeType.ActiveFile -eq "ACTIVE_DISCORD_UDP.bin")
    $warn = [System.Windows.Forms.MessageBoxIcon]::Warning
    $okBtn = [System.Windows.Forms.MessageBoxButtons]::OK

    if (-not (Get-ServiceInfo).Installed) {
        [System.Windows.Forms.MessageBox]::Show("Auto mode restarts the zapret service for every candidate, so the service must be installed first.", "Auto fake", $okBtn, $warn) | Out-Null
        return
    }

    # probe servers + preconditions
    $probeList = @()
    if ($isDiscord) {
        $probeList = @("stun.l.google.com:19302", "stun1.l.google.com:19302", "stun2.l.google.com:19302")
    } else {
        $gf = Get-GameFilterStatus
        if ($gf.FilterUDP -eq "12") {
            [System.Windows.Forms.MessageBox]::Show("GameFilter UDP is disabled - the game fake is not used. Enable Game Filter (TCP+UDP or UDP) first.", "Auto fake", $okBtn, $warn) | Out-Null
            return
        }
        if (-not (Test-PortInRanges -Port 3478 -Ranges $gf.FilterUDP)) {
            [System.Windows.Forms.MessageBox]::Show("Probe port 3478 is outside your GameFilter UDP range ($($gf.FilterUDP)), so the result would not reflect the game fake.", "Auto fake", $okBtn, $warn) | Out-Null
            return
        }
        $probeList = @("stun.cloudflare.com:3478", "stun.stunprotocol.org:3478", "stun.nextcloud.com:3478")
    }

    $ipsetMode  = Get-IPSetStatus
    $ipsetLines = @()
    if (-not $isDiscord) {
        if ($ipsetMode -eq "none") {
            [System.Windows.Forms.MessageBox]::Show("IPSet is in NONE mode - the game fake is never applied. Switch IPSet to LOADED or ANY first.", "Auto fake", $okBtn, $warn) | Out-Null
            return
        }
        if ($ipsetMode -eq "loaded") { $ipsetLines = @(Get-Content (Join-Path $ScriptPath "lists\ipset-all.txt") -ErrorAction SilentlyContinue) }
    }

    $targets = @()
    foreach ($p in $probeList) {
        $h, $port = $p.Split(":")
        try {
            $ip = [System.Net.Dns]::GetHostAddresses($h) | Where-Object { $_.AddressFamily -eq "InterNetwork" } | Select-Object -First 1
            if (-not $ip) { continue }
            if (-not $isDiscord -and $ipsetMode -eq "loaded" -and -not (Test-IpInIpset -Ip $ip -Lines $ipsetLines)) { continue }
            $targets += @{ Ip = $ip; Port = [int]$port; Host = $h }
        } catch {}
    }
    if ($targets.Count -eq 0) {
        $why = if ($isDiscord) { "Could not resolve the STUN test servers (DNS/network problem)." } else { "None of the STUN test servers is covered by your ipset-all list (or DNS failed), so the game fake can't be measured here. Use manual selection." }
        [System.Windows.Forms.MessageBox]::Show($why, "Auto fake", $okBtn, $warn) | Out-Null
        return
    }

    $cands = @($BinFiles | Where-Object { $_.BaseName -match '^(quic_initial_|stun)' })
    if ($cands.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No UDP fake candidates (quic_initial_*, stun*) in bin.", "Auto fake", $okBtn, $warn) | Out-Null
        return
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Auto will test $($cands.Count) fakes for '$($FakeType.Label)': for each one the zapret service is restarted and STUN requests are sent through the filter.`n`nThis takes a few minutes and internet may blink during restarts. The best fake is applied; if nothing beats the current one, it is kept.`n`nContinue?",
        "Auto fake", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    # progress window
    $script:afCancel = $false
    $pf = New-Object System.Windows.Forms.Form
    $pf.Text = "Auto fake - $($FakeType.Label)"
    $pf.ClientSize = New-Object System.Drawing.Size(480, 360)
    $pf.StartPosition = "CenterScreen"
    $pf.FormBorderStyle = "FixedDialog"
    $pf.MaximizeBox = $false; $pf.MinimizeBox = $false; $pf.ControlBox = $false
    $pf.BackColor = $colors.Midnight

    $lblCur = New-Object System.Windows.Forms.Label
    $lblCur.Location = New-Object System.Drawing.Point(15, 12)
    $lblCur.Size = New-Object System.Drawing.Size(450, 22)
    $lblCur.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblCur.ForeColor = $colors.Light
    $pf.Controls.Add($lblCur)

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Location = New-Object System.Drawing.Point(15, 40)
    $bar.Size = New-Object System.Drawing.Size(450, 20)
    $bar.Minimum = 0; $bar.Maximum = $cands.Count + 1; $bar.Value = 0
    $pf.Controls.Add($bar)

    $logBox = New-Object System.Windows.Forms.ListBox
    $logBox.Location = New-Object System.Drawing.Point(15, 70)
    $logBox.Size = New-Object System.Drawing.Size(450, 235)
    $logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $logBox.BackColor = $colors.DarkGray
    $logBox.ForeColor = $colors.Light
    $pf.Controls.Add($logBox)

    $btnStop = New-Object System.Windows.Forms.Button
    $btnStop.Location = New-Object System.Drawing.Point(350, 315)
    $btnStop.Size = New-Object System.Drawing.Size(115, 34)
    $btnStop.Text = "Cancel"
    $btnStop.BackColor = $colors.Danger
    $btnStop.ForeColor = $colors.White
    $btnStop.FlatStyle = "Flat"
    $btnStop.Add_Click({ $script:afCancel = $true; $btnStop.Enabled = $false; $btnStop.Text = "Stopping..." })
    $pf.Controls.Add($btnStop)

    $origCopy = Join-Path $env:TEMP "zapret_active_fake_orig.bin"
    $hadOrig = Test-Path $activePath
    if ($hadOrig) { Copy-Item $activePath $origCopy -Force }

    $results = @()
    $form.Enabled = $false
    $pf.Show()
    [System.Windows.Forms.Application]::DoEvents()

    $setFake = {
        param($srcPath)
        Stop-ZapretService -Silent $true | Out-Null
        Start-Sleep -Milliseconds 300
        if ($srcPath) {
            if (Test-Path $activePath) { Remove-Item $activePath -Force -ErrorAction SilentlyContinue }
            Copy-Item $srcPath $activePath -Force
        }
        return (Start-ZapretService -Silent $true)
    }

    try {
        $queue = @(@{ Name = "(current)"; Path = $null }) + @($cands | ForEach-Object { @{ Name = $_.BaseName; Path = $_.FullName } })
        foreach ($c in $queue) {
            if ($script:afCancel) { break }
            $lblCur.Text = "Testing: $($c.Name)"
            [System.Windows.Forms.Application]::DoEvents()

            $started = & $setFake $c.Path
            if (-not $started) {
                $results += [pscustomobject]@{ Name = $c.Name; Ok = 0; Total = 1; Avg = $null }
                $logBox.Items.Add("{0,-34} service failed to start" -f $c.Name) | Out-Null
            } else {
                for ($w = 0; $w -lt 8; $w++) { Start-Sleep -Milliseconds 100; [System.Windows.Forms.Application]::DoEvents() }
                $pr = Test-StunProbe -Targets $targets
                $results += [pscustomobject]@{ Name = $c.Name; Ok = $pr.Ok; Total = $pr.Total; Avg = $pr.AvgMs }
                $avgTxt = if ($pr.AvgMs) { "$($pr.AvgMs) ms" } else { "-" }
                $logBox.Items.Add(("{0,-34} {1}/{2}  {3}" -f $c.Name, $pr.Ok, $pr.Total, $avgTxt)) | Out-Null
            }
            $logBox.TopIndex = $logBox.Items.Count - 1
            $bar.Value = [math]::Min($bar.Maximum, $bar.Value + 1)
            [System.Windows.Forms.Application]::DoEvents()
        }

        # choose
        $base  = $results | Where-Object { $_.Name -eq "(current)" } | Select-Object -First 1
        $valid = @($results | Where-Object { $_.Name -ne "(current)" -and $_.Total -gt 0 })
        $best  = $valid | Sort-Object @{ Expression = { $_.Ok }; Descending = $true }, @{ Expression = { if ($_.Avg) { $_.Avg } else { 99999 } } } | Select-Object -First 1
        $choice = $null; $reason = ""
        if ($script:afCancel) {
            $reason = "Cancelled - original fake restored."
        } elseif (-not $base -or -not $best) {
            $reason = "No usable results - original fake restored."
        } elseif ($best.Ok -gt $base.Ok) {
            $choice = $best; $reason = "Best: $($best.Name) ($($best.Ok)/$($best.Total) answered vs $($base.Ok)/$($base.Total) for the current one)."
        } elseif ($best.Ok -eq $base.Ok -and $best.Ok -gt 0 -and $best.Avg -and $base.Avg -and $best.Avg -lt ($base.Avg * 0.8)) {
            $choice = $best; $reason = "Best: $($best.Name) - same reliability ($($best.Ok)/$($best.Total)) but faster ($($best.Avg) ms vs $($base.Avg) ms)."
        } elseif ($base.Ok -eq 0) {
            $reason = "No fake got any STUN answer - probes are probably blocked by your network/firewall, so nothing was changed."
        } else {
            $reason = "No candidate was clearly better than the current fake ($($base.Ok)/$($base.Total)) - kept the current one."
        }

        $lblCur.Text = "Applying result..."
        [System.Windows.Forms.Application]::DoEvents()
        if ($choice) {
            $cand = $cands | Where-Object { $_.BaseName -eq $choice.Name } | Select-Object -First 1
            & $setFake $cand.FullName | Out-Null
            Update-StatusBar "$($FakeType.Label) fake set to $($choice.Name) (auto)" "Success"
        } else {
            if ($hadOrig) { Copy-Item $origCopy $activePath -Force -ErrorAction SilentlyContinue }
            & $setFake $null | Out-Null
            Update-StatusBar "Auto fake: $reason" "Info"
        }
    } catch {
        if ($hadOrig) { Copy-Item $origCopy $activePath -Force -ErrorAction SilentlyContinue }
        & $setFake $null | Out-Null
        $reason = "Error: $($_.Exception.Message) - original fake restored."
        Update-StatusBar "Auto fake failed: $($_.Exception.Message)" "Error"
    } finally {
        $form.Enabled = $true
        $pf.Close(); $pf.Dispose()
        Remove-Item $origCopy -Force -ErrorAction SilentlyContinue
        Update-ServiceStatusBar
        Update-StatusDisplay
    }

    $top = @($results | Where-Object { $_.Total -gt 0 } | Sort-Object @{ Expression = { $_.Ok }; Descending = $true }, @{ Expression = { if ($_.Avg) { $_.Avg } else { 99999 } } } | Select-Object -First 6 |
        ForEach-Object { "{0,-34} {1}/{2}  {3}" -f $_.Name, $_.Ok, $_.Total, $(if ($_.Avg) { "$($_.Avg) ms" } else { "-" }) })
    [System.Windows.Forms.MessageBox]::Show(
        "$reason`n`nTop results (STUN answers / avg RTT):`n$($top -join "`n")`n`nNote: this measures whether UDP/STUN traffic passes and how fast with each fake. It is a proxy, not a real Discord voice or game test.",
        "Auto fake result", $okBtn, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}

function Replace-ActiveFakes {
    $binPath = Join-Path $ScriptPath "bin"
    if (-not (Test-Path $binPath)) {
        [System.Windows.Forms.MessageBox]::Show(
            "bin folder not found.",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    # fake types this feature supports (mirrors service.bat: only Discord UDP (Voice) and GameFilter UDP)
    $fakeTypes = @(
        @{ Label = "Discord UDP (Voice)"; ActiveFile = "ACTIVE_DISCORD_UDP.bin" },
        @{ Label = "GameFilter UDP";      ActiveFile = "ACTIVE_GAME_UDP.bin" }
    )

    # Collect all .bin files (excluding ACTIVE_*), and hash the ACTIVE_* files to detect current selection
    $binFiles = @(Get-ChildItem -LiteralPath $binPath -Filter "*.bin" -ErrorAction SilentlyContinue |
                Where-Object { $_.BaseName -notlike "ACTIVE_*" })

    if ($binFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "No .bin files were found in the bin folder.",
            "Replace Active Fakes",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    function Get-FakeHashSafe($path) {
        if (Test-Path $path) {
            try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash } catch { return $null }
        }
        return $null
    }

    foreach ($ft in $fakeTypes) {
        $activePath = Join-Path $binPath $ft.ActiveFile
        $activeHash = Get-FakeHashSafe $activePath
        $ft.Current = "(not found)"
        if ($activeHash) {
            foreach ($f in $binFiles) {
                if ((Get-FakeHashSafe $f.FullName) -eq $activeHash) {
                    $ft.Current = $f.BaseName
                    break
                }
            }
        }
    }

    #  Dialog 
    $rf = New-Object System.Windows.Forms.Form
    $rf.Text = "Replace Active Fakes"
    $rf.Size = New-Object System.Drawing.Size(480, 480)
    $rf.StartPosition = "CenterScreen"
    $rf.BackColor = $colors.Midnight
    $rf.FormBorderStyle = "FixedDialog"
    $rf.MaximizeBox = $false

    $lblType = New-Object System.Windows.Forms.Label
    $lblType.Location = New-Object System.Drawing.Point(15, 15)
    $lblType.Size = New-Object System.Drawing.Size(440, 20)
    $lblType.Text = "Fake type:"
    $lblType.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblType.ForeColor = $colors.Light
    $rf.Controls.Add($lblType)

    $cmbType = New-Object System.Windows.Forms.ComboBox
    $cmbType.Location = New-Object System.Drawing.Point(15, 38)
    $cmbType.Size = New-Object System.Drawing.Size(440, 26)
    $cmbType.DropDownStyle = "DropDownList"
    $cmbType.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    foreach ($ft in $fakeTypes) {
        $cmbType.Items.Add("$($ft.Label)  -  current: $($ft.Current)") | Out-Null
    }
    $cmbType.SelectedIndex = 0
    $rf.Controls.Add($cmbType)

    $lblFile = New-Object System.Windows.Forms.Label
    $lblFile.Location = New-Object System.Drawing.Point(15, 76)
    $lblFile.Size = New-Object System.Drawing.Size(440, 20)
    $lblFile.Text = "Replace with fake file:"
    $lblFile.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblFile.ForeColor = $colors.Light
    $rf.Controls.Add($lblFile)

    $lb = New-Object System.Windows.Forms.ListBox
    $lb.Location = New-Object System.Drawing.Point(15, 100)
    $lb.Size = New-Object System.Drawing.Size(440, 280)
    $lb.Font = New-Object System.Drawing.Font("Consolas", 10)
    $lb.BackColor = $colors.DarkGray
    $lb.ForeColor = $colors.Light
    foreach ($f in $binFiles) { $lb.Items.Add($f.BaseName) | Out-Null }
    $lb.SelectedIndex = 0
    $rf.Controls.Add($lb)

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Location = New-Object System.Drawing.Point(255, 395)
    $btnApply.Size = New-Object System.Drawing.Size(100, 36)
    $btnApply.Text = "Replace"
    $btnApply.BackColor = $colors.Success
    $btnApply.ForeColor = $colors.White
    $btnApply.FlatStyle = "Flat"
    $btnApply.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnApply.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnApply.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $rf.Controls.Add($btnApply)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(360, 395)
    $btnCancel.Size = New-Object System.Drawing.Size(95, 36)
    $btnCancel.Text = "Cancel"
    $btnCancel.BackColor = $colors.Slate
    $btnCancel.ForeColor = $colors.White
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $btnCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $rf.Controls.Add($btnCancel)

    $script:rfAuto = $false
    $btnAutoFake = New-Object System.Windows.Forms.Button
    $btnAutoFake.Location = New-Object System.Drawing.Point(15, 395)
    $btnAutoFake.Size = New-Object System.Drawing.Size(140, 36)
    $btnAutoFake.Text = "Auto (best fake)"
    $btnAutoFake.BackColor = $colors.Primary
    $btnAutoFake.ForeColor = $colors.White
    $btnAutoFake.FlatStyle = "Flat"
    $btnAutoFake.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnAutoFake.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnAutoFake.Add_Click({ $script:rfAuto = $true; $rf.DialogResult = [System.Windows.Forms.DialogResult]::OK; $rf.Close() })
    $rf.Controls.Add($btnAutoFake)

    $rf.AcceptButton = $btnApply
    $rf.CancelButton = $btnCancel

    if ($rf.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    if ($script:rfAuto) {
        Invoke-AutoFakes -FakeType $fakeTypes[$cmbType.SelectedIndex] -BinFiles $binFiles
        return
    }

    $selectedType = $fakeTypes[$cmbType.SelectedIndex]
    $selectedFile = $binFiles[$lb.SelectedIndex]
    $activePath = Join-Path $binPath $selectedType.ActiveFile

    try {
        if (Test-Path $activePath) { Remove-Item $activePath -Force -ErrorAction SilentlyContinue }
        Copy-Item $selectedFile.FullName $activePath -Force
        Update-StatusBar "$($selectedType.Label) fake set to $($selectedFile.BaseName) - restart service to apply" "Success"
    } catch {
        Update-StatusBar "Failed to replace active fake: $($_.Exception.Message)" "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to replace the active fake file.`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Run-Tests {
    $testScript = Join-Path $ScriptPath "utils\test zapret.ps1"
    if (-not (Test-Path $testScript)) {
        Update-StatusBar "Test script not found!" "Error"
        return
    }
    
    Update-StatusBar "Running tests in PowerShell..." "Info"
    
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$testScript`"" -WindowStyle Normal
        Update-StatusBar "Tests launched" "Success"
    } catch {
        Update-StatusBar "Failed to run tests: $_" "Error"
    }
}


$form = New-Object System.Windows.Forms.Form
$form.Text = "Zapret Service Manager v$LOCAL_VERSION"
$form.Size = New-Object System.Drawing.Size(525, 723)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = $colors.Midnight
$form.ForeColor = $colors.Light

$statusPanel = New-Object System.Windows.Forms.Panel
$statusPanel.Location = New-Object System.Drawing.Point(0, 0)
$statusPanel.Size = New-Object System.Drawing.Size(550, 55)  
$statusPanel.BackColor = $colors.DarkPrimary 
$statusPanel.BorderStyle = "FixedSingle"
$form.Controls.Add($statusPanel)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Location = New-Object System.Drawing.Point(10, 10)
$statusLabel.Size = New-Object System.Drawing.Size(525, 35)  
$statusLabel.Text = "  Zapret Service Manager v$LOCAL_VERSION - Ready"
$statusLabel.ForeColor = $colors.Light
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$statusLabel.TextAlign = "MiddleLeft"
$statusPanel.Controls.Add($statusLabel)

$statusIcon = New-Object System.Windows.Forms.Label
$statusIcon.Location = New-Object System.Drawing.Point(10, 15)
$statusIcon.Size = New-Object System.Drawing.Size(20, 20)
$statusIcon.Text = "●"
$statusIcon.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$statusIcon.ForeColor = $colors.Success
$statusIcon.TextAlign = "MiddleCenter"
$statusPanel.Controls.Add($statusIcon)

$lblService = New-Object System.Windows.Forms.Label
$lblService.Location = New-Object System.Drawing.Point(15, 65)
$lblService.Size = New-Object System.Drawing.Size(480, 25)
$lblService.Text = "SERVICE CONTROL"
$lblService.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblService.ForeColor = $colors.Light
$form.Controls.Add($lblService)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Location = New-Object System.Drawing.Point(15, 95)
$btnInstall.Size = New-Object System.Drawing.Size(150, 40)
$btnInstall.Text = "Install Service"
$btnInstall.BackColor = $colors.Success
$btnInstall.ForeColor = $colors.White
$btnInstall.FlatStyle = "Flat"
$btnInstall.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnInstall.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnInstall.Add_Click({ Install-ZapretService })
$form.Controls.Add($btnInstall)

$btnStopService = New-Object System.Windows.Forms.Button
$btnStopService.Location = New-Object System.Drawing.Point(177, 95)
$btnStopService.Size = New-Object System.Drawing.Size(150, 40)
$btnStopService.Text = "Stop Service"
$btnStopService.BackColor = $colors.Slate
$btnStopService.ForeColor = $colors.White
$btnStopService.FlatStyle = "Flat"
$btnStopService.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnStopService.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnStopService.Add_Click({ 
    if (Stop-ZapretService) {
        Update-StatusBar "Service stopped" "Warning"
        Update-ServiceStatusBar
        Update-StatusDisplay
    }
})
$form.Controls.Add($btnStopService)

$btnStartService = New-Object System.Windows.Forms.Button
$btnStartService.Location = New-Object System.Drawing.Point(340, 95)
$btnStartService.Size = New-Object System.Drawing.Size(150, 40)
$btnStartService.Text = "Start Service"
$btnStartService.BackColor = $colors.Slate
$btnStartService.ForeColor = $colors.White
$btnStartService.FlatStyle = "Flat"
$btnStartService.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnStartService.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnStartService.Add_Click({ 
    if (Start-ZapretService) {
        Update-StatusBar "Service started" "Success"
        Update-ServiceStatusBar
        Update-StatusDisplay
    }
})
$form.Controls.Add($btnStartService)

$btnRemove = New-Object System.Windows.Forms.Button
$btnRemove.Location = New-Object System.Drawing.Point(15, 145)
$btnRemove.Size = New-Object System.Drawing.Size(150, 40)
$btnRemove.Text = "Remove Services"
$btnRemove.BackColor = $colors.Danger
$btnRemove.ForeColor = $colors.White
$btnRemove.FlatStyle = "Flat"
$btnRemove.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnRemove.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnRemove.Add_Click({ Remove-ZapretService })
$form.Controls.Add($btnRemove)

$btnStatus = New-Object System.Windows.Forms.Button
$btnStatus.Location = New-Object System.Drawing.Point(177, 145)
$btnStatus.Size = New-Object System.Drawing.Size(150, 40)
$btnStatus.Text = "Check Status"
$btnStatus.BackColor = $colors.Primary
$btnStatus.ForeColor = $colors.White
$btnStatus.FlatStyle = "Flat"
$btnStatus.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnStatus.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnStatus.Add_Click({ Show-ServiceStatus })
$form.Controls.Add($btnStatus)

$btnRestart = New-Object System.Windows.Forms.Button
$btnRestart.Location = New-Object System.Drawing.Point(340, 145)
$btnRestart.Size = New-Object System.Drawing.Size(150, 40)
$btnRestart.Text = "Restart Service"
$btnRestart.BackColor = $colors.Warning
$btnRestart.ForeColor = $colors.White
$btnRestart.FlatStyle = "Flat"
$btnRestart.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnRestart.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnRestart.Add_Click({ Restart-ZapretService })
$form.Controls.Add($btnRestart)

$lblSettings = New-Object System.Windows.Forms.Label
$lblSettings.Location = New-Object System.Drawing.Point(15, 200)
$lblSettings.Size = New-Object System.Drawing.Size(480, 25)
$lblSettings.Text = "SETTINGS"
$lblSettings.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblSettings.ForeColor = $colors.Light
$form.Controls.Add($lblSettings)

$btnGameFilter = New-Object System.Windows.Forms.Button
$btnGameFilter.Location = New-Object System.Drawing.Point(15, 230)
$btnGameFilter.Size = New-Object System.Drawing.Size(475, 40)
$btnGameFilter.Text = "Game Filter [...]"
$btnGameFilter.BackColor = $colors.DarkGray
$btnGameFilter.ForeColor = $colors.Light
$btnGameFilter.FlatStyle = "Flat"
$btnGameFilter.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnGameFilter.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnGameFilter.Add_Click({ Show-GameFilterDialog })
$form.Controls.Add($btnGameFilter)

$btnIPSet = New-Object System.Windows.Forms.Button
$btnIPSet.Location = New-Object System.Drawing.Point(15, 280)
$btnIPSet.Size = New-Object System.Drawing.Size(475, 40)
$btnIPSet.Text = "IPSet Filter [...]"
$btnIPSet.BackColor = $colors.DarkGray
$btnIPSet.ForeColor = $colors.Light
$btnIPSet.FlatStyle = "Flat"
$btnIPSet.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnIPSet.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnIPSet.Add_Click({ Toggle-IPSet })
$form.Controls.Add($btnIPSet)

$btnAutoUpdate = New-Object System.Windows.Forms.Button
$btnAutoUpdate.Location = New-Object System.Drawing.Point(15, 330)
$btnAutoUpdate.Size = New-Object System.Drawing.Size(475, 40)
$btnAutoUpdate.Text = "Auto-Update Check [...]"
$btnAutoUpdate.BackColor = $colors.DarkGray
$btnAutoUpdate.ForeColor = $colors.Light
$btnAutoUpdate.FlatStyle = "Flat"
$btnAutoUpdate.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnAutoUpdate.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnAutoUpdate.Add_Click({ Toggle-AutoUpdate })
$form.Controls.Add($btnAutoUpdate)

$btnUserLists = New-Object System.Windows.Forms.Button
$btnUserLists.Location = New-Object System.Drawing.Point(15, 380)
$btnUserLists.Size = New-Object System.Drawing.Size(475, 40)
$btnUserLists.Text = "User Lists (domains / IPs)"
$btnUserLists.BackColor = $colors.DarkGray
$btnUserLists.ForeColor = $colors.Light
$btnUserLists.FlatStyle = "Flat"
$btnUserLists.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnUserLists.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnUserLists.Add_Click({ Open-UserListsEditor })
$form.Controls.Add($btnUserLists)

$lblUpdates = New-Object System.Windows.Forms.Label
$lblUpdates.Location = New-Object System.Drawing.Point(15, 440)
$lblUpdates.Size = New-Object System.Drawing.Size(480, 25)
$lblUpdates.Text = "UPDATES"
$lblUpdates.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblUpdates.ForeColor = $colors.Light
$form.Controls.Add($lblUpdates)

$btnUpdateIPSet = New-Object System.Windows.Forms.Button
$btnUpdateIPSet.Location = New-Object System.Drawing.Point(15, 470)
$btnUpdateIPSet.Size = New-Object System.Drawing.Size(150, 40)
$btnUpdateIPSet.Text = "Update IPSet"
$btnUpdateIPSet.BackColor = $colors.DarkGray
$btnUpdateIPSet.ForeColor = $colors.Light
$btnUpdateIPSet.FlatStyle = "Flat"
$btnUpdateIPSet.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnUpdateIPSet.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnUpdateIPSet.Add_Click({ Update-IPSetList })
$form.Controls.Add($btnUpdateIPSet)

$btnUpdateHosts = New-Object System.Windows.Forms.Button
$btnUpdateHosts.Location = New-Object System.Drawing.Point(177, 470)
$btnUpdateHosts.Size = New-Object System.Drawing.Size(150, 40)
$btnUpdateHosts.Text = "Update Hosts"
$btnUpdateHosts.BackColor = $colors.DarkGray
$btnUpdateHosts.ForeColor = $colors.Light
$btnUpdateHosts.FlatStyle = "Flat"
$btnUpdateHosts.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnUpdateHosts.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnUpdateHosts.Add_Click({ Update-HostsFile })
$form.Controls.Add($btnUpdateHosts)

$btnCheckUpdates = New-Object System.Windows.Forms.Button
$btnCheckUpdates.Location = New-Object System.Drawing.Point(340, 470)
$btnCheckUpdates.Size = New-Object System.Drawing.Size(150, 40)
$btnCheckUpdates.Text = "Check Updates"
$btnCheckUpdates.BackColor = $colors.DarkGray
$btnCheckUpdates.ForeColor = $colors.Light
$btnCheckUpdates.FlatStyle = "Flat"
$btnCheckUpdates.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$btnCheckUpdates.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnCheckUpdates.Add_Click({ Check-Updates })
$form.Controls.Add($btnCheckUpdates)

$lblTools = New-Object System.Windows.Forms.Label
$lblTools.Location = New-Object System.Drawing.Point(15, 530)
$lblTools.Size = New-Object System.Drawing.Size(480, 25)
$lblTools.Text = "TOOLS"
$lblTools.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblTools.ForeColor = $colors.Light
$form.Controls.Add($lblTools)

$btnDiagnostics = New-Object System.Windows.Forms.Button
$btnDiagnostics.Location = New-Object System.Drawing.Point(15, 560)
$btnDiagnostics.Size = New-Object System.Drawing.Size(230, 40)
$btnDiagnostics.Text = "Run Diagnostics"
$btnDiagnostics.BackColor = $colors.Warning
$btnDiagnostics.ForeColor = $colors.White
$btnDiagnostics.FlatStyle = "Flat"
$btnDiagnostics.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnDiagnostics.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnDiagnostics.Add_Click({ Run-Diagnostics })
$form.Controls.Add($btnDiagnostics)

$btnTests = New-Object System.Windows.Forms.Button
$btnTests.Location = New-Object System.Drawing.Point(260, 560)
$btnTests.Size = New-Object System.Drawing.Size(230, 40)
$btnTests.Text = "Run Tests"
$btnTests.BackColor = $colors.DarkWarning
$btnTests.ForeColor = $colors.White
$btnTests.FlatStyle = "Flat"
$btnTests.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnTests.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnTests.Add_Click({ Run-Tests })
$form.Controls.Add($btnTests)

$btnReplaceFakes = New-Object System.Windows.Forms.Button
$btnReplaceFakes.Location = New-Object System.Drawing.Point(15, 610)
$btnReplaceFakes.Size = New-Object System.Drawing.Size(475, 40)
$btnReplaceFakes.Text = "Replace Active Fakes (Discord UDP / GameFilter UDP)"
$btnReplaceFakes.BackColor = $colors.DarkGray
$btnReplaceFakes.ForeColor = $colors.Light
$btnReplaceFakes.FlatStyle = "Flat"
$btnReplaceFakes.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnReplaceFakes.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnReplaceFakes.Add_Click({ Replace-ActiveFakes })
$form.Controls.Add($btnReplaceFakes)


Update-StatusDisplay
Update-ServiceStatusBar
Initialize-UserLists

if ((Get-UpdateCheckStatus) -eq "enabled") {
    Check-Updates -AutoCheck $true
}

[void]$form.ShowDialog()