Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

Add-Type -Name Win -Namespace Native -MemberDefinition '[DllImport("Kernel32.dll")]public static extern IntPtr GetConsoleWindow();[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'
[Native.Win]::ShowWindow([Native.Win]::GetConsoleWindow(), 0) | Out-Null

$LOCAL_VERSION = "1.9.6"
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

function Get-GameFilterStatus {
    $flagFile = Join-Path $ScriptPath "utils\game_filter.enabled"
    if (-not (Test-Path $flagFile)) {
        return @{Status="disabled"; Filter="12"; FilterTCP="12"; FilterUDP="12"}
    }
    $mode = ((Get-Content $flagFile -ErrorAction SilentlyContinue | Select-Object -First 1) + "").Trim().ToLower()
    switch ($mode) {
        "all" { return @{Status="enabled (TCP+UDP)"; Filter="1024-65535"; FilterTCP="1024-65535"; FilterUDP="1024-65535"} }
        "tcp" { return @{Status="enabled (TCP)";     Filter="1024-65535"; FilterTCP="1024-65535"; FilterUDP="12"        } }
        "udp" { return @{Status="enabled (UDP)";     Filter="1024-65535"; FilterTCP="12";         FilterUDP="1024-65535"} }
        default { return @{Status="enabled (TCP+UDP)"; Filter="1024-65535"; FilterTCP="1024-65535"; FilterUDP="1024-65535"} }
    }
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
            $defaults[$fileName] | Out-File -FilePath $filePath -Encoding UTF8 -NoNewline
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

    # ---- Editor form ----
    $ef = New-Object System.Windows.Forms.Form
    $ef.Text = "User List Editor - $Title"
    $ef.Size = New-Object System.Drawing.Size(560, 620)
    $ef.StartPosition = "CenterScreen"
    $ef.BackColor = $colors.Midnight
    $ef.FormBorderStyle = "Sizable"
    $ef.MinimumSize = New-Object System.Drawing.Size(420, 440)

    # ---- Top description panel (2 lines) ----
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

    # ---- Bottom panel ----
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

    # ---- Main text area ----
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

    # ---- Save logic ----
    $doSave = {
        $lines = $rtb.Lines | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        if ($lines.Count -eq 0) {
            $DefaultContent | Out-File -FilePath $FilePath -Encoding UTF8 -NoNewline
            $rtb.Text = $DefaultContent
            $count = 1
        } else {
            $lines | Out-File -FilePath $FilePath -Encoding UTF8
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

    # ---- Picker ----
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
        $def.Default | Out-File -FilePath $filePath -Encoding UTF8 -NoNewline
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

function Toggle-GameFilter {
    $flagFile  = Join-Path $ScriptPath "utils\game_filter.enabled"
    $utilsPath = Join-Path $ScriptPath "utils"

    # Cycle: disabled -> all -> tcp -> udp -> disabled
    $current = (Get-GameFilterStatus).Status
    switch -Wildcard ($current) {
        "disabled"         { $next = "all" }
        "enabled (TCP+UDP)"{ $next = "tcp" }
        "enabled (TCP)"    { $next = "udp" }
        default            { $next = "disabled" }
    }

    if (-not (Test-Path $utilsPath)) { New-Item -ItemType Directory -Path $utilsPath -Force | Out-Null }

    $labels = @{all="TCP+UDP"; tcp="TCP only"; udp="UDP only"}
    if ($next -eq "disabled") {
        if (Test-Path $flagFile) { Remove-Item $flagFile -Force }
        Update-StatusBar "Game filter: disabled - restart service to apply" "Warning"
    } else {
        $next | Out-File -FilePath $flagFile -Encoding ASCII -NoNewline
        Update-StatusBar "Game filter: $($labels[$next]) - restart service to apply" "Warning"
    }
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

function Update-HostsFile {
    Update-StatusBar "Checking hosts file..." "Info"
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsUrl = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts"
    $tempFile = "$env:TEMP\zapret_hosts.txt"
    try {
        Invoke-WebRequest -Uri $hostsUrl -OutFile $tempFile -TimeoutSec 10 -UseBasicParsing
        $repoContent = Get-Content $tempFile
        $firstLine = $repoContent[0]
        $lastLine = $repoContent[-1]
        $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
        if ($hostsContent -notcontains $firstLine -or $hostsContent -notcontains $lastLine) {
            Update-StatusBar "Hosts file needs update" "Warning"
            Start-Process notepad.exe -ArgumentList $tempFile
            Start-Sleep -Milliseconds 300
            Start-Process explorer.exe -ArgumentList "/select,`"$hostsFile`""
        } else {
            Update-StatusBar "Hosts file up to date!" "Success"
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Update-StatusBar "Failed: $($_.Exception.Message)" "Error"
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

        # --- Choice dialog ---
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

        # --- Auto-install path ---
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
        $guiPath = $MyInvocation.ScriptName
        if (-not $guiPath) { $guiPath = Join-Path $ScriptPath "zapret-gui.ps1" }

        Start-Process powershell.exe -ArgumentList (
            "-NoProfile -ExecutionPolicy Bypass -File `"$updaterPath`"",
            "-ScriptPath `"$ScriptPath`"",
            "-ZipUrl `"$zipUrl`"",
            "-GuiPath `"$guiPath`""
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

function Run-Diagnostics {
    Update-StatusBar "Running diagnostics..." "Info"

    $report = @()
    $report += "=== DIAGNOSTICS REPORT ==="
    $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += ""

    # --- Service ---
    $serviceInfo = Get-ServiceInfo
    if ($serviceInfo.Installed) {
        $report += "[OK] Service installed: $($serviceInfo.Config)"
        $report += "[$(if($serviceInfo.Running){'OK'}else{'X'})] Service status: $(if($serviceInfo.Running){'Running'}else{'Stopped'})"
    } else {
        $report += "[X] Service not installed"
    }

    # winws.exe process
    $winwsProc = Get-Process -Name winws -ErrorAction SilentlyContinue
    $report += "[$(if($winwsProc){'OK'}else{'X'})] winws.exe: $(if($winwsProc){"Running ($($winwsProc.Count))"}else{'Not running'})"
    $report += ""

    # --- WinDivert64.sys ---
    $binPath = Join-Path $ScriptPath "bin"
    if (Test-Path "$binPath\*.sys") {
        $report += "[OK] WinDivert64.sys found"
    } else {
        $report += "[X] WinDivert64.sys NOT found"
    }

    # WinDivert conflict (active without winws)
    $wdStatus = (sc.exe query WinDivert 2>&1 | Out-String)
    if ($wdStatus -match "RUNNING|STOP_PENDING") {
        if (-not $winwsProc) {
            $report += "[!] WinDivert active but winws.exe not running - possible conflict"
        } else {
            $report += "[OK] WinDivert service active"
        }
    }
    $report += ""

    # --- Base Filtering Engine ---
    $bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
    if ($bfe -and $bfe.Status -eq "Running") {
        $report += "[OK] Base Filtering Engine running"
    } else {
        $report += "[X] Base Filtering Engine NOT running (required for zapret)"
    }

    # --- TCP Timestamps ---
    $tcpTs = netsh interface tcp show global 2>&1 | Out-String
    if ($tcpTs -match "timestamps.*enabled" -or $tcpTs -match "enabled.*timestamps") {
        $report += "[OK] TCP Timestamps enabled"
    } else {
        $report += "[!] TCP Timestamps disabled - enabling..."
        netsh interface tcp set global timestamps=enabled 2>&1 | Out-Null
        $report += "    -> attempted to enable automatically"
    }
    $report += ""

    # --- Proxy ---
    $proxyEnabled = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).ProxyEnable
    if ($proxyEnabled -eq 1) {
        $proxyServer = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).ProxyServer
        $report += "[!] System proxy enabled: $proxyServer"
        $report += "    -> verify proxy is valid or disable if unused"
    } else {
        $report += "[OK] No system proxy"
    }

    # --- DNS / DoH ---
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

    # --- Hosts file: youtube entries ---
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue | Out-String
        if ($hostsContent -match "youtube\.com|youtu\.be") {
            $report += "[!] Hosts file has youtube.com/youtu.be entries - may interfere with YouTube"
        } else {
            $report += "[OK] Hosts file: no YouTube overrides"
        }
    }
    $report += ""

    # --- Conflicting services ---
    $allServices = sc.exe query 2>&1 | Out-String

    $checks = @(
        @{Pattern="Killer";     Name="Killer Network"},
        @{Pattern="SmartByte";  Name="SmartByte"},
        @{Pattern="Adguard";    Name="AdGuard"},
        @{Pattern="EPWD|TracSrvWrapper"; Name="Check Point"},
        @{Pattern="Intel.*Connectivity|IntelCNS"; Name="Intel Connectivity"}
    )
    $foundConflicts = @()
    foreach ($c in $checks) {
        if ($allServices -match $c.Pattern) { $foundConflicts += $c.Name }
    }
    if ($foundConflicts.Count -gt 0) {
        $report += "[X] Conflicting software found: $($foundConflicts -join ', ')"
    } else {
        $report += "[OK] No known conflicting software"
    }

    # VPN services
    $vpnMatches = [regex]::Matches($allServices, "SERVICE_NAME:\s*(\S*VPN\S*)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($vpnMatches.Count -gt 0) {
        $vpnNames = ($vpnMatches | ForEach-Object { $_.Groups[1].Value }) -join ", "
        $report += "[!] VPN services detected: $vpnNames - disable VPN while using zapret"
    } else {
        $report += "[OK] No VPN services detected"
    }

    # Competing bypass services
    $bypassServices = @("GoodbyeDPI","discordfix_zapret","winws1","winws2")
    $foundBypass = $bypassServices | Where-Object { $allServices -match $_ }
    if ($foundBypass) {
        $report += "[X] Conflicting bypass services: $($foundBypass -join ', ')"
    } else {
        $report += "[OK] No competing bypass services"
    }
    $report += ""
    $report += "=== END REPORT ==="

    # --- Build window ---
    $diagForm = New-Object System.Windows.Forms.Form
    $diagForm.Text = "Diagnostics Report"
    $diagForm.Size = New-Object System.Drawing.Size(500, 580)
    $diagForm.StartPosition = "CenterScreen"
    $diagForm.BackColor = $colors.Midnight
    $diagForm.FormBorderStyle = "FixedDialog"
    $diagForm.MaximizeBox = $false

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.ScrollBars = "Vertical"
    $textBox.Location = New-Object System.Drawing.Point(15, 15)
    $textBox.Size = New-Object System.Drawing.Size(456, 430)
    $textBox.Text = ($report -join "`r`n")
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $textBox.BackColor = $colors.DarkGray
    $textBox.ForeColor = $colors.Light
    $textBox.BorderStyle = "None"
    $diagForm.Controls.Add($textBox)

    $btnClearCache = New-Object System.Windows.Forms.Button
    $btnClearCache.Location = New-Object System.Drawing.Point(15, 460)
    $btnClearCache.Size = New-Object System.Drawing.Size(200, 40)
    $btnClearCache.Text = "Clear Discord Cache"
    $btnClearCache.BackColor = $colors.DarkGray
    $btnClearCache.ForeColor = $colors.Light
    $btnClearCache.FlatStyle = "Flat"
    $btnClearCache.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnClearCache.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnClearCache.Add_Click({ Clear-DiscordCache; $diagForm.Close() })
    $diagForm.Controls.Add($btnClearCache)

    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Location = New-Object System.Drawing.Point(340, 460)
    $closeBtn.Size = New-Object System.Drawing.Size(130, 40)
    $closeBtn.Text = "Close"
    $closeBtn.BackColor = $colors.Primary
    $closeBtn.ForeColor = $colors.White
    $closeBtn.FlatStyle = "Flat"
    $closeBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $closeBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $closeBtn.Add_Click({ $diagForm.Close() })
    $diagForm.Controls.Add($closeBtn)

    Update-StatusBar "Diagnostics complete" "Success"
    $diagForm.ShowDialog()
}

function Clear-DiscordCache {
    Update-StatusBar "Clearing Discord cache..." "Info"
    
    $discordProcess = Get-Process -Name Discord -ErrorAction SilentlyContinue
    if ($discordProcess) {
        Stop-Process -Name Discord -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    
    $cachePaths = @(
        "$env:APPDATA\discord\Cache",
        "$env:APPDATA\discord\Code Cache",
        "$env:APPDATA\discord\GPUCache"
    )
    
    $clearedCount = 0
    foreach ($path in $cachePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                $clearedCount++
            } catch {
                Write-Host "Failed to clear: $path"
            }
        }
    }
    
    if ($clearedCount -gt 0) {
        Update-StatusBar "Discord cache cleared ($clearedCount folders)" "Success"
    } else {
        Update-StatusBar "No Discord cache found" "Info"
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
$form.Size = New-Object System.Drawing.Size(525, 668)
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
$btnGameFilter.Add_Click({ Toggle-GameFilter })
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


Update-StatusDisplay
Update-ServiceStatusBar
Initialize-UserLists

if ((Get-UpdateCheckStatus) -eq "enabled") {
    Check-Updates -AutoCheck $true
}

[void]$form.ShowDialog()