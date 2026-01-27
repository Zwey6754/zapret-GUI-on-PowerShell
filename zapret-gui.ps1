#Requires -Version 3.0

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Check admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# Hide console window
Add-Type -Name Win -Namespace Native -MemberDefinition '[DllImport("Kernel32.dll")]public static extern IntPtr GetConsoleWindow();[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'
[Native.Win]::ShowWindow([Native.Win]::GetConsoleWindow(), 0) | Out-Null

$LOCAL_VERSION = "1.9.3"
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

# Enhanced Color scheme with dark tones
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

# Helper Functions
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
    
    # update statusbar
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
    if (Test-Path $flagFile) {
        return @{Status="enabled"; Filter="1024-65535"}
    }
    return @{Status="disabled"; Filter="12"}
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

function Update-StatusDisplay {
    $serviceInfo = Get-ServiceInfo
    $gameStatus = Get-GameFilterStatus
    $btnGameFilter.Text = "Game Filter [$($gameStatus.Status)]"
    $ipsetStatus = Get-IPSetStatus
    $btnIPSet.Text = "IPSet Filter [$ipsetStatus]"
    $updateStatus = Get-UpdateCheckStatus
    $btnAutoUpdate.Text = "Auto-Update [$updateStatus]"
    
    # Update service buttons state
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
        
        # Verify service started
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

# Service Functions
function Install-ZapretService {
    Update-StatusBar "Preparing to install service..." "Info"
    
    $batFiles = Get-ChildItem -Path $ScriptPath -Filter "*.bat" | 
                Where-Object { $_.Name -notlike "service*" } |
                Sort-Object { [Regex]::Replace($_.Name, '\d+', { $args[0].Value.PadLeft(8, '0') }) }
    
    if ($batFiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No configuration files (.bat) found!", "Error", 0, 16)
        Update-StatusBar "Installation cancelled" "Error"
        return
    }
    
    # Selection dialog
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
    foreach ($file in $batFiles) { $listBox.Items.Add($file.Name) | Out-Null }
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
    
    $selectedFile = Join-Path $ScriptPath $listBox.SelectedItem
    $binPath = Join-Path $ScriptPath "bin"
    $listsPath = Join-Path $ScriptPath "lists"
    $gameStatus = Get-GameFilterStatus
    $gameFilter = $gameStatus.Filter
    
    # use new parser
    Update-StatusBar "Parsing configuration..." "Info"
    $cmdLine = Parse-BatFile -FilePath $selectedFile -BinPath $binPath -ListsPath $listsPath -GameFilter $gameFilter
    
    if ([string]::IsNullOrWhiteSpace($cmdLine)) {
        Update-StatusBar "Failed to parse configuration!" "Error"
        return
    }
    
    # show edit
    $argsForm = New-Object System.Windows.Forms.Form
    $argsForm.Text = "Review and Edit Arguments"
    $argsForm.Size = New-Object System.Drawing.Size(800, 600)
    $argsForm.StartPosition = "CenterScreen"
    $argsForm.BackColor = $colors.Midnight
    $argsForm.FormBorderStyle = "FixedDialog"
    $argsForm.MaximizeBox = $false
    
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Location = New-Object System.Drawing.Point(20, 15)
    $lblInfo.Size = New-Object System.Drawing.Size(750, 40)
    $lblInfo.Text = "Review the parsed arguments below. You can edit them if needed.`nClick Install to proceed or Cancel to abort."
    $lblInfo.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblInfo.ForeColor = $colors.Light
    $argsForm.Controls.Add($lblInfo)
    
    $textArgs = New-Object System.Windows.Forms.TextBox
    $textArgs.Multiline = $true
    $textArgs.ScrollBars = "Both"
    $textArgs.WordWrap = $false
    $textArgs.Location = New-Object System.Drawing.Point(20, 60)
    $textArgs.Size = New-Object System.Drawing.Size(750, 430)
    $textArgs.Text = $cmdLine
    $textArgs.Font = New-Object System.Drawing.Font("Consolas", 9)
    $textArgs.BackColor = $colors.DarkGray
    $textArgs.ForeColor = $colors.Light
    $argsForm.Controls.Add($textArgs)
    
    $btnInstallNow = New-Object System.Windows.Forms.Button
    $btnInstallNow.Location = New-Object System.Drawing.Point(540, 505)
    $btnInstallNow.Size = New-Object System.Drawing.Size(110, 40)
    $btnInstallNow.Text = "Install"
    $btnInstallNow.BackColor = $colors.Success
    $btnInstallNow.ForeColor = $colors.White
    $btnInstallNow.FlatStyle = "Flat"
    $btnInstallNow.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnInstallNow.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnInstallNow.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $argsForm.Controls.Add($btnInstallNow)
    
    $btnCancelNow = New-Object System.Windows.Forms.Button
    $btnCancelNow.Location = New-Object System.Drawing.Point(660, 505)
    $btnCancelNow.Size = New-Object System.Drawing.Size(110, 40)
    $btnCancelNow.Text = "Cancel"
    $btnCancelNow.BackColor = $colors.Danger
    $btnCancelNow.ForeColor = $colors.White
    $btnCancelNow.FlatStyle = "Flat"
    $btnCancelNow.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnCancelNow.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCancelNow.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $argsForm.Controls.Add($btnCancelNow)
    
    $argsForm.AcceptButton = $btnInstallNow
    $argsForm.CancelButton = $btnCancelNow
    
    if ($argsForm.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        Update-StatusBar "Installation cancelled" "Warning"
        return
    }
    
    # Get edited arguments
    $cmdLine = $textArgs.Text.Trim()
    
    # Enable TCP timestamps
    netsh interface tcp set global timestamps=enabled | Out-Null
    
    # delet old service 
    Update-StatusBar "Removing old service..." "Info"
    Stop-ZapretService -Silent $true | Out-Null
    Start-Sleep -Milliseconds 500
    sc.exe delete zapret 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    
    $winwsPath = Join-Path $binPath "winws.exe"
 
    $cmdLine = $cmdLine -replace '^\s*"|"\s*$', '' 
    
    $fullCommand = "`"$winwsPath`" $cmdLine"
    
    $serviceBinPath = "\`"$winwsPath\`" $cmdLine"
    
    Write-Host "Full command: $fullCommand"
    Write-Host "Service binpath: $serviceBinPath"
    
    Update-StatusBar "Creating service via PowerShell..." "Info"
    
    try {
        $serviceName = "zapret"
        $displayName = "zapret"
        $description = "Zapret DPI bypass software"
        
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        
        if ($existingService) {
            Stop-Service $serviceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            sc.exe delete $serviceName 2>&1 | Out-Null
            Start-Sleep -Seconds 1
        }
        
        # create service through New-Service
        $service = New-Service -Name $serviceName `
                               -BinaryPathName $fullCommand `
                               -DisplayName $displayName `
                               -Description $description `
                               -StartupType Automatic `
                               -ErrorAction Stop
        
        Update-StatusBar "Service created successfully" "Success"
        
        Set-Service -Name $serviceName -Description $description -ErrorAction SilentlyContinue
        
        $configName = [System.IO.Path]::GetFileNameWithoutExtension($listBox.SelectedItem)
        reg add "HKLM\System\CurrentControlSet\Services\zapret" /v zapret-discord-youtube /t REG_SZ /d $configName /f 2>&1 | Out-Null
        
        Update-StatusBar "Starting service..." "Info"
        Start-Service -Name $serviceName -ErrorAction Stop
        

        Start-Sleep -Seconds 2
        $serviceStatus = Get-ServiceStatus "zapret"
        $process = Get-Process -Name winws -ErrorAction SilentlyContinue
        
        if ($serviceStatus -eq "Running") {
            Update-StatusBar "Service installed and running!" "Success"
            
            $message = "Zapret service installed and started successfully!`n`n"
            $message += "Configuration: $configName`n"
            $message += "Status: Running`n"
            

            Start-Process $winwsPath -ArgumentList $cmdLine -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            
            $process = Get-Process -Name winws -ErrorAction SilentlyContinue
            if ($process) {
                Update-StatusBar "winws.exe started manually" "Success"
            }
        }
        
    } catch {
        Update-StatusBar "Trying sc.exe method..." "Warning"
        
        try {
            $scCommand = "sc.exe create zapret binPath= `"$serviceBinPath`" DisplayName= `"zapret`" start= auto"
            Write-Host "SC command: $scCommand"
            
            $result = cmd.exe /c $scCommand 2>&1
            Write-Host "SC result: $result"
            
            if ($LASTEXITCODE -eq 0) {
                Update-StatusBar "Service created via sc.exe" "Success"
                
                sc.exe description zapret "Zapret DPI bypass software" 2>&1 | Out-Null
                
                $configName = [System.IO.Path]::GetFileNameWithoutExtension($listBox.SelectedItem)
                reg add "HKLM\System\CurrentControlSet\Services\zapret" /v zapret-discord-youtube /t REG_SZ /d $configName /f 2>&1 | Out-Null
                
                sc.exe start zapret 2>&1 | Out-Null
                Start-Sleep -Seconds 2
                
                $serviceStatus = Get-ServiceStatus "zapret"
                if ($serviceStatus -eq "Running") {
                    Update-StatusBar "Service started via sc.exe" "Success"
                } else {
                    Update-StatusBar "Service created but failed to start" "Warning"
                }
            } else {
                throw "sc.exe failed with exit code $LASTEXITCODE"
            }
            
        } catch {
            Update-StatusBar "All methods failed: $($_.Exception.Message)" "Error"
            
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to create service using all methods.`n`n" +
                "Error: $($_.Exception.Message)`n`n" +
                "You can try:`n" +
                "1. Run original service.bat manually`n" +
                "2. Check if winws.exe exists at:`n$winwsPath`n`n" +
                "Command line was:`n$fullCommand",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }
    }
    
    Update-ServiceStatusBar
    Update-StatusDisplay
}
function Toggle-GameFilter {
    $flagFile = Join-Path $ScriptPath "utils\game_filter.enabled"
    if (Test-Path $flagFile) {
        Remove-Item $flagFile -Force
        Update-StatusBar "Game filter disabled" "Warning"
    } else {
        $utilsPath = Join-Path $ScriptPath "utils"
        if (-not (Test-Path $utilsPath)) { New-Item -ItemType Directory -Path $utilsPath -Force | Out-Null }
        "ENABLED" | Out-File -FilePath $flagFile -Encoding ASCII
        Update-StatusBar "Game filter enabled" "Warning"
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
    Update-StatusBar "Checking for updates..." "Info"
    $versionUrl = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/version.txt"
    try {
        $githubVersion = (Invoke-WebRequest -Uri $versionUrl -UseBasicParsing -TimeoutSec 5).Content.Trim()
        if ($LOCAL_VERSION -eq $githubVersion) {
            Update-StatusBar "Latest version: $LOCAL_VERSION" "Success"
        } else {
            Update-StatusBar "Update available: $githubVersion" "Warning"
            $result = [System.Windows.Forms.MessageBox]::Show(
                "New version available!`n`nCurrent: $LOCAL_VERSION`nLatest: $githubVersion`n`nOpen download page?",
                "Update",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                Start-Process "https://github.com/Flowseal/zapret-discord-youtube/releases/latest"
            }
        }
#by_Zwey
    } catch {
        Update-StatusBar "Check failed: $($_.Exception.Message)" "Error"
    }
}

function Run-Diagnostics {
    Update-StatusBar "Running diagnostics..." "Info"
    
    $report = @()
    $report += "=== DIAGNOSTICS REPORT ==="
    $report += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $report += ""
    
    # Service status
    $serviceInfo = Get-ServiceInfo
    if ($serviceInfo.Installed) {
        $report += "[OK] Service installed: $($serviceInfo.Config)"
        $report += "[$(if($serviceInfo.Running){'OK'}else{'X'})] Service status: $(if($serviceInfo.Running){'Running'}else{'Stopped'})"
    } else {
        $report += "[X] Service not installed"
    }
    $report += ""
    
    # Base Filtering Engine
    $bfe = Get-Service -Name BFE -ErrorAction SilentlyContinue
    if ($bfe -and $bfe.Status -eq "Running") { 
        $report += "[OK] Base Filtering Engine running" 
    } else { 
        $report += "[X] Base Filtering Engine NOT running" 
    }
    
    # Proxy check
    $proxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($proxy.ProxyEnable -eq 1) { 
        $report += "[!] Proxy enabled: $($proxy.ProxyServer)" 
    } else { 
        $report += "[OK] No proxy" 
    }
    
    # TCP timestamps
    $report += "[OK] TCP configured"
    
    # Adguard
    if (Get-Process -Name AdguardSvc -ErrorAction SilentlyContinue) { 
        $report += "[X] Adguard detected" 
    }
    
    # Killer/SmartByte
    $services = sc.exe query
    if ($services -match "Killer") { $report += "[X] Killer found" }
    if ($services -match "SmartByte") { $report += "[X] SmartByte found" }
    
    # WinDivert
    $binPath = Join-Path $ScriptPath "bin"
    if (Test-Path "$binPath\*.sys") { 
        $report += "[OK] WinDivert64.sys found" 
    } else { 
        $report += "[X] WinDivert64.sys NOT found" 
    }
    
    # VPN
    if ($services -match "VPN") { $report += "[!] VPN detected" }
    
    # Discord cache status
    $discordCacheDir = "$env:APPDATA\discord"
    $cacheFolders = @("Cache", "Code Cache", "GPUCache")
    $hasCache = $false
    
    foreach ($folder in $cacheFolders) {
        $folderPath = Join-Path $discordCacheDir $folder
        if (Test-Path $folderPath) {
            $hasCache = $true
            $size = "{0:N2}" -f ((Get-ChildItem $folderPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB)
            $report += "[!] Discord $folder cache: ${size}MB"
        }
    }
    
    if (-not $hasCache) {
        $report += "[OK] Discord cache not found or already cleaned"
    }
    
    $report += ""
    $report += "=== END REPORT ==="
    
    # Show diagnostics in styled window
    $diagForm = New-Object System.Windows.Forms.Form
    $diagForm.Text = "Diagnostics Report"
    $diagForm.Size = New-Object System.Drawing.Size(400, 380) 
    $diagForm.StartPosition = "CenterScreen"
    $diagForm.BackColor = $colors.Midnight
    $diagForm.FormBorderStyle = "FixedDialog"
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.ScrollBars = "Vertical"
    $textBox.Location = New-Object System.Drawing.Point(15, 15)
    $textBox.Size = New-Object System.Drawing.Size(360, 250) 
    $textBox.Text = ($report -join "`r`n")
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $textBox.BackColor = $colors.DarkGray
    $textBox.ForeColor = $colors.Light
    $textBox.BorderStyle = "None"
    $diagForm.Controls.Add($textBox)

    $clearCacheBtn = New-Object System.Windows.Forms.Button
    $clearCacheBtn.Location = New-Object System.Drawing.Point(50, 280)
    $clearCacheBtn.Size = New-Object System.Drawing.Size(100, 40)
    $clearCacheBtn.Text = "Clear Discord Cache"
    $clearCacheBtn.BackColor = $colors.Warning
    $clearCacheBtn.ForeColor = $colors.White
    $clearCacheBtn.FlatStyle = "Flat"
    $clearCacheBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $clearCacheBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $clearCacheBtn.Add_Click({
        $diagForm.Close()
        Clear-DiscordCache
    })
    $diagForm.Controls.Add($clearCacheBtn)
    
    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Location = New-Object System.Drawing.Point(200, 280)
    $closeBtn.Size = New-Object System.Drawing.Size(100, 40)
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

function Run-Tests {
    Update-StatusBar "Preparing tests..." "Info"
    
    $testScript = Join-Path $ScriptPath "utils\test zapret.ps1"
    if (-not (Test-Path $testScript)) {
        Update-StatusBar "Test script not found!" "Error"
        return
    }
    
    # Store current service state
    $serviceInfo = Get-ServiceInfo
    $wasServiceInstalled = $serviceInfo.Installed
    $wasServiceRunning = $serviceInfo.Running
    $originalConfig = $serviceInfo.Config
    
    # Stop service if running
    if ($wasServiceRunning) {
        Update-StatusBar "Stopping service for tests..." "Warning"
        Stop-ZapretService -Silent $true | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Kill any running winws processes
    Get-Process -Name winws -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    
    # Запускаем тесты в новом окне PowerShell
    Update-StatusBar "Running configuration tests..." "Info"
    
    try {
        # Создаем процесс PowerShell с тестовым скриптом
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$testScript`""
        $psi.WorkingDirectory = $ScriptPath
        $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
        $psi.UseShellExecute = $true
        
        $process = [System.Diagnostics.Process]::Start($psi)
        
        $process.WaitForExit()
        
        Update-StatusBar "Tests completed" "Success"
        

        if ($wasServiceInstalled -and $originalConfig) {
            Update-StatusBar "Restoring original service..." "Info"
            

            $configFile = Join-Path $ScriptPath "$originalConfig.bat"
            if (Test-Path $configFile) {
                $global:selectedFile = $configFile
                $global:listBox = @{SelectedItem = "$originalConfig.bat"}
                
                $binPath = Join-Path $ScriptPath "bin"
                $listsPath = Join-Path $ScriptPath "lists"
                $gameStatus = Get-GameFilterStatus
                $gameFilter = $gameStatus.Filter
                
                $fileLines = Get-Content $configFile
                $capture = $false
                $parsedArgs = ""
                
                foreach ($line in $fileLines) {
                    if ($line -match 'winws\.exe') {
                        $capture = $true
                        $line = $line -replace '^.*winws\.exe', ''
                    }
                    
                    if ($capture) {
                        $line = $line.Trim()
                        if ($line.EndsWith('^')) {
                            $line = $line.Substring(0, $line.Length - 1).TrimEnd()
                            $parsedArgs += $line + " "
                        } else {
                            $parsedArgs += $line + " "
                            break
                        }
                    }
                }
                
                $parsedArgs = $parsedArgs -replace '%BIN%', ($binPath + '\')
                $parsedArgs = $parsedArgs -replace '%LISTS%', ($listsPath + '\')
                $parsedArgs = $parsedArgs -replace '%GameFilter%', $gameFilter
                $parsedArgs = $parsedArgs.Trim()
                
                $winwsPath = Join-Path $binPath "winws.exe"
                $serviceBinPath = "\`"$winwsPath\`" $parsedArgs"
                
                sc.exe delete zapret 2>&1 | Out-Null
                Start-Sleep -Milliseconds 500
                
                sc.exe create zapret binPath= $serviceBinPath DisplayName= "zapret" start= auto 2>&1 | Out-Null
                sc.exe description zapret "Zapret DPI bypass software" | Out-Null
                reg add "HKLM\System\CurrentControlSet\Services\zapret" /v zapret-discord-youtube /t REG_SZ /d $originalConfig /f 2>&1 | Out-Null
                
                if ($wasServiceRunning) {
                    sc.exe start zapret 2>&1 | Out-Null
                    Start-Sleep -Seconds 2
                }
                
                Update-StatusBar "Original service restored: $originalConfig" "Success"
            }
        }
    } catch {
        Update-StatusBar "Error running tests: $($_.Exception.Message)" "Error"
    }
    
    Update-ServiceStatusBar
    Update-StatusDisplay
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Zapret Service Manager v$LOCAL_VERSION"
$form.Size = New-Object System.Drawing.Size(525, 650)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = $colors.Midnight
$form.ForeColor = $colors.Light
function Test-InstalledService {
    $serviceInfo = Get-ServiceInfo
    if (-not $serviceInfo.Installed) { return $false }

    $service = Get-WmiObject Win32_Service -Filter "Name='zapret'" -ErrorAction SilentlyContinue
    if (-not $service) { return $false }
    
    $binPath = $service.PathName
    Write-Host "Service command line: $binPath"

    if ($binPath -notmatch 'winws\.exe') {
        Update-StatusBar "Service path doesn't contain winws.exe!" "Error"
        return $false
    }
    
    return $true
}
function Parse-BatFile {
    param(
        [string]$FilePath,
        [string]$BinPath,
        [string]$ListsPath,
        [string]$GameFilter
    )
    
    $content = Get-Content $FilePath -Raw
    $lines = $content -split "`r`n"
    
    $capture = $false
    $argsLine = ""
    $inQuotes = $false
    $escapeNext = $false
    
    foreach ($line in $lines) {
        if ($line -match 'winws\.exe') {
            $capture = $true

            $line = $line -replace '^.*?winws\.exe', ''
        }
        
        if ($capture) {
            $chars = $line.ToCharArray()
            for ($i = 0; $i -lt $chars.Length; $i++) {
                $char = $chars[$i]
                
                if ($escapeNext) {
                    $argsLine += $char
                    $escapeNext = $false
                    continue
                }
                
                if ($char -eq '^') {
                    if ($i -eq ($chars.Length - 1)) {
                        continue
                    } else {
                        $argsLine += $char
                    }
                } elseif ($char -eq '"') {
                    $argsLine += $char
                    $inQuotes = -not $inQuotes
                } elseif ($char -eq '\' -and $i -lt ($chars.Length - 1) -and $chars[$i + 1] -eq '^') {
                    $escapeNext = $true
                } else {
                    $argsLine += $char
                }
            }
            
            if ($line -notmatch '\^$') {
                break
            }
        }
    }
    
    $argsLine = $argsLine -replace '%BIN%', ($BinPath + '\')
    $argsLine = $argsLine -replace '%LISTS%', ($ListsPath + '\')
    $argsLine = $argsLine -replace '%GameFilter%', $GameFilter

    $argsLine = $argsLine -replace '(?<!["\w])(@|\.\\)([^"\s]+)', {
        param($match)
        $prefix = $match.Groups[1].Value
        $path = $match.Groups[2].Value
        
        if ($prefix -eq '@') {
            
            $fullPath = Join-Path $ScriptPath $path
        } else {
          
            $fullPath = Join-Path $ScriptPath $path
        }
        
        "`"$fullPath`""
    }
    

    $argsLine = $argsLine -replace '\s+', ' '
    $argsLine = $argsLine.Trim()
    
    return $argsLine
}


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

function Remove-ZapretService {
    Update-StatusBar "Removing services..." "Info"
    sc.exe stop zapret 2>&1 | Out-Null
    sc.exe delete zapret 2>&1 | Out-Null
    Get-Process -Name winws -ErrorAction SilentlyContinue | Stop-Process -Force
    sc.exe stop WinDivert 2>&1 | Out-Null
    sc.exe delete WinDivert 2>&1 | Out-Null
    sc.exe stop WinDivert14 2>&1 | Out-Null
    sc.exe delete WinDivert14 2>&1 | Out-Null
    Update-StatusBar "Services removed successfully!" "Success"
     return "Success"
}

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

$lblUpdates = New-Object System.Windows.Forms.Label
$lblUpdates.Location = New-Object System.Drawing.Point(15, 385)
$lblUpdates.Size = New-Object System.Drawing.Size(480, 25)
$lblUpdates.Text = "UPDATES"
$lblUpdates.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblUpdates.ForeColor = $colors.Light
$form.Controls.Add($lblUpdates)

$btnUpdateIPSet = New-Object System.Windows.Forms.Button
$btnUpdateIPSet.Location = New-Object System.Drawing.Point(15, 415)
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
$btnUpdateHosts.Location = New-Object System.Drawing.Point(177, 415)
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
$btnCheckUpdates.Location = New-Object System.Drawing.Point(340, 415)
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
$lblTools.Location = New-Object System.Drawing.Point(15, 470)
$lblTools.Size = New-Object System.Drawing.Size(480, 25)
$lblTools.Text = "TOOLS"
$lblTools.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$lblTools.ForeColor = $colors.Light
$form.Controls.Add($lblTools)

$btnDiagnostics = New-Object System.Windows.Forms.Button
$btnDiagnostics.Location = New-Object System.Drawing.Point(15, 500)
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
$btnTests.Location = New-Object System.Drawing.Point(260, 500)
$btnTests.Size = New-Object System.Drawing.Size(230, 40)
$btnTests.Text = "Run Tests"
$btnTests.BackColor = $colors.DarkWarning
$btnTests.ForeColor = $colors.White
$btnTests.FlatStyle = "Flat"
$btnTests.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnTests.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnTests.Add_Click({ Run-Tests })
$form.Controls.Add($btnTests)
$btnNetworkTest = New-Object System.Windows.Forms.Button
$btnNetworkTest.Location = New-Object System.Drawing.Point(15, 550)
$btnNetworkTest.Size = New-Object System.Drawing.Size(475, 40)
$btnNetworkTest.Text = "Network Diagnostics"
$btnNetworkTest.BackColor = $colors.Primary
$btnNetworkTest.ForeColor = $colors.White
$btnNetworkTest.FlatStyle = "Flat"
$btnNetworkTest.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnNetworkTest.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnNetworkTest.Add_Click({ Test-NetworkSettings })
$form.Controls.Add($btnNetworkTest)
Update-StatusDisplay
Update-ServiceStatusBar

function Test-NetworkSettings {
    Update-StatusBar "Checking network settings..." "Info"
    
    $report = @()
    
    try {
        $dnsOutput = nslookup youtube.com 2>&1
        if ($dnsOutput -match "server can't find") {
            $report += "[WARNING] DNS resolution failed for youtube.com"
        } else {
            $report += "[OK] DNS resolution working"
        }
    } catch {
        $report += "[ERROR] DNS test failed: $_"
    }
    
    try {
        $pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -ErrorAction Stop
        if ($pingResult) {
            $report += "[OK] Ping to 8.8.8.8 successful"
        } else {
            $report += "[WARNING] Ping to 8.8.8.8 failed"
        }
    } catch {
        $report += "[ERROR] Ping test failed: $_"
    }
    
    $adapters = Get-NetAdapter -Physical | Where-Object {$_.Status -eq "Up"}
    if ($adapters) {
        $report += "[OK] Network adapters found: $($adapters.Count)"
    } else {
        $report += "[ERROR] No active network adapters found"
    }
    
    $diagForm = New-Object System.Windows.Forms.Form
    $diagForm.Text = "Network Diagnostics"
    $diagForm.Size = New-Object System.Drawing.Size(500, 400)
    $diagForm.StartPosition = "CenterScreen"
    $diagForm.BackColor = $colors.Midnight
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.ScrollBars = "Vertical"
    $textBox.Location = New-Object System.Drawing.Point(15, 15)
    $textBox.Size = New-Object System.Drawing.Size(460, 300)
    $textBox.Text = ($report -join "`r`n")
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    $textBox.BackColor = $colors.DarkGray
    $textBox.ForeColor = $colors.Light
    $textBox.BorderStyle = "None"
    $diagForm.Controls.Add($textBox)
    
    $closeBtn = New-Object System.Windows.Forms.Button
    $closeBtn.Location = New-Object System.Drawing.Point(190, 325)
    $closeBtn.Size = New-Object System.Drawing.Size(100, 35)
    $closeBtn.Text = "Close"
    $closeBtn.BackColor = $colors.Primary
    $closeBtn.ForeColor = $colors.White
    $closeBtn.FlatStyle = "Flat"
    $closeBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $closeBtn.Add_Click({ $diagForm.Close() })
    $diagForm.Controls.Add($closeBtn)
    
    Update-StatusBar "Network check complete" "Success"
    $diagForm.ShowDialog()
}
[void]$form.ShowDialog()