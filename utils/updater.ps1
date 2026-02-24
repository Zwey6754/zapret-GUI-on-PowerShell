param(
    [string]$ScriptPath,
    [string]$ZipUrl,
    [string]$GuiPath
)

# -------------------------------------------------------
#  Zapret GUI - Auto Updater
#  Launched by zapret-gui.ps1 when user confirms update.
#  Runs as a separate elevated process.
# -------------------------------------------------------

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Msg, [string]$Color = "Cyan")
    Write-Host $Msg -ForegroundColor $Color
}

# Validate args
if (-not $ScriptPath -or -not $ZipUrl -or -not $GuiPath) {
    Write-Host "[ERROR] Missing required parameters." -ForegroundColor Red
    Write-Host "Usage: updater.ps1 -ScriptPath <path> -ZipUrl <url> -GuiPath <path>" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

$tempDir  = Join-Path $env:TEMP "zapret_update_$(Get-Random)"
$zipFile  = Join-Path $env:TEMP "zapret_update.zip"

try {
    Write-Step "=== Zapret GUI Updater ===" "White"
    Write-Step ""
    Write-Step "[1/5] Downloading update..."

    # GitHub redirects zipball, so follow redirects
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "zapret-gui-updater")
    $webClient.DownloadFile($ZipUrl, $zipFile)
    Write-Step "      Downloaded: $zipFile" "DarkGray"

    Write-Step "[2/5] Extracting..."
    if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $tempDir)

$topLevelItems = Get-ChildItem $tempDir
$topLevelDirs  = $topLevelItems | Where-Object { $_.PSIsContainer }
$topLevelFiles = $topLevelItems | Where-Object { -not $_.PSIsContainer }

if ($topLevelFiles.Count -eq 0 -and $topLevelDirs.Count -eq 1) {
    $sourceDir = $topLevelDirs[0].FullName
} else {
    $sourceDir = $tempDir
}
    Write-Step "      Extracted to: $sourceDir" "DarkGray"

    Write-Step "[3/5] Backing up user lists..."
    # Save user list files so they survive the update
    $userListFiles = @(
        "lists\list-general-user.txt",
        "lists\list-exclude-user.txt",
        "lists\ipset-exclude-user.txt"
    )
    $backups = @{}
    foreach ($rel in $userListFiles) {
        $full = Join-Path $ScriptPath $rel
        if (Test-Path $full) {
            $backups[$rel] = Get-Content $full -Raw -Encoding UTF8
            Write-Step "      Backed up: $rel" "DarkGray"
        }
    }

    Write-Step "[4/5] Copying new files..."
    # Copy all files from extracted folder over current installation
    # Exclude user-specific files and utils folder entirely
    $excludeDirs  = @("utils")
    $excludeFiles = @("list-general-user.txt", "list-exclude-user.txt", "ipset-exclude-user.txt")

    $allItems = Get-ChildItem $sourceDir -Recurse
    foreach ($item in $allItems) {
        $relPath = $item.FullName.Substring($sourceDir.Length).TrimStart('\', '/')

        # Skip excluded dirs
        $skip = $false
        foreach ($excDir in $excludeDirs) {
            if ($relPath -like "$excDir*") { $skip = $true; break }
        }
        # Skip excluded files
        foreach ($excFile in $excludeFiles) {
            if ($item.Name -eq $excFile) { $skip = $true; break }
        }
        if ($skip) { continue }

        $dest = Join-Path $ScriptPath $relPath

        if ($item.PSIsContainer) {
            if (-not (Test-Path $dest)) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
            }
        } else {
            $destDir = Split-Path $dest -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            Copy-Item $item.FullName $dest -Force
        }
    }
    Write-Step "      Files copied." "DarkGray"

    # Restore user lists
    if ($backups.Count -gt 0) {
        Write-Step "      Restoring user lists..." "DarkGray"
        foreach ($rel in $backups.Keys) {
            $full = Join-Path $ScriptPath $rel
            $backups[$rel] | Out-File -FilePath $full -Encoding UTF8 -NoNewline
        }
    }

    Write-Step "[5/5] Cleanup..."
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Step ""
    Write-Step "[OK] Update complete! Restarting GUI..." "Green"
    Start-Sleep -Seconds 1

    # Relaunch GUI
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$GuiPath`"" -Verb RunAs

} catch {
    Write-Step ""
    Write-Step "[ERROR] Update failed: $($_.Exception.Message)" "Red"
    Write-Step "Your files have NOT been modified (error occurred during copy phase)." "Yellow"

    # Cleanup temp files
    Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}
