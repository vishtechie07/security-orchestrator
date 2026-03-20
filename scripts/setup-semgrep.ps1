# Download and extract Semgrep binary for Security Orchestrator (Windows).
# Run from repo root: .\scripts\setup-semgrep.ps1
# Requires: PowerShell 5.1+ (Invoke-RestMethod, Expand-Archive)

$ErrorActionPreference = "Stop"
$OutDir = Join-Path $PSScriptRoot ".." "tools" "semgrep"
$ApiUrl = "https://api.github.com/repos/semgrep/semgrep/releases/latest"

Write-Host "Fetching latest Semgrep release..."
$release = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "Security-Orchestrator" }
$tag = $release.tag_name
$assets = $release.assets

# Prefer win64/win; fallback to any asset with "win" in name
$asset = $assets | Where-Object { $_.name -match "win" } | Select-Object -First 1
if (-not $asset) {
    Write-Error "No Windows asset found for $tag. Check https://github.com/semgrep/semgrep/releases"
}
$zipPath = Join-Path $env:TEMP "semgrep-$tag.zip"
Write-Host "Downloading $($asset.name)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "Extracting to $OutDir..."
Expand-Archive -Path $zipPath -DestinationPath $OutDir -Force
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

# Find semgrep.exe in extracted tree (may be in subdir); flatten to $OutDir
$exe = Get-ChildItem -Path $OutDir -Filter "semgrep.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($exe) {
    $destExe = Join-Path $OutDir "semgrep.exe"
    if ($exe.FullName -ne $destExe) {
        Copy-Item $exe.FullName -Destination $destExe -Force
        Get-ChildItem -Path $OutDir -Exclude "semgrep.exe" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Semgrep installed at: $destExe"
} else {
    Write-Host "Extracted to $OutDir. Ensure semgrep.exe is in that folder; set semgrep.command to its full path if needed."
}
Write-Host "Done. Start the app with: mvn spring-boot:run (semgrep.command will default to tools/semgrep/semgrep.exe when bundled)."
