param(
    [int]$Port = 6333,
    [int]$TimeoutSeconds = 30
)

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$BinaryPath = Join-Path $ProjectDir "qdrant_bin\qdrant.exe"
$LogPath    = Join-Path $ProjectDir "qdrant_bin\qdrant.log"
$ErrPath    = Join-Path $ProjectDir "qdrant_bin\qdrant.err"
$HealthUrl  = "http://127.0.0.1:$Port/healthz"

# Guard: binary must exist
if (-not (Test-Path $BinaryPath)) {
    Write-Error "[qdrant] Binary not found at: $BinaryPath"
    Write-Error "[qdrant] Download from: https://github.com/qdrant/qdrant/releases"
    exit 1
}

# Guard: already running?
$alreadyUp = $false
try {
    $r = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    if ($r.StatusCode -eq 200) { $alreadyUp = $true }
} catch {
    $alreadyUp = $false
}

if ($alreadyUp) {
    Write-Host "[qdrant] Already healthy on port $Port -- nothing to do." -ForegroundColor Green
    exit 0
}

# Launch the binary in the background
Write-Host "[qdrant] Starting binary: $BinaryPath" -ForegroundColor Cyan
$proc = Start-Process `
    -FilePath $BinaryPath `
    -WorkingDirectory (Join-Path $ProjectDir "qdrant_bin") `
    -RedirectStandardOutput $LogPath `
    -RedirectStandardError  $ErrPath `
    -PassThru `
    -WindowStyle Hidden

Write-Host "[qdrant] PID $($proc.Id) -- polling $HealthUrl ..."

# Poll /healthz until ready or timeout
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$ready    = $false
$lastResp = $null

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    try {
        $lastResp = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($lastResp.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        # still starting -- keep polling
    }
}

if ($ready) {
    Write-Host "[qdrant] Healthy -- HTTP 200 from $HealthUrl" -ForegroundColor Green
    Write-Host "[qdrant] Status code : $($lastResp.StatusCode)"
    Write-Host "[qdrant] Body        : $($lastResp.Content.Trim())"
    exit 0
} else {
    Write-Error "[qdrant] Did not become healthy within $TimeoutSeconds seconds."
    Write-Error "[qdrant] Check server log : $LogPath"
    Write-Error "[qdrant] Check error log  : $ErrPath"
    exit 1
}
