param(
    [ValidateSet("all", "laptop", "worker")]
    [string]$Role = "all",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$script:OllamaExe = ""

function Ensure-Ollama {
    $cmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($cmd) {
        $script:OllamaExe = $cmd.Source
    } else {
        $fallback = Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe"
        if (Test-Path $fallback) {
            $script:OllamaExe = $fallback
        } else {
            throw "Ollama is not installed or not on PATH."
        }
    }
    try {
        & $script:OllamaExe list | Out-Null
    } catch {
        Write-Host "Starting Ollama service..."
        Start-Process -FilePath $script:OllamaExe -ArgumentList "serve" -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 3
        & $script:OllamaExe list | Out-Null
    }
}

function Get-InstalledModels {
    $lines = & $script:OllamaExe list 2>$null
    $installed = @{}
    foreach ($line in $lines) {
        if ($line -match "^(?<name>\S+)\s+[a-f0-9]{7,}\s+") {
            $fullName = $Matches["name"]
            $installed[$fullName] = $true
            if ($fullName -like "*:*") {
                $baseName = $fullName.Split(":")[0]
                $installed[$baseName] = $true
            }
        }
    }
    return $installed
}

function Pull-Model([string]$ModelName) {
    Write-Host "Pulling model: $ModelName"
    & $script:OllamaExe pull $ModelName
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull model: $ModelName"
    }
}

Ensure-Ollama
$installed = Get-InstalledModels

$models = switch ($Role) {
    "laptop" { @("mistral:7b", "qwen2.5:32b") }
    "worker" { @("phi3.5") }
    default { @("phi3.5", "mistral:7b", "qwen2.5:32b") }
}

foreach ($model in $models) {
    if (-not $Force -and $installed.ContainsKey($model)) {
        Write-Host "Model already present, skipping: $model"
        continue
    }
    Pull-Model -ModelName $model
}

Write-Host "Model install complete for role: $Role"
