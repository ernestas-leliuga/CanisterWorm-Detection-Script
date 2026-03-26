param(
    [string]$TargetDir = "."
)

$IssuesFound = $false

function Flag-Issue {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
    $script:IssuesFound = $true
}

Write-Host "=== CanisterWorm Detection Script ==="
Write-Host "Scanning directory: $TargetDir"
Write-Host ""

########################################
# 1. Check suspicious files (IOCs)
########################################
Write-Host "[+] Checking known malicious files..."

$files = @(
    "/tmp/pglog",
    "$HOME/.config/systemd/user/pgmon.service"
)

foreach ($f in $files) {
    if (Test-Path $f) {
        Flag-Issue "Suspicious file found: $f"
    } else {
        Write-Host "[OK] Not found: $f"
    }
}

Write-Host ""

########################################
# 2. Check systemd persistence (Linux/macOS only)
########################################
Write-Host "[+] Checking systemd user services..."

try {
    $services = systemctl --user list-units --type=service 2>$null
    if ($services -match "pgmon") {
        Flag-Issue "Suspicious service 'pgmon' detected"
    } else {
        Write-Host "[OK] No pgmon service found"
    }
} catch {
    Write-Host "[OK] systemctl not available (likely Windows)"
}

Write-Host ""

########################################
# 3. Check npm credentials
########################################
Write-Host "[+] Checking npm credentials..."

$npmrc = "$HOME/.npmrc"

if (Test-Path $npmrc) {
    $content = Get-Content $npmrc -ErrorAction SilentlyContinue
    if ($content -match "_authToken") {
        Flag-Issue "~/.npmrc contains auth token (possible exfil risk)"
    } else {
        Write-Host "[OK] ~/.npmrc has no auth token"
    }
} else {
    Write-Host "[OK] No ~/.npmrc file"
}

if ($env:NPM_TOKEN) {
    Flag-Issue "NPM_TOKEN environment variable is set"
} else {
    Write-Host "[OK] No NPM_TOKEN env variable"
}

Write-Host ""

########################################
# 4. Scan for postinstall scripts
########################################
Write-Host "[+] Scanning for postinstall hooks..."

Get-ChildItem -Path $TargetDir -Recurse -Filter package.json -ErrorAction SilentlyContinue | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match '"postinstall"') {
        Flag-Issue "postinstall script in: $($_.FullName)"
    }
}

Write-Host ""

########################################
# 5. Check suspicious dependencies
########################################
Write-Host "[+] Checking dependencies..."

$pkgPath = Join-Path $TargetDir "package.json"

if (Test-Path $pkgPath) {
    $pkgContent = Get-Content $pkgPath -Raw
    if ($pkgContent -match "emilgroup|opengov|eslint-config-ppf|teale") {
        Flag-Issue "Suspicious dependency pattern in package.json"
    } else {
        Write-Host "[OK] No obvious suspicious dependencies"
    }
} else {
    Write-Host "[OK] No package.json in target directory"
}

Write-Host ""

########################################
# 6. Check running processes
########################################
Write-Host "[+] Checking running processes..."

$procs = Get-Process | Where-Object {
    $_.ProcessName -match "pglog|icp0"
}

if ($procs) {
    Flag-Issue "Suspicious process detected (pglog/icp0)"
} else {
    Write-Host "[OK] No suspicious processes"
}

Write-Host ""

########################################
# 7. Check network connections
########################################
Write-Host "[+] Checking network connections..."

try {
    $connections = netstat -ano | Select-String -Pattern "icp0"
    if ($connections) {
        Flag-Issue "Connection to ICP (icp0) detected"
    } else {
        Write-Host "[OK] No ICP connections"
    }
} catch {
    Write-Host "[OK] Could not check network connections"
}

Write-Host ""

########################################
# 8. npm audit
########################################
Write-Host "[+] Running npm audit..."

if (Test-Path $pkgPath) {
    Push-Location $TargetDir
    try {
        $audit = npm audit --omit=dev 2>$null
        if ($audit -match "critical") {
            Flag-Issue "Critical vulnerabilities reported by npm audit"
        } else {
            Write-Host "[OK] No critical npm audit findings"
        }
    } catch {
        Write-Host "[OK] npm audit failed or npm not installed"
    }
    Pop-Location
} else {
    Write-Host "[OK] Skipping npm audit (no package.json)"
}

Write-Host ""

########################################
# FINAL RESULT + REMEDIATION
########################################
Write-Host "=== RESULT ==="

if ($IssuesFound) {
    Write-Host "[!!!] Potential compromise indicators detected!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Recommended actions:"
    Write-Host "----------------------------------------"
    Write-Host "1. Remove persistence:"
    Write-Host "   systemctl --user disable pgmon.service"
    Write-Host "   Remove-Item ~/.config/systemd/user/pgmon.service -Force"
    Write-Host ""
    Write-Host "2. Remove payload:"
    Write-Host "   Remove-Item /tmp/pglog -Force"
    Write-Host ""
    Write-Host "3. Rotate npm credentials:"
    Write-Host "   npm token revoke <token-id>"
    Write-Host ""
    Write-Host "4. Clean install dependencies safely:"
    Write-Host "   cd $TargetDir"
    Write-Host "   Remove-Item node_modules -Recurse -Force"
    Write-Host "   Remove-Item package-lock.json -Force"
    Write-Host "   npm install --ignore-scripts"
    Write-Host ""
    Write-Host "5. Review package.json for unknown dependencies"
    Write-Host ""
    Write-Host "6. Check npm account for unauthorized publishes:"
    Write-Host "   https://www.npmjs.com/settings/YOUR_USERNAME/profile"
    Write-Host ""
    Write-Host "7. Enable npm 2FA immediately"
    Write-Host "----------------------------------------"
} else {
    Write-Host "[OK] No obvious indicators of CanisterWorm compromise" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Scan Complete ==="