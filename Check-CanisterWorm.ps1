<#
.SYNOPSIS
    CanisterWorm Detection Script (PowerShell Edition)

.DESCRIPTION
    Detects indicators of the CanisterWorm npm supply chain attack, first
    observed on 20 March 2026 and attributed to threat actor "TeamPCP".

    CanisterWorm is a three-stage, self-propagating npm worm that:
      1. Installs via a malicious postinstall hook during 'npm install'
      2. Persists as a user-level systemd service disguised as PostgreSQL tooling
         (Linux/macOS only; Windows systems will not show the service)
      3. Polls an Internet Computer Protocol (ICP) canister acting as a
         censorship-resistant C2 dead-drop to download and execute payloads
      4. Harvests npm tokens from the victim machine and autonomously republishes
         itself to every package the stolen token can reach

    Affected packages include the entire @emilgroup scope (28+ packages),
    @opengov (16+ packages), @teale.io/eslint-config, @airtm/uuid-base32,
    and @pypestream/floating-ui-dom.  As of 21 Mar 2026 the attack had spread
    to 135+ malicious artifacts across 64+ unique packages.

    References:
      https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise
      https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
      https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack

    Note: Heuristic-based detection only. Not a full malware scanner.
          Use alongside proper security tooling.

.PARAMETER TargetDir
    Path to the project directory to scan.  Defaults to the current directory.

.EXAMPLE
    .\Check-CanisterWorm.ps1
    .\Check-CanisterWorm.ps1 -TargetDir "C:\Projects\my-app"
    .\Check-CanisterWorm.ps1 -TargetDir "/home/user/my-app"
#>

param(
    [string]$TargetDir = "."
)

$ErrorActionPreference = 'SilentlyContinue'
$IssuesFound = $false
$IsLinuxPS   = $PSVersionTable.OS -match 'Linux' -or (Test-Path variable:IsLinux -and $IsLinux)
$IsMacOSPS   = $PSVersionTable.OS -match 'Darwin' -or (Test-Path variable:IsMacOS -and $IsMacOS)

# Per-finding flags — used to print targeted remediation at the end
# ($script: prefix used inside ForEach-Object / pipeline scriptblocks to escape child scope)
$FoundBackdoorService  = $false   # pgmon.service file or active systemd service
$FoundPayloadFiles     = $false   # /tmp/pglog or /tmp/.pg_state
$ProcSuspicious        = $false   # running malicious processes
$NetFound              = $false   # C2 network connection
$TokenFound            = $false   # exposed npm token
$FoundPostinstall      = $false   # dangerous postinstall hook
$FoundCompromisedPkgs  = $false   # known-bad hash or compromised package
$FoundTrivy            = $false   # Trivy binary detected (was compromised by TeamPCP)
$FoundNpmAudit         = $false   # critical npm audit finding

# ─── Colour helpers ──────────────────────────────────────────────────────────
function Write-Banner  { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Write-Good    { param([string]$Text) Write-Host "[OK ] $Text" -ForegroundColor Green }
function Write-Warn    { param([string]$Text) Write-Host "[WARN] $Text" -ForegroundColor Yellow }
function Write-Bad     {
    param([string]$Text)
    Write-Host "[!!!] $Text" -ForegroundColor Red
    $script:IssuesFound = $true
}
function Write-Detail  { param([string]$Text) Write-Host "      $Text" -ForegroundColor Gray }

Write-Host "========================================================" -ForegroundColor White
Write-Host "   CanisterWorm Detection Script - PowerShell Edition"    -ForegroundColor White
Write-Host "========================================================" -ForegroundColor White
Write-Host "Scanning : $(( Resolve-Path $TargetDir -ErrorAction SilentlyContinue ).Path ?? $TargetDir)"
Write-Host "Date     : $(Get-Date)"
Write-Host "========================================================" -ForegroundColor White

# =============================================================================
# SECTION 1 — Malicious file artefacts (filesystem IOCs)
# =============================================================================
# CanisterWorm drops the following files on disk (Linux/macOS):
#   /tmp/pglog                          — downloaded second-stage binary payload
#   /tmp/.pg_state                      — tracks the last C2 URL (avoids re-download)
#   ~/.config/systemd/user/pgmon.service — systemd persistence unit (Restart=always)
#   ~/.local/share/pgmon/service.py      — Python C2 polling backdoor (~50 min interval)
# All names deliberately mimic PostgreSQL tooling to avoid suspicion.
# =============================================================================
Write-Banner "[1/9] Checking malicious file artefacts (IOCs)..."

$FsIocs = @(
    [pscustomobject]@{
        Path   = "/tmp/pglog"
        Detail = "Downloaded second-stage binary executed by the Python backdoor."
        Remedy = "Kill the running process, then: Remove-Item /tmp/pglog -Force"
    }
    [pscustomobject]@{
        Path   = "/tmp/.pg_state"
        Detail = "State file tracking the last C2-supplied payload URL."
        Remedy = "Remove-Item /tmp/.pg_state -Force"
    }
    [pscustomobject]@{
        Path   = "$HOME/.config/systemd/user/pgmon.service"
        Detail = "systemd user service with Restart=always — survives reboots without root."
        Remedy = "systemctl --user stop pgmon.service; systemctl --user disable pgmon.service`n      Remove-Item ~/.config/systemd/user/pgmon.service -Force`n      systemctl --user daemon-reload"
    }
    [pscustomobject]@{
        Path   = "$HOME/.local/share/pgmon/service.py"
        Detail = "Python backdoor polling ICP C2 canister every ~50 minutes."
        Remedy = "Remove-Item ~/.local/share/pgmon/service.py -Force"
    }
)

foreach ($ioc in $FsIocs) {
    if (Test-Path $ioc.Path) {
        Write-Bad "Malicious file present: $($ioc.Path)"
        Write-Detail $ioc.Detail
        Write-Detail "Remediation: $($ioc.Remedy)"
        # Tag which category of IOC was found
        if ($ioc.Path -match 'pgmon\.service|service\.py') {
            $script:FoundBackdoorService = $true
        } else {
            $script:FoundPayloadFiles = $true
        }
    } else {
        Write-Good "Not present: $($ioc.Path)"
    }
}

# Known SHA-256 hashes of confirmed malicious CanisterWorm payloads
$KnownHashes = @(
    # index.js waves
    "e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b"  # Wave 1: dry run (empty payload)
    "61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba"  # Wave 2: armed ICP backdoor, manual deploy
    "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a"  # Wave 3: self-propagating, test payload
    "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926"  # Wave 4: final form (self-prop + armed)
    # deploy.js waves
    "f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152"  # Wave 1: verbose, no --tag latest
    "7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7"  # Wave 2: added --tag latest
    "5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956"  # Wave 3+: minified, silent
)

$NodeModulesPath = Join-Path $TargetDir "node_modules"
if (Test-Path $NodeModulesPath) {
    Get-ChildItem -Path $NodeModulesPath -Recurse -Depth 4 -Include "index.js","deploy.js" -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
                if ($KnownHashes -contains $hash) {
                    Write-Bad "Known malicious file hash detected: $($_.FullName)"
                    Write-Detail "SHA-256: $hash"
                    Write-Detail "Remediation: Remove-Item '$($_.DirectoryName)' -Recurse -Force"
                    Write-Detail "             Then rotate ALL npm tokens immediately."
                    $script:FoundCompromisedPkgs = $true
                }
            } catch {}
        }
}

# =============================================================================
# SECTION 2 — systemd persistence (Linux/macOS only)
# =============================================================================
# The backdoor registers pgmon.service with Restart=always so it starts on
# login and restarts every 5 seconds on crash — no root required.
# =============================================================================
Write-Banner "[2/9] Checking systemd user-service persistence..."

if ($IsLinuxPS -or $IsMacOSPS) {
    try {
        $unitFiles   = & systemctl --user list-unit-files --type=service 2>$null | Out-String
        $activeUnits = & systemctl --user list-units     --type=service 2>$null | Out-String

        if ($activeUnits -imatch "pgmon") {
            Write-Bad "Service 'pgmon' is currently ACTIVE in the user systemd session."
            $script:FoundBackdoorService = $true
            Write-Detail "Restart=always means it survives reboots and restarts automatically."
            Write-Detail "Remediation:"
            Write-Detail "  systemctl --user stop pgmon.service"
            Write-Detail "  systemctl --user disable pgmon.service"
            Write-Detail "  Remove-Item ~/.config/systemd/user/pgmon.service -Force"
            Write-Detail "  systemctl --user daemon-reload"
        } elseif ($unitFiles -imatch "pgmon") {
            Write-Bad "Service 'pgmon' is installed but not currently running."
            $script:FoundBackdoorService = $true
            Write-Detail "Disable and remove it (same steps as above)."
        } else {
            Write-Good "No pgmon systemd service found"
        }
    } catch {
        Write-Good "systemctl not available (skipping systemd check)"
    }
} else {
    Write-Good "Not Linux/macOS — systemd backdoor only activates on Linux (skipping)"
}

# =============================================================================
# SECTION 3 — Running processes
# =============================================================================
# Active infection indicators:
#   - python3 running ~/.local/share/pgmon/service.py  (C2 poller)
#   - /tmp/pglog running as a process                  (second-stage payload)
#   - node running scripts/deploy.js                   (worm spreading tokens)
# =============================================================================
Write-Banner "[3/9] Checking running processes..."

$ProcSuspicious = $false

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $cmdLine = ""
    try {
        # Windows: WMI for command line
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue
        $cmdLine = if ($wmi) { $wmi.CommandLine } else { $_.MainModule.FileName }
    } catch { $cmdLine = $_.Name }

    if ($cmdLine -match "pgmon[/\\]service\.py|/tmp/pglog") {
        Write-Bad "Backdoor process is running: $cmdLine (PID $($_.Id))"
        Write-Detail "Kill: Stop-Process -Id $($_.Id) -Force"
        Write-Detail "Then remove payload and state files listed in Section 1."
        $script:ProcSuspicious = $true
    }
    if ($cmdLine -match "deploy\.js") {
        Write-Bad "Worm (deploy.js) process is running — npm token exfiltration may be occurring!"
        Write-Detail "Process: $cmdLine  (PID $($_.Id))"
        Write-Detail "Immediately:"
        Write-Detail "  1. Stop-Process -Id $($_.Id) -Force"
        Write-Detail "  2. npm token list  then  npm token revoke <id>  for each token"
        Write-Detail "  3. Check your npm account for unauthorised package publishes."
        $script:ProcSuspicious = $true
    }
}

# On Linux, also scan /proc cmdlines for missed processes
if ($IsLinuxPS) {
    try {
        Get-ChildItem /proc -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+$' } |
            ForEach-Object {
                $cl = try { [System.IO.File]::ReadAllText("/proc/$($_.Name)/cmdline") -replace "`0"," " } catch { "" }
                if ($cl -match "pgmon/service\.py|/tmp/pglog|deploy\.js") {
                    Write-Bad "Suspicious CanisterWorm process found in /proc: $cl"
                    $script:ProcSuspicious = $true
                }
            }
    } catch {}
}

if (-not $ProcSuspicious) { Write-Good "No suspicious CanisterWorm processes detected" }

# =============================================================================
# SECTION 4 — Network connections to C2 infrastructure
# =============================================================================
# The Python backdoor contacts:
#   https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/
# every ~50 minutes via a spoofed Mozilla/5.0 User-Agent.
# The ICP canister returns a URL; 'youtube.com' means the implant is dormant.
# Any other URL is downloaded to /tmp/pglog and executed.
# =============================================================================
Write-Banner "[4/9] Checking network connections to C2 infrastructure..."

$C2Domain     = "icp0.io"
$C2CanisterId = "tdtqy-oyaaa-aaaae-af2dq-cai"
$NetFound = $false

try {
    $connections = netstat -ano 2>$null | Out-String
    if ($connections -imatch $C2CanisterId -or $connections -imatch $C2Domain) {
        Write-Bad "Active connection to CanisterWorm C2: $C2Domain"
        Write-Detail "The backdoor is communicating with the attacker's ICP canister right now."
        Write-Detail "Block outbound TCP 443 to *.icp0.io at your firewall immediately."
        $NetFound = $true
    }
} catch {}

# Unix: check /etc/hosts for defensive sinkholing and journalctl for history
if ($IsLinuxPS -or $IsMacOSPS) {
    if (Test-Path "/etc/hosts") {
        if ((Get-Content "/etc/hosts" -Raw) -match $C2Domain) {
            Write-Good "C2 domain ($C2Domain) is in /etc/hosts — possible defensive sinkhole"
        }
    }
    try {
        $journal = & journalctl -q --since "7 days ago" 2>$null | Out-String
        if ($journal -imatch $C2CanisterId) {
            Write-Bad "Recent journalctl entries reference CanisterWorm C2 canister ID"
            Write-Detail "Indicates recent backdoor activity on this host."
            $NetFound = $true
        }
    } catch {}
}

if (-not $NetFound) { Write-Good "No active connections to known CanisterWorm C2 infrastructure" }

# =============================================================================
# SECTION 5 — npm credential exposure
# =============================================================================
# CanisterWorm harvests npm tokens from:
#   1. ~/.npmrc                — user npm config
#   2. ./.npmrc                — project config
#   3. /etc/npmrc              — global config (Linux)
#   4. env NPM_TOKEN, NPM_TOKENS, any *NPM*TOKEN*
#   5. npm config get //registry.npmjs.org/:_authToken
# Stolen tokens are used by deploy.js to republish malware across all packages.
# =============================================================================
Write-Banner "[5/9] Checking npm credential exposure..."

$TokenFound = $false

$NpmrcPaths = @(
    (Join-Path $HOME ".npmrc"),
    (Join-Path (Get-Location).Path ".npmrc"),
    "/etc/npmrc"
)
foreach ($rcPath in $NpmrcPaths) {
    if (Test-Path $rcPath) {
        $content = Get-Content $rcPath -Raw -ErrorAction SilentlyContinue
        if ($content -match "_authToken") {
            Write-Bad "npm auth token found in: $rcPath"
            Write-Detail "CanisterWorm harvests this token to republish malware to all your packages."
            Write-Detail "Remediation:"
            Write-Detail "  1. npm token list                     # find the token IDs"
            Write-Detail "  2. npm token revoke <id>              # revoke every one"
            Write-Detail "  3. Remove the _authToken line from $rcPath"
            Write-Detail "  4. Re-authenticate with a new scoped, 2FA-protected token."
            $TokenFound = $true
        } else {
            Write-Good "$rcPath — no auth token"
        }
    }
}

# Environment variable scan
[System.Environment]::GetEnvironmentVariables().Keys | ForEach-Object {
    if ($_ -eq "NPM_TOKEN" -or $_ -eq "NPM_TOKENS" -or ($_ -match "NPM" -and $_ -match "TOKEN")) {
        Write-Bad "Environment variable with npm token: $_"
        Write-Detail "CanisterWorm reads this variable during postinstall to spread itself."
        Write-Detail "Unset the variable and rotate the token: npm token revoke <id>"
        $script:TokenFound = $true
    }
}

# Direct npm config query
if (Get-Command npm -ErrorAction SilentlyContinue) {
    try {
        $cfgToken = (& npm config get "//registry.npmjs.org/:_authToken" 2>$null).ToString().Trim()
        if ($cfgToken -and $cfgToken -ne "undefined" -and $cfgToken -ne "null" -and $cfgToken -ne "") {
            Write-Bad "npm registry auth token accessible via 'npm config get'"
            $preview = if ($cfgToken.Length -gt 8) { $cfgToken.Substring(0,8) + "..." } else { "..." }
            Write-Detail "Value (truncated): $preview"
            Write-Detail "This is exactly how CanisterWorm steals tokens."
            Write-Detail "Revoke: npm token list  →  npm token revoke <id>"
            $TokenFound = $true
        }
    } catch {}
}

if (-not $TokenFound) { Write-Good "No exposed npm tokens detected" }

# =============================================================================
# SECTION 6 — Dangerous postinstall hooks
# =============================================================================
# CanisterWorm activates through a postinstall hook containing:
#   - base64 decode (hides the embedded Python payload)
#   - systemctl calls (installs persistence)
#   - python3 execution (runs the backdoor)
# Legitimate packages rarely need postinstall; always inspect when present.
# =============================================================================
Write-Banner "[6/9] Scanning for dangerous postinstall hooks..."

# Project files (excluding node_modules)
Get-ChildItem -Path $TargetDir -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch "node_modules" } |
    ForEach-Object {
        $raw = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($raw -match '"postinstall"') {
            if ($raw -imatch 'base64|systemctl|python3|eval|exec\b|curl\b|wget\b') {
                Write-Bad "Dangerous postinstall hook in: $($_.FullName)"
                $script:FoundPostinstall = $true
                try {
                    $cmd = ($raw | ConvertFrom-Json).scripts.postinstall
                    Write-Detail "Command: $cmd"
                } catch {}
                Write-Detail "Pattern matches CanisterWorm's installation method."
                Write-Detail "Remediation: npm install --ignore-scripts  (or remove the dependency)"
            } else {
                Write-Warn "postinstall hook present in: $($_.FullName) — review manually"
            }
        }
    }

# node_modules: flag base64 in postinstall (strong CanisterWorm signal)
if (Test-Path $NodeModulesPath) {
    Get-ChildItem -Path $NodeModulesPath -Recurse -Depth 3 -Filter "package.json" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $raw = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($raw -match '"postinstall"' -and $raw -imatch 'base64') {
                Write-Bad "Dependency with base64 postinstall: $($_.FullName)"
                $script:FoundPostinstall = $true
                Write-Detail "CanisterWorm embeds its Python backdoor as base64 in postinstall."
                Write-Detail "Remediation: Remove-Item node_modules -Recurse -Force; npm install --ignore-scripts"
            }
        }
}

Write-Good "postinstall hook scan complete"

# =============================================================================
# SECTION 7 — Known compromised package dependencies
# =============================================================================
# Packages confirmed to have distributed CanisterWorm payloads (Mar 2026):
#   @emilgroup/*            — full scope (28 packages)
#   @opengov/*              — 16+ packages
#   @teale.io/eslint-config
#   @airtm/uuid-base32
#   @pypestream/floating-ui-dom
# The presence of deploy.js in node_modules — with worm-specific patterns —
# is an additional high-confidence indicator even if package names changed.
# =============================================================================
Write-Banner "[7/9] Checking for known compromised package dependencies..."

$PkgFound    = $false
$PkgJsonPath = Join-Path $TargetDir "package.json"

if (Test-Path $PkgJsonPath) {
    $pkgContent = Get-Content $PkgJsonPath -Raw -ErrorAction SilentlyContinue

    if ($pkgContent -imatch '@emilgroup/' -or $pkgContent -imatch '@opengov/') {
        Write-Bad "Dependency from a fully compromised npm scope: @emilgroup or @opengov"
        $script:FoundCompromisedPkgs = $true
        Write-Detail "These scopes were entirely replaced with CanisterWorm on 20 Mar 2026."
        Write-Detail "All versions published on/after that date are malicious."
        Write-Detail "Remediation:"
        Write-Detail "  1. Remove the dependency from package.json"
        Write-Detail "  2. Remove-Item node_modules,package-lock.json -Recurse -Force"
        Write-Detail "  3. npm install --ignore-scripts"
        $PkgFound = $true
    }

    @("@teale.io/eslint-config","@airtm/uuid-base32","@pypestream/floating-ui-dom") |
        ForEach-Object {
            if ($pkgContent -imatch [regex]::Escape($_)) {
                Write-Bad "Known compromised package referenced: $_"
                $script:FoundCompromisedPkgs = $true
                Write-Detail "Remove from package.json, delete node_modules, reinstall with --ignore-scripts"
                $script:PkgFound = $true
            }
        }
} else {
    Write-Good "No package.json in target directory (skipping dependency check)"
}

# Scan node_modules for deploy.js worm tool
if (Test-Path $NodeModulesPath) {
    Get-ChildItem -Path $NodeModulesPath -Recurse -Depth 3 -Filter "deploy.js" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -imatch "maintainer|npm publish|NPM_TOKEN|whoami") {
                Write-Bad "Suspected CanisterWorm worm script: $($_.FullName)"
                $script:FoundCompromisedPkgs = $true
                Write-Detail "deploy.js harvests npm tokens and republishes malware to all reachable packages."
                Write-Detail "Legitimate packages do not include this script."
                Write-Detail "Remediation: Remove-Item node_modules -Recurse -Force; npm install --ignore-scripts"
                $script:PkgFound = $true
            }
        }
}

if (-not $PkgFound) { Write-Good "No known compromised package dependencies detected" }

# =============================================================================
# SECTION 8 — CI/CD and environment exposure
# =============================================================================
# CanisterWorm targets CI/CD runners where npm tokens are injected as env vars.
# GitHub Actions is a primary target.  Trivy was compromised by TeamPCP as an
# initial entry point before the npm wave; verify your Trivy binary.
# =============================================================================
Write-Banner "[8/9] Checking CI/CD exposure indicators..."

$CiFound = $false

if ($env:GITHUB_ACTIONS -or $env:GITHUB_TOKEN) {
    Write-Warn "Running inside GitHub Actions — npm tokens in CI are a primary CanisterWorm target."
    Write-Detail "Use short-lived, scoped tokens. Enable 2FA for npm publish."
    $CiFound = $true
}
if ($env:CI -or $env:JENKINS_URL -or $env:CIRCLECI -or $env:TRAVIS -or $env:GITLAB_CI) {
    Write-Warn "CI environment detected — ensure npm publish tokens are revoked after each job."
    $CiFound = $true
}
if (Get-Command trivy -ErrorAction SilentlyContinue) {
    $trivyVer = (& trivy --version 2>$null | Select-Object -First 1)
    Write-Warn "Trivy detected: $trivyVer"
    $FoundTrivy = $true
    Write-Detail "Trivy was compromised by TeamPCP before the CanisterWorm npm campaign."
    Write-Detail "Verify your binary: https://github.com/aquasecurity/trivy/releases"
    $CiFound = $true
}

if (-not $CiFound) { Write-Good "No specific CI/CD exposure signals detected" }

# =============================================================================
# SECTION 9 — npm audit
# =============================================================================
Write-Banner "[9/9] Running npm audit for critical vulnerabilities..."

if (Test-Path $PkgJsonPath) {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        Push-Location $TargetDir
        try {
            $auditOut = & npm audit --omit=dev 2>$null | Out-String
            if ($auditOut -imatch "critical") {
                Write-Bad "Critical vulnerabilities found by npm audit"
                $FoundNpmAudit = $true
                $auditOut -split "`n" | Where-Object { $_ -imatch "critical" } |
                    Select-Object -First 10 | ForEach-Object { Write-Detail $_ }
                Write-Detail "Remediation: npm audit fix  (review for breaking changes first)"
            } else {
                Write-Good "No critical npm audit findings"
            }
        } catch {
            Write-Warn "npm audit failed or npm is not installed"
        }
        Pop-Location
    } else {
        Write-Warn "npm not found — skipping npm audit"
    }
} else {
    Write-Good "No package.json in target directory — skipping npm audit"
}

# =============================================================================
# FINAL RESULT + REMEDIATION SUMMARY
# =============================================================================
Write-Host "`n========================================================" -ForegroundColor White
Write-Host "   SCAN RESULT"                                               -ForegroundColor White
Write-Host "========================================================"     -ForegroundColor White

if ($IssuesFound) {
    Write-Host "`n[!!!] POTENTIAL COMPROMISE INDICATORS DETECTED!" -ForegroundColor Red
    Write-Host "`nTARGETED REMEDIATION — actions for issues found above" -ForegroundColor Yellow
    Write-Host "--------------------------------------------------------"

    # Step 1: only when pgmon.service file or active systemd service found
    if ($FoundBackdoorService) {
        Write-Host "`nSTEP 1 — Stop and remove the persistent backdoor" -ForegroundColor Yellow
        Write-Host "  systemctl --user stop pgmon.service"
        Write-Host "  systemctl --user disable pgmon.service"
        Write-Host "  systemctl --user daemon-reload"
        Write-Host "  Remove-Item ~/.config/systemd/user/pgmon.service -Force"
        Write-Host "  Remove-Item ~/.local/share/pgmon -Recurse -Force -ErrorAction SilentlyContinue"
    }

    # Step 2: only when payload files or running malicious processes found
    if ($FoundPayloadFiles -or $ProcSuspicious) {
        Write-Host "`nSTEP 2 — Kill malicious processes and remove payload files" -ForegroundColor Yellow
        Write-Host "  # Linux/macOS:"
        Write-Host "  pkill -f '/tmp/pglog'           # kill running payload"
        Write-Host "  pkill -f 'pgmon/service.py'     # kill C2 poller"
        Write-Host "  pkill -f 'deploy.js'            # kill worm if still running"
        Write-Host "  Remove-Item /tmp/pglog, /tmp/.pg_state -Force -ErrorAction SilentlyContinue"
    }

    # Steps 3+4: only when tokens are exposed or worm process was running
    if ($TokenFound -or $ProcSuspicious) {
        Write-Host "`nSTEP 3 — Rotate ALL npm credentials immediately" -ForegroundColor Yellow
        Write-Host "  npm token list                         # list all active tokens"
        Write-Host "  npm token revoke <id>                  # revoke every one"
        Write-Host "  # Create a fresh scoped, 2FA-protected token afterwards."

        Write-Host "`nSTEP 4 — Audit your npm packages for unauthorised publishes" -ForegroundColor Yellow
        Write-Host "  npm access list packages <your-username>"
        Write-Host "  # Or visit: https://www.npmjs.com/settings/<username>/packages"
        Write-Host "  # Look for versions published on/after 20 Mar 2026 without your consent."
        Write-Host "  # If found: npm deprecate <pkg>@<version> 'Compromised by CanisterWorm'"
    }

    # Step 5: only when compromised packages, dangerous postinstall, or critical audit vulns found
    if ($FoundCompromisedPkgs -or $FoundPostinstall -or $FoundNpmAudit) {
        Write-Host "`nSTEP 5 — Clean-reinstall project dependencies" -ForegroundColor Yellow
        Write-Host "  Set-Location '$TargetDir'"
        Write-Host "  Remove-Item node_modules -Recurse -Force"
        Write-Host "  Remove-Item package-lock.json -Force -ErrorAction SilentlyContinue"
        Write-Host "  npm install --ignore-scripts"
        Write-Host "  # --ignore-scripts prevents any postinstall hook from running."
        if ($FoundNpmAudit) {
            Write-Host "  npm audit fix                          # then fix audit findings"
        }
    }

    # Step 6: only when active C2 connection or backdoor was running
    if ($NetFound -or $FoundBackdoorService) {
        Write-Host "`nSTEP 6 — Block the C2 infrastructure" -ForegroundColor Yellow
        Write-Host "  # Linux/macOS — sinkhole in /etc/hosts:"
        Write-Host "  '0.0.0.0 tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io' | sudo tee -a /etc/hosts"
        Write-Host "  # Firewall: block outbound TCP 443 to *.icp0.io"
    }

    # Step 7: only when Trivy was detected (it was the initial TeamPCP attack vector)
    if ($FoundTrivy) {
        Write-Host "`nSTEP 7 — Verify your Trivy binary" -ForegroundColor Yellow
        Write-Host "  # Trivy was compromised by TeamPCP before the CanisterWorm npm campaign."
        Write-Host "  # Verify binary checksums: https://github.com/aquasecurity/trivy/releases"
    }

    # General prevention — always shown when any issue was found
    Write-Host "`nGENERAL — Prevent future infection" -ForegroundColor Yellow
    Write-Host "  npm config set ignore-scripts true    # global default"
    Write-Host "  # Enable npm 2FA: https://docs.npmjs.com/configuring-two-factor-authentication"
    Write-Host "  # Use scoped, automation-only tokens with minimal publish permissions."
    Write-Host "  # Add supply-chain monitoring: socket.dev or aikido.dev"

    Write-Host "--------------------------------------------------------`n"
} else {
    Write-Host "`n[OK] No indicators of CanisterWorm compromise detected." -ForegroundColor Green
    Write-Host "`nPrevention best practices:" -ForegroundColor Cyan
    Write-Host "  * Always run: npm install --ignore-scripts"
    Write-Host "  * Enable npm 2FA on your account"
    Write-Host "  * Use scoped, short-lived publish tokens"
    Write-Host "  * Monitor package.json changes in code review"
    Write-Host "  * Use a supply-chain scanner (socket.dev, Aikido, Snyk)"
    Write-Host "  * Verify Trivy binaries against official release checksums"
}

Write-Host "`n========================================================" -ForegroundColor White
Write-Host "   Scan Complete"                                             -ForegroundColor White
Write-Host "========================================================"     -ForegroundColor White