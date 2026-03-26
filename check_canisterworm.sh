#!/bin/bash
# =============================================================================
# CanisterWorm Detection Script (Bash)
# =============================================================================
# Detects indicators of the CanisterWorm npm supply chain attack, first
# observed on 20 March 2026 and attributed to threat actor "TeamPCP".
#
# Background:
#   CanisterWorm is a three-stage, self-propagating npm worm that:
#     1. Installs via a malicious postinstall hook during 'npm install'
#     2. Persists as a user-level systemd service disguised as PostgreSQL tooling
#     3. Polls an Internet Computer Protocol (ICP) canister acting as a
#        censorship-resistant C2 dead-drop to download and execute payloads
#     4. Harvests npm tokens from the victim machine and autonomously republishes
#        itself to every package the stolen token can reach
#
#   Affected packages include the entire @emilgroup scope (28+ packages),
#   @opengov (16+ packages), @teale.io/eslint-config, @airtm/uuid-base32,
#   and @pypestream/floating-ui-dom.  As of 21 Mar 2026 the attack had spread
#   to 135+ malicious artifacts across 64+ unique packages.
#
# References:
#   https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise
#   https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
#   https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack
#
# Usage:
#   ./check_canisterworm.sh [path/to/project]
#   Defaults to the current directory when no path is supplied.
#
# Note: Heuristic-based detection only. Not a full malware scanner.
#       Use alongside proper security tooling.
# =============================================================================

TARGET_DIR="${1:-.}"
ISSUES_FOUND=0

# Per-finding flags — used to print targeted remediation at the end
FOUND_BACKDOOR_SERVICE=0   # pgmon.service file or active systemd service
FOUND_PAYLOAD_FILES=0      # /tmp/pglog or /tmp/.pg_state
FOUND_COMPROMISED_PKGS=0   # known-bad package hash or compromised dependency
FOUND_POSTINSTALL=0        # dangerous postinstall hook detected
FOUND_TRIVY=0              # Trivy binary detected (was compromised by TeamPCP)
FOUND_NPM_AUDIT=0          # critical npm audit finding
# Note: PROC_SUSPICIOUS, NET_FOUND, TOKEN_FOUND, CI_FOUND are declared per-section
# but remain accessible in the final block (bash has no block scope).

# Colour codes (suppressed when stdout is not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
    RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

banner()  { printf "\n${BOLD}${CYAN}%s${RESET}\n" "$1"; }
ok()      { printf "${GREEN}[OK ]${RESET} %s\n" "$1"; }
warn()    { printf "${YELLOW}[WARN]${RESET} %s\n" "$1"; }
bad()     { printf "${RED}[!!!]${RESET} %s\n" "$1"; ISSUES_FOUND=1; }
info()    { printf "      %s\n" "$1"; }

printf "${BOLD}========================================================${RESET}\n"
printf "${BOLD}   CanisterWorm Detection Script — Bash Edition${RESET}\n"
printf "${BOLD}========================================================${RESET}\n"
printf "Scanning: %s\n" "$(realpath "$TARGET_DIR" 2>/dev/null || echo "$TARGET_DIR")"
printf "Date    : %s\n" "$(date)"
printf "${BOLD}========================================================${RESET}\n"

# =============================================================================
# SECTION 1 — Malicious file artefacts (filesystem IOCs)
# =============================================================================
# CanisterWorm drops the following files on disk:
#   /tmp/pglog          — the downloaded second-stage binary payload
#   /tmp/.pg_state      — tracks the last C2 URL to avoid re-downloading
#   ~/.config/systemd/user/pgmon.service  — systemd persistence unit
#   ~/.local/share/pgmon/service.py       — the Python C2 polling backdoor
# All names deliberately mimic PostgreSQL tooling to avoid suspicion.
# =============================================================================
banner "[1/9] Checking malicious file artefacts (IOCs)..."

FS_IOCS="
/tmp/pglog
/tmp/.pg_state
$HOME/.config/systemd/user/pgmon.service
$HOME/.local/share/pgmon/service.py
"

for f in $FS_IOCS; do
    if [ -f "$f" ]; then
        bad "Malicious file present: $f"
        case "$f" in
            /tmp/pglog)
                FOUND_PAYLOAD_FILES=1
                info "This is the downloaded second-stage binary executed by the backdoor."
                info "Remediation: kill the process if running, then: rm -f /tmp/pglog"
                ;;
            /tmp/.pg_state)
                FOUND_PAYLOAD_FILES=1
                info "State file tracking the last C2-supplied payload URL."
                info "Remediation: rm -f /tmp/.pg_state"
                ;;
            *pgmon.service)
                FOUND_BACKDOOR_SERVICE=1
                info "systemd user-service providing Restart=always persistence."
                info "Remediation:"
                info "  systemctl --user stop pgmon.service"
                info "  systemctl --user disable pgmon.service"
                info "  rm -f ~/.config/systemd/user/pgmon.service"
                info "  systemctl --user daemon-reload"
                ;;
            *service.py)
                FOUND_BACKDOOR_SERVICE=1
                info "Python backdoor that polls the ICP C2 canister every ~50 minutes."
                info "Remediation: rm -f ~/.local/share/pgmon/service.py"
                info "             rmdir ~/.local/share/pgmon  # if empty"
                ;;
        esac
    else
        ok "Not present: $f"
    fi
done

# Known SHA-256 hashes of malicious index.js payloads (all four waves)
if command -v sha256sum >/dev/null 2>&1; then
    KNOWN_HASHES="
e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b
61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba
0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a
c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926
f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152
7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7
5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956
"
    # Scan node_modules index.js and deploy.js files for known hashes
    while IFS= read -r jsfile; do
        h=$(sha256sum "$jsfile" 2>/dev/null | awk '{print $1}')
        if echo "$KNOWN_HASHES" | grep -qF "$h"; then
            bad "Known malicious file hash detected: $jsfile"
            info "SHA-256: $h"
            info "Remediation: rm -rf \"$(dirname \"$jsfile\")\""
            info "             Rotate all npm tokens immediately."
            FOUND_COMPROMISED_PKGS=1
        fi
    done < <(find "$TARGET_DIR/node_modules" -maxdepth 4 \( -name "index.js" -o -name "deploy.js" \) 2>/dev/null)
fi

# =============================================================================
# SECTION 2 — systemd persistence
# =============================================================================
# The backdoor installs pgmon.service with Restart=always so it survives
# reboots and crashes without elevated privileges.
# =============================================================================
banner "[2/9] Checking systemd user-service persistence..."

if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user list-units --type=service 2>/dev/null | grep -iq pgmon; then
        bad "Service 'pgmon' is active in the current user systemd session."
        FOUND_BACKDOOR_SERVICE=1
        info "This service restarts automatically and survives reboots."
        info "Remediation:"
        info "  systemctl --user stop pgmon.service"
        info "  systemctl --user disable pgmon.service"
        info "  rm -f ~/.config/systemd/user/pgmon.service"
        info "  systemctl --user daemon-reload"
    elif systemctl --user list-unit-files 2>/dev/null | grep -iq pgmon; then
        bad "Service 'pgmon' is installed but not currently running."
        FOUND_BACKDOOR_SERVICE=1
        info "Remediation: same as above — disable and remove the unit file."
    else
        ok "No pgmon systemd service found"
    fi
else
    ok "systemctl not available on this system (skipping)"
fi

# =============================================================================
# SECTION 3 — Running processes
# =============================================================================
# An active infection shows:
#   - python3 running ~/.local/share/pgmon/service.py (the C2 poller)
#   - /tmp/pglog (the downloaded second-stage binary) as a running process
# The worm also spawns 'deploy.js' via 'node' to spread itself.
# =============================================================================
banner "[3/9] Checking running processes..."

PROC_SUSPICIOUS=0
if ps aux 2>/dev/null | grep -E "pgmon/service\.py|/tmp/pglog" | grep -v grep; then
    bad "Backdoor process is running (pgmon service.py or /tmp/pglog)"
    PROC_SUSPICIOUS=1
    info "Kill the process and remove the files listed in Section 1."
fi
if ps aux 2>/dev/null | grep "deploy\.js" | grep -v grep; then
    bad "deploy.js worm process is running — npm token exfiltration in progress."
    PROC_SUSPICIOUS=1
    info "This script is actively spreading the malware to other npm packages."
    info "Immediately:"
    info "  1. Kill the process: pkill -f deploy.js"
    info "  2. Revoke ALL npm tokens tied to this machine: npm token list && npm token revoke <id>"
    info "  3. Check your npm account for unauthorised publishes."
fi
[ "$PROC_SUSPICIOUS" -eq 0 ] && ok "No suspicious CanisterWorm processes detected"

# =============================================================================
# SECTION 4 — Network connections to ICP C2 infrastructure
# =============================================================================
# The Python backdoor contacts:
#   https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/
# every ~50 minutes using a spoofed Mozilla/5.0 User-Agent.
# The ICP canister returns a URL; if it contains 'youtube.com' the payload
# is considered dormant.  Any other URL is downloaded to /tmp/pglog.
# =============================================================================
banner "[4/9] Checking network connections to C2 infrastructure..."

C2_DOMAIN="icp0.io"
C2_CANISTER="tdtqy-oyaaa-aaaae-af2dq-cai"
NET_FOUND=0

# Try ss first (more modern), fall back to netstat
if command -v ss >/dev/null 2>&1; then
    if ss -tnp 2>/dev/null | grep -iq "$C2_DOMAIN\|$C2_CANISTER"; then
        bad "Active connection to CanisterWorm C2: $C2_DOMAIN"
        info "The backdoor is currently communicating with the attacker's ICP canister."
        info "Block outbound access to *.icp0.io at your firewall."
        NET_FOUND=1
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -tnp 2>/dev/null | grep -iq "$C2_DOMAIN\|$C2_CANISTER"; then
        bad "Active connection to CanisterWorm C2: $C2_DOMAIN"
        info "The backdoor is currently communicating with the attacker's ICP canister."
        info "Block outbound access to *.icp0.io at your firewall."
        NET_FOUND=1
    fi
fi

# Check /etc/hosts for any override of the C2 domain (could indicate prior
# defensive blocking or attacker tampering)
if grep -q "$C2_DOMAIN" /etc/hosts 2>/dev/null; then
    ok "C2 domain ($C2_DOMAIN) is listed in /etc/hosts — possible defensive sinkhole"
fi

# Check DNS resolution history via nscd cache or journalctl if available
if command -v journalctl >/dev/null 2>&1; then
    if journalctl -q --since "7 days ago" 2>/dev/null | grep -qi "$C2_CANISTER"; then
        bad "Recent DNS/journal activity referencing CanisterWorm C2 canister ID"
        info "This indicates recent backdoor activity on this host."
        NET_FOUND=1
    fi
fi

[ "$NET_FOUND" -eq 0 ] && ok "No active connections to known CanisterWorm C2 infrastructure"

# =============================================================================
# SECTION 5 — npm credential exposure
# =============================================================================
# CanisterWorm harvests npm tokens from three locations:
#   1. ~/.npmrc                — user npm config
#   2. .npmrc in current dir   — project config
#   3. /etc/npmrc              — global config
# It also reads NPM_TOKEN, NPM_TOKENS, and any env var matching *NPM*TOKEN*,
# and queries 'npm config get //registry.npmjs.org/:_authToken' directly.
# Exposed tokens are used by deploy.js to republish malware to victim packages.
# =============================================================================
banner "[5/9] Checking npm credential exposure..."

NPMRC_FILES="$HOME/.npmrc $(pwd)/.npmrc /etc/npmrc"
TOKEN_FOUND=0

for rc in $NPMRC_FILES; do
    if [ -f "$rc" ]; then
        if grep -qi "_authToken" "$rc"; then
            bad "npm auth token found in: $rc"
            info "CanisterWorm harvests this token to republish malware."
            info "Remediation:"
            info "  1. Run: npm token list  — note the token IDs visible."
            info "  2. Run: npm token revoke <id>  for each token linked to this machine."
            info "  3. Remove the token line from $rc"
            info "  4. Re-authenticate using a new, scoped, 2FA-protected token."
            TOKEN_FOUND=1
        else
            ok "$rc — no auth token"
        fi
    fi
done

# Check environment variables
for envvar in $(env | grep -iE 'NPM.*TOKEN|TOKEN.*NPM' | awk -F= '{print $1}'); do
    bad "Env var with npm token: $envvar"
    info "CanisterWorm reads this variable during postinstall."
    info "Remediation: unset $envvar and rotate the token."
    TOKEN_FOUND=1
done

# Check npm config directly
if command -v npm >/dev/null 2>&1; then
    CFG_TOKEN=$(npm config get //registry.npmjs.org/:_authToken 2>/dev/null)
    if [ -n "$CFG_TOKEN" ] && [ "$CFG_TOKEN" != "undefined" ] && [ "$CFG_TOKEN" != "null" ]; then
        bad "npm registry auth token is accessible via 'npm config get'"
        info "Value: ${CFG_TOKEN:0:8}... (truncated)"
        info "This is the same method CanisterWorm uses to harvest tokens."
        info "Revoke this token immediately: npm token revoke <id>"
        TOKEN_FOUND=1
    fi
fi

[ "$TOKEN_FOUND" -eq 0 ] && ok "No exposed npm tokens detected"

# =============================================================================
# SECTION 6 — Suspicious postinstall hooks
# =============================================================================
# CanisterWorm installs through a postinstall hook in package.json.
# Legitimate packages rarely need postinstall; when present, inspect the
# script carefully.  Red flags: base64 decode, systemctl, python3, eval.
# =============================================================================
banner "[6/9] Scanning for dangerous postinstall hooks..."

while IFS= read -r pkgfile; do
    if grep -q '"postinstall"' "$pkgfile"; then
        # Try to extract the actual command and check for red-flag patterns
        POSTINSTALL_CMD=$(python3 -c "
import json,sys
try:
    d=json.load(open('$pkgfile'))
    s=d.get('scripts',{})
    print(s.get('postinstall',''))
except: pass
" 2>/dev/null)
        if echo "$POSTINSTALL_CMD" | grep -qiE "base64|systemctl|python3|eval|exec|curl|wget"; then
            bad "Dangerous postinstall hook in: $pkgfile"
            FOUND_POSTINSTALL=1
            info "Command: $POSTINSTALL_CMD"
            info "This matches CanisterWorm's installation pattern."
            info "Remediation: Remove the dependency or run: npm install --ignore-scripts"
        else
            warn "postinstall hook in: $pkgfile — review manually"
            info "Command: $POSTINSTALL_CMD"
        fi
    fi
done < <(find "$TARGET_DIR" -name package.json -not -path "*/node_modules/*" 2>/dev/null)

# Also scan inside node_modules for postinstall hooks with dangerous patterns
while IFS= read -r pkgfile; do
    if grep -q '"postinstall"' "$pkgfile"; then
        CONTENT=$(cat "$pkgfile" 2>/dev/null)
        if echo "$CONTENT" | grep -qiE '"postinstall".*base64|base64.*postinstall'; then
            bad "Dependency with base64 postinstall: $pkgfile"
            FOUND_POSTINSTALL=1
            info "CanisterWorm embeds its Python backdoor as a base64 string in postinstall."
            info "Remediation: rm -rf node_modules && npm install --ignore-scripts"
        fi
    fi
done < <(find "$TARGET_DIR/node_modules" -maxdepth 3 -name package.json 2>/dev/null)
ok "postinstall hook scan complete"

# =============================================================================
# SECTION 7 — Known compromised package dependencies
# =============================================================================
# Packages confirmed to have distributed CanisterWorm payloads:
#   @emilgroup/*          — Full scope compromised (28+ packages)
#   @opengov/*            — 16+ packages compromised
#   @teale.io/eslint-config
#   @airtm/uuid-base32
#   @pypestream/floating-ui-dom
# The worm also plants deploy.js in packages it infects. Scanning for that
# file provides an additional signal even if package names have changed.
# =============================================================================
banner "[7/9] Checking for known compromised package dependencies..."

PKG_FOUND=0

if [ -f "$TARGET_DIR/package.json" ]; then
    # Check for known compromised scopes and packages
    if grep -E "@emilgroup/|@opengov/" "$TARGET_DIR/package.json" >/dev/null 2>&1; then
        bad "Dependency from compromised npm scope (@emilgroup or @opengov) in package.json"
        FOUND_COMPROMISED_PKGS=1
        info "These scopes were fully compromised by CanisterWorm on 20 Mar 2026."
        info "All versions published on or after that date should be treated as malicious."
        info "Remediation:"
        info "  1. Remove the dependency from package.json"
        info "  2. rm -rf node_modules package-lock.json"
        info "  3. npm install --ignore-scripts"
        PKG_FOUND=1
    fi
    if grep -E "@teale\.io/eslint-config|@airtm/uuid-base32|@pypestream/floating-ui-dom" "$TARGET_DIR/package.json" >/dev/null 2>&1; then
        bad "Known compromised package referenced in package.json"
        FOUND_COMPROMISED_PKGS=1
        info "Compromised packages: @teale.io/eslint-config, @airtm/uuid-base32, @pypestream/floating-ui-dom"
        info "Remediation: remove and reinstall with --ignore-scripts"
        PKG_FOUND=1
    fi
else
    ok "No package.json in target directory (skipping)"
fi

# Check node_modules for deploy.js (the worm propagation tool)
if find "$TARGET_DIR/node_modules" -maxdepth 3 -name "deploy.js" 2>/dev/null | grep -q .; then
    DEPLOY_FILES=$(find "$TARGET_DIR/node_modules" -maxdepth 3 -name "deploy.js" 2>/dev/null)
    for df in $DEPLOY_FILES; do
        if grep -qi "maintainer\|npm publish\|NPM_TOKEN\|whoami" "$df" 2>/dev/null; then
            bad "Suspected CanisterWorm worm script: $df"
            FOUND_COMPROMISED_PKGS=1
            info "deploy.js is the tool that harvests npm tokens and republishes malware."
            info "Legitimate npm packages do not ship a deploy.js with these patterns."
            info "Remediation: rm -rf node_modules && npm install --ignore-scripts"
            PKG_FOUND=1
        fi
    done
fi

[ "$PKG_FOUND" -eq 0 ] && ok "No known compromised package dependencies detected"

# =============================================================================
# SECTION 8 — CI/CD and GitHub Actions exposure
# =============================================================================
# CanisterWorm specifically targets CI/CD environments where npm tokens are
# commonly injected as environment variables.  GitHub Actions runners are a
# primary target.  Trivy (the scanner) was also compromised as an entry point.
# =============================================================================
banner "[8/9] Checking CI/CD exposure indicators..."

CI_FOUND=0

# Check for GitHub Actions secrets that could be harvested
if [ -n "$GITHUB_TOKEN" ] || [ -n "$GITHUB_ACTIONS" ]; then
    warn "Running inside GitHub Actions — CI npm tokens are a primary CanisterWorm target"
    info "Ensure npm tokens are scoped and short-lived."
    info "Enable npm token automation flags: --ci (requires 2FA for publishing)."
    CI_FOUND=1
fi

# Check for any CI system
if [ -n "$CI" ] || [ -n "$JENKINS_URL" ] || [ -n "$CIRCLECI" ] || [ -n "$TRAVIS" ]; then
    warn "CI environment detected — ensure npm publish tokens are revoked after each job"
    CI_FOUND=1
fi

# Check if Trivy is in use (it was the original attack vector for TeamPCP)
if command -v trivy >/dev/null 2>&1; then
    TRIVY_VERSION=$(trivy --version 2>/dev/null | head -1)
    warn "Trivy detected: $TRIVY_VERSION"
    FOUND_TRIVY=1
    info "Trivy itself was compromised by TeamPCP before the CanisterWorm npm wave."
    info "Ensure you are using an official Trivy release from: https://github.com/aquasecurity/trivy/releases"
    info "Verify the binary hash against official checksums."
    CI_FOUND=1
fi

[ "$CI_FOUND" -eq 0 ] && ok "No specific CI/CD exposure signals detected"

# =============================================================================
# SECTION 9 — npm audit
# =============================================================================
banner "[9/9] Running npm audit for critical vulnerabilities..."

if [ -f "$TARGET_DIR/package.json" ]; then
    if command -v npm >/dev/null 2>&1; then
        AUDIT_OUT=$(cd "$TARGET_DIR" && npm audit --omit=dev 2>/dev/null)
        if echo "$AUDIT_OUT" | grep -qi "critical"; then
            bad "Critical vulnerabilities found by npm audit"
            FOUND_NPM_AUDIT=1
            echo "$AUDIT_OUT" | grep -i "critical" | head -10
            info "Remediation: npm audit fix  (or review manually for breaking changes)"
        else
            ok "No critical npm audit findings"
        fi
    else
        warn "npm not found — skipping npm audit"
    fi
else
    ok "No package.json in target directory — skipping npm audit"
fi

# =============================================================================
# FINAL RESULT + TARGETED REMEDIATION SUMMARY
# =============================================================================
echo ""
printf "${BOLD}========================================================${RESET}\n"
printf "${BOLD}   SCAN RESULT${RESET}\n"
printf "${BOLD}========================================================${RESET}\n"

if [ "$ISSUES_FOUND" -eq 1 ]; then
    printf "${RED}${BOLD}[!!!] POTENTIAL COMPROMISE INDICATORS DETECTED!${RESET}\n"
    printf "\n${BOLD}TARGETED REMEDIATION — actions for issues found above${RESET}\n"
    echo "--------------------------------------------------------"

    # Step 1: only when pgmon service or backdoor files were found
    if [ "$FOUND_BACKDOOR_SERVICE" -eq 1 ]; then
        printf "\n${BOLD}STEP 1 — Stop and remove the persistent backdoor${RESET}\n"
        printf "  systemctl --user stop pgmon.service\n"
        printf "  systemctl --user disable pgmon.service\n"
        printf "  systemctl --user daemon-reload\n"
        printf "  rm -f  ~/.config/systemd/user/pgmon.service\n"
        printf "  rm -f  ~/.local/share/pgmon/service.py\n"
        printf "  rmdir  ~/.local/share/pgmon 2>/dev/null\n"
    fi

    # Step 2: only when payload files exist or malicious processes are running
    if [ "$FOUND_PAYLOAD_FILES" -eq 1 ] || [ "$PROC_SUSPICIOUS" -eq 1 ]; then
        printf "\n${BOLD}STEP 2 — Kill malicious processes and remove payload files${RESET}\n"
        printf "  pkill -f '/tmp/pglog'          # kill running payload\n"
        printf "  pkill -f 'pgmon/service.py'    # kill C2 poller\n"
        printf "  pkill -f 'deploy.js'           # kill worm if running\n"
        printf "  rm -f /tmp/pglog /tmp/.pg_state\n"
    fi

    # Steps 3+4: only when npm tokens are exposed or worm process was found
    if [ "$TOKEN_FOUND" -eq 1 ] || [ "$PROC_SUSPICIOUS" -eq 1 ]; then
        printf "\n${BOLD}STEP 3 — Rotate ALL npm credentials immediately${RESET}\n"
        printf "  npm token list                           # see all active tokens\n"
        printf "  npm token revoke <id>                    # revoke every one\n"
        printf "  # Then create a fresh, scoped, 2FA-protected token.\n"

        printf "\n${BOLD}STEP 4 — Check for unauthorised npm publishes${RESET}\n"
        printf "  npm access list packages <your-username> # list your packages\n"
        printf "  # Visit: https://www.npmjs.com/settings/<username>/packages\n"
        printf "  # Look for versions published on or after 20 Mar 2026 that\n"
        printf "  # you did not authorise — deprecate or unpublish them.\n"
    fi

    # Step 5: only when compromised packages, dangerous hooks, or audit vulns found
    if [ "$FOUND_COMPROMISED_PKGS" -eq 1 ] || [ "$FOUND_POSTINSTALL" -eq 1 ] || [ "$FOUND_NPM_AUDIT" -eq 1 ]; then
        printf "\n${BOLD}STEP 5 — Clean-reinstall project dependencies${RESET}\n"
        printf "  cd %s\n" "$TARGET_DIR"
        printf "  rm -rf node_modules package-lock.json\n"
        printf "  npm install --ignore-scripts\n"
        printf "  # --ignore-scripts prevents any postinstall hook from running.\n"
        if [ "$FOUND_NPM_AUDIT" -eq 1 ]; then
            printf "  npm audit fix                            # then fix audit findings\n"
        fi
    fi

    # Step 6: only when active C2 connection detected or backdoor was running
    if [ "$NET_FOUND" -eq 1 ] || [ "$FOUND_BACKDOOR_SERVICE" -eq 1 ]; then
        printf "\n${BOLD}STEP 6 — Block the C2 infrastructure${RESET}\n"
        printf "  # Sinkhole the ICP canister in /etc/hosts:\n"
        printf "  echo '0.0.0.0 tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io' | sudo tee -a /etc/hosts\n"
        printf "  # Or block at firewall level: outbound TCP 443 to *.icp0.io\n"
    fi

    # Step 7: only when Trivy is present (it was the initial TeamPCP attack vector)
    if [ "$FOUND_TRIVY" -eq 1 ]; then
        printf "\n${BOLD}STEP 7 — Verify your Trivy binary${RESET}\n"
        printf "  # Trivy was compromised by TeamPCP before the CanisterWorm npm wave.\n"
        printf "  # Download and verify against official checksums:\n"
        printf "  # https://github.com/aquasecurity/trivy/releases\n"
    fi

    # General prevention — always shown when any issue was found
    printf "\n${BOLD}GENERAL — Prevent future infection${RESET}\n"
    printf "  npm install --ignore-scripts       # always use for untrusted packages\n"
    printf "  npm config set ignore-scripts true # set as global default\n"
    printf "  # Enable npm 2FA: https://docs.npmjs.com/configuring-two-factor-authentication\n"
    printf "  # Use scoped, automation-only tokens with minimal publish permissions.\n"
    printf "  # Consider: socket.dev or Aikido.dev for supply chain monitoring.\n"

    echo "--------------------------------------------------------"
else
    printf "${GREEN}${BOLD}[OK] No indicators of CanisterWorm compromise detected.${RESET}\n"
    printf "\n${BOLD}Prevention best practices:${RESET}\n"
    printf "  • Always run: npm install --ignore-scripts\n"
    printf "  • Enable npm 2FA on your account\n"
    printf "  • Use scoped, short-lived publish tokens\n"
    printf "  • Monitor package.json changes in code review\n"
    printf "  • Use a supply-chain scanner (socket.dev, Aikido, Snyk)\n"
    printf "  • Verify Trivy binaries if used: check official release checksums\n"
fi

echo ""
printf "${BOLD}========================================================${RESET}\n"
printf "${BOLD}   Scan Complete${RESET}\n"
printf "${BOLD}========================================================${RESET}\n"
echo ""