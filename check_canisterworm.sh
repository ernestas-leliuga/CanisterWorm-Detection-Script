#!/bin/sh

TARGET_DIR="${1:-.}"
ISSUES_FOUND=0

echo "=== CanisterWorm Detection Script ==="
echo "Scanning directory: $TARGET_DIR"
echo

########################################
# Helper to flag issues
########################################
flag_issue() {
    echo "[!] $1"
    ISSUES_FOUND=1
}

########################################
# 1. Check suspicious files (IOCs)
########################################
echo "[+] Checking known malicious files..."

FILES="
/tmp/pglog
$HOME/.config/systemd/user/pgmon.service
"

for f in $FILES; do
    if [ -f "$f" ]; then
        flag_issue "Suspicious file found: $f"
    else
        echo "[OK] Not found: $f"
    fi
done

echo

########################################
# 2. Check systemd persistence
########################################
echo "[+] Checking systemd user services..."

if systemctl --user list-units --type=service 2>/dev/null | grep -iq pgmon; then
    flag_issue "Suspicious service 'pgmon' detected"
else
    echo "[OK] No pgmon service found"
fi

echo

########################################
# 3. Check npm credentials
########################################
echo "[+] Checking npm credentials..."

if [ -f "$HOME/.npmrc" ]; then
    grep -qi "_authToken" "$HOME/.npmrc" && \
        flag_issue "~/.npmrc contains auth token (possible exfil risk)" || \
        echo "[OK] ~/.npmrc has no auth token"
else
    echo "[OK] No ~/.npmrc file"
fi

if [ ! -z "$NPM_TOKEN" ]; then
    flag_issue "NPM_TOKEN environment variable is set"
else
    echo "[OK] No NPM_TOKEN env variable"
fi

echo

########################################
# 4. Scan for postinstall scripts
########################################
echo "[+] Scanning for postinstall hooks..."

find "$TARGET_DIR" -name package.json 2>/dev/null | while read file; do
    if grep -q '"postinstall"' "$file"; then
        flag_issue "postinstall script in: $file"
    fi
done

echo

########################################
# 5. Check for suspicious dependencies
########################################
echo "[+] Checking dependencies..."

if [ -f "$TARGET_DIR/package.json" ]; then
    if grep -E "emilgroup|opengov|eslint-config-ppf|teale" "$TARGET_DIR/package.json" >/dev/null; then
        flag_issue "Suspicious dependency pattern in package.json"
    else
        echo "[OK] No obvious suspicious dependencies"
    fi
else
    echo "[OK] No package.json in target directory"
fi

echo

########################################
# 6. Check running processes
########################################
echo "[+] Checking running processes..."

if ps aux | grep -E "pglog|icp0" | grep -v grep >/dev/null; then
    flag_issue "Suspicious process detected (pglog/icp0)"
else
    echo "[OK] No suspicious processes"
fi

echo

########################################
# 7. Check network connections
########################################
echo "[+] Checking network connections..."

if netstat -tulnp 2>/dev/null | grep -iq icp0; then
    flag_issue "Connection to ICP (icp0) detected"
else
    echo "[OK] No ICP connections"
fi

echo

########################################
# 8. npm audit
########################################
echo "[+] Running npm audit..."

if [ -f "$TARGET_DIR/package.json" ]; then
    (cd "$TARGET_DIR" && npm audit --omit=dev 2>/dev/null | grep -i critical) && \
        flag_issue "Critical vulnerabilities reported by npm audit" || \
        echo "[OK] No critical npm audit findings"
else
    echo "[OK] Skipping npm audit (no package.json)"
fi

echo

########################################
# FINAL RESULT + REMEDIATION
########################################
echo "=== RESULT ==="

if [ "$ISSUES_FOUND" -eq 1 ]; then
    echo "[!!!] Potential compromise indicators detected!"
    echo
    echo "Recommended actions:"
    echo "----------------------------------------"
    echo "1. Remove persistence:"
    echo "   systemctl --user disable pgmon.service"
    echo "   rm -f ~/.config/systemd/user/pgmon.service"
    echo
    echo "2. Remove payload:"
    echo "   rm -f /tmp/pglog"
    echo
    echo "3. Rotate npm credentials:"
    echo "   npm token revoke <token-id>"
    echo
    echo "4. Clean install dependencies safely:"
    echo "   cd $TARGET_DIR"
    echo "   rm -rf node_modules package-lock.json"
    echo "   npm install --ignore-scripts"
    echo
    echo "5. Review package.json for unknown dependencies"
    echo
    echo "6. Check npm account for unauthorized publishes:"
    echo "   https://www.npmjs.com/settings/YOUR_USERNAME/profile"
    echo
    echo "7. Enable npm 2FA immediately"
    echo "----------------------------------------"
else
    echo "[OK] No obvious indicators of CanisterWorm compromise"
fi

echo
echo "=== Scan Complete ==="