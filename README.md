## 🛡️ CanisterWorm Detection Scripts — Usage Guide

---

# 🐧 Using the Bash Script

## Make executable
```bash
chmod +x check_canisterworm.sh
```

## Run scan

### Scan current directory
```bash
./check_canisterworm.sh
```

### Scan a specific project
```bash
./check_canisterworm.sh /path/to/project
```

---

# 🪟 Using the PowerShell Script

## Allow script execution (if needed)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Run scan

### Scan current directory
```powershell
.\Check-CanisterWorm.ps1
```

### Scan a specific project
```powershell
.\Check-CanisterWorm.ps1 -TargetDir "C:\path\to\project"
```

---

# 🔍 What the Scripts Check

- Malicious files (e.g. `/tmp/pglog`)
- Suspicious services (`pgmon.service`)
- Exposed npm tokens (`.npmrc`, env vars)
- `postinstall` scripts in dependencies
- Known suspicious package patterns
- Suspicious processes
- Network connections (e.g. `icp0`)
- `npm audit` critical vulnerabilities

---

# 🚨 Understanding Results

## No Issues
```
[OK] No obvious indicators of CanisterWorm compromise
```

## Issues Found
```
[!!!] Potential compromise indicators detected!
```

Follow remediation steps printed by the script.

---

# 🧯 What To Do If Infected

## Remove persistence
```bash
systemctl --user disable pgmon.service
rm -f ~/.config/systemd/user/pgmon.service
```

## Remove payload
```bash
rm -f /tmp/pglog
```

## Rotate npm credentials
```bash
npm token revoke <token-id>
```

## Clean reinstall dependencies
```bash
rm -rf node_modules package-lock.json
npm install --ignore-scripts
```

## Check npm account
Review for unauthorized package publishes.

---

# 🔒 Prevention Best Practices

## Safer installs
```bash
npm install --ignore-scripts
```

- Enable npm 2FA
- Use scoped tokens
- Avoid untrusted packages
- Monitor `package.json` changes

---

# ⚠️ Disclaimer

- Heuristic-based detection only
- Detects known indicators (IOCs)
- Not a full malware scanner
- Use alongside proper security tools