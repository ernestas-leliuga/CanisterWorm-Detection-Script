## 🛡️ CanisterWorm Detection Scripts — Usage Guide

---

## 🦠 What is CanisterWorm?

CanisterWorm is a **self-propagating npm supply chain worm** first observed on **20 March 2026**, attributed to threat actor **TeamPCP** (also responsible for the preceding Aqua Security Trivy compromises).

### How it works

1. **Postinstall hook** — A malicious `postinstall` script in a compromised npm package runs automatically during `npm install`. It decodes a base64-embedded Python script and installs a systemd user-service.
2. **Systemd persistence** — The `pgmon.service` unit is created with `Restart=always`. It requires no root privileges, starts at login, and restarts every 5 seconds on crash. It is deliberately named to blend in as PostgreSQL tooling.
3. **ICP canister C2** — The Python backdoor (`service.py`) polls an [Internet Computer Protocol (ICP)](https://internetcomputer.org/) canister at `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` every ~50 minutes using a spoofed browser User-Agent. The canister returns a URL for a second-stage binary. If the URL contains `youtube.com` the payload is dormant; any other URL is downloaded to `/tmp/pglog` and executed.
4. **Token harvest + self-propagation** — The worm scrapes npm tokens from `~/.npmrc`, `./.npmrc`, `/etc/npmrc`, environment variables (`NPM_TOKEN`, `NPM_TOKENS`, `*NPM*TOKEN*`), and `npm config get`. It then uses `deploy.js` to republish itself to every package the stolen token can reach, bumping the patch version to appear as a routine update.

### Affected packages (as of 21 Mar 2026)
- **`@emilgroup/*`** — entire scope, 28+ packages
- **`@opengov/*`** — 16+ packages
- `@teale.io/eslint-config`
- `@airtm/uuid-base32`
- `@pypestream/floating-ui-dom`
- 135+ malicious artifacts across 64+ unique packages total

### References
- [Aikido Security: TeamPCP deploys CanisterWorm on NPM following Trivy compromise](https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise)
- [Socket: CanisterWorm — npm Publisher Compromise Deploys Backdoor Across 29+ Packages](https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages)
- [Wiz: Trivy Compromised — TeamPCP Supply Chain Attack](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)

---

## 🐧 Using the Bash Script

### Make executable
```bash
chmod +x check_canisterworm.sh
```

### Run scan

#### Scan current directory
```bash
./check_canisterworm.sh
```

#### Scan a specific project
```bash
./check_canisterworm.sh /path/to/project
```

---

## 🪟 Using the PowerShell Script

### Allow script execution (if needed)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Run scan

#### Scan current directory
```powershell
.\Check-CanisterWorm.ps1
```

#### Scan a specific project
```powershell
.\Check-CanisterWorm.ps1 -TargetDir "C:\path\to\project"
# Also works on Linux/macOS with PowerShell Core (pwsh):
.\Check-CanisterWorm.ps1 -TargetDir "/home/user/project"
```

---

## 🔍 What the Scripts Check (9 sections)

| # | Check | What it looks for |
|---|-------|-------------------|
| 1 | **Malicious file artefacts** | `/tmp/pglog`, `/tmp/.pg_state`, `~/.config/systemd/user/pgmon.service`, `~/.local/share/pgmon/service.py` + known SHA-256 hashes of malicious `index.js` and `deploy.js` |
| 2 | **systemd persistence** | Active or installed `pgmon.service` in the user systemd session |
| 3 | **Running processes** | `pgmon/service.py` (C2 poller), `/tmp/pglog` (payload), `deploy.js` (worm spreading tokens) |
| 4 | **C2 network connections** | Active connections or DNS lookups to `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` / `*.icp0.io` |
| 5 | **npm token exposure** | Tokens in `~/.npmrc`, `./.npmrc`, `/etc/npmrc`, environment variables (`NPM_TOKEN`, `NPM_TOKENS`, `*NPM*TOKEN*`), and `npm config get` |
| 6 | **Dangerous postinstall hooks** | Hooks containing `base64`, `systemctl`, `python3`, `eval`, `exec`, `curl`, or `wget` patterns |
| 7 | **Compromised dependencies** | `@emilgroup/*`, `@opengov/*`, `@teale.io/eslint-config`, `@airtm/uuid-base32`, `@pypestream/floating-ui-dom`; also `deploy.js` with worm-specific code in `node_modules` |
| 8 | **CI/CD exposure** | GitHub Actions, Jenkins, CircleCI, Travis, GitLab CI; Trivy binary presence (Trivy was the preceding attack vector) |
| 9 | **npm audit** | Critical vulnerabilities via `npm audit --omit=dev` |

---

## 🔴 Known Indicators of Compromise (IOCs)

### Filesystem
| File | Description |
|------|-------------|
| `~/.local/share/pgmon/service.py` | Python backdoor script (C2 poller) |
| `~/.config/systemd/user/pgmon.service` | systemd persistence unit (`Restart=always`) |
| `/tmp/pglog` | Downloaded second-stage binary payload |
| `/tmp/.pg_state` | State file storing last downloaded payload URL |

### Network / C2
| Indicator | Description |
|-----------|-------------|
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` | ICP canister acting as C2 dead-drop |
| ICP canister ID: `tdtqy-oyaaa-aaaae-af2dq-cai` | Decentralized, censorship-resistant C2 |

### Malicious file hashes (SHA-256)

**`index.js` (backdoor installer):**
| Hash | Wave |
|------|------|
| `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b` | Wave 1 — dry run, empty payload |
| `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba` | Wave 2 — armed ICP backdoor, manual deploy |
| `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a` | Wave 3 — self-propagating, test payload |
| `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926` | Wave 4 — final form (self-propagating + armed) |

**`deploy.js` (worm propagation tool):**
| Hash | Wave |
|------|------|
| `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152` | Wave 1 — verbose, no `--tag latest` |
| `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7` | Wave 2 — added `--tag latest` |
| `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956` | Wave 3+ — minified, silent |

---

## 🚨 Understanding Results

### No Issues
```
[OK] No indicators of CanisterWorm compromise detected.
```

### Issues Found
```
[!!!] POTENTIAL COMPROMISE INDICATORS DETECTED!
```

The scripts print targeted remediation for each finding directly under the `[!!!]` line.

---

## 🧯 Full Remediation (if infected)

### Step 1 — Stop and remove the persistent backdoor
```bash
systemctl --user stop pgmon.service
systemctl --user disable pgmon.service
systemctl --user daemon-reload
rm -f  ~/.config/systemd/user/pgmon.service
rm -rf ~/.local/share/pgmon
```

### Step 2 — Kill running malware and remove payload files
```bash
pkill -f '/tmp/pglog'          # kill running payload
pkill -f 'pgmon/service.py'   # kill C2 poller
pkill -f 'deploy.js'          # kill worm if running
rm -f /tmp/pglog /tmp/.pg_state
```

### Step 3 — Rotate ALL npm credentials immediately
```bash
npm token list                  # find all active token IDs
npm token revoke <token-id>     # revoke each one
# Then create a fresh scoped, 2FA-protected token.
```

### Step 4 — Audit your npm packages for unauthorised publishes
```bash
npm access list packages <your-username>
# Look for versions published on or after 20 Mar 2026 that you did not authorise.
# If found:
npm deprecate <package>@<version> "Compromised by CanisterWorm — do not install"
```

### Step 5 — Clean-reinstall project dependencies
```bash
rm -rf node_modules package-lock.json
npm install --ignore-scripts
```

### Step 6 — Block C2 infrastructure
```bash
# Sinkhole via /etc/hosts:
echo "0.0.0.0 tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io" | sudo tee -a /etc/hosts
# Or block at firewall: outbound TCP 443 to *.icp0.io
```

### Step 7 — Verify Trivy (if used in CI)
TeamPCP compromised Trivy before deploying CanisterWorm. Verify your binary:
```bash
# Download and verify checksums from the official release:
# https://github.com/aquasecurity/trivy/releases
```

---

## 🔒 Prevention Best Practices

### Always use `--ignore-scripts`
```bash
npm install --ignore-scripts
npm config set ignore-scripts true   # set as global default
```

### npm account hardening
- Enable **2FA** on your npm account: [docs.npmjs.com/configuring-two-factor-authentication](https://docs.npmjs.com/configuring-two-factor-authentication)
- Use **scoped, automation-only tokens** with the minimum required publish permissions
- Regularly rotate tokens and revoke any that are no longer needed
- Audit your npm account for unexpected package versions

### Dependency hygiene
- Review `package.json` changes in every code review
- Pin exact dependency versions and lock via `package-lock.json`
- Verify packages before adding them using [socket.dev](https://socket.dev) or [Aikido](https://aikido.dev)

### CI/CD
- Never store long-lived npm tokens in CI environment variables
- Use short-lived tokens scoped to specific publish operations
- Scan for token leakage in CI logs

---

## ⚠️ Disclaimer

- Heuristic-based detection only
- Detects known indicators of compromise (IOCs) from the March 2026 CanisterWorm campaign
- Cannot detect unknown variants or future evolutions of the malware
- Not a substitute for a full malware scanner or endpoint security product
- Use alongside proper security tooling such as [Socket](https://socket.dev), [Aikido](https://aikido.dev), or [Snyk](https://snyk.io)
