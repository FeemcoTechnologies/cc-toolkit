# Playbook Audit Report — Best Practices Analysis

**Date:** 2026-06-11
**Scope:** 62 playbook YAML files
**Directories:** `/share/git-repo/Scripts/cc-toolkit-public/playbooks/`, `/share/git-repo/Scripts/ai-combined-tools/playbooks/`

---

## Executive Summary

| Metric | Score |
|--------|-------|
| **Excellent** (v3/v2, all features) | 4 (6%) |
| **Good** (v2, most features) | 33 (53%) |
| **Okay** (v1-era, partial features) | 15 (24%) |
| **Poor** (no version, minimal structure) | 10 (16%) |

**Key Issues:**
- **14 playbooks** (23%) have hardcoded credentials or filesystem paths
- **10 playbooks** (16%) lack `version` fields (legacy format)
- **15 v1-era playbooks** are missing postflight blocks, notify steps, and use `log` instead of `report` type
- 23% don't use conditional execution (run everything regardless of findings)
- 56% lack proper `preflight` blocks

---

## Best Practices Check — Per-Playbook

### Excellent (4)

| Playbook | Strengths |
|----------|-----------|
| `cloud-enum-v3.yaml` | v3, full pre/postflight, artifacts, conditional, parallel, notify, report |
| `kubernetes-security-v3.yaml` | v3, full pre/postflight, artifacts, conditional, parallel, notify, report |
| `memory-forensics.yaml` | v2, max_workers parallelism, full pre/postflight, artifacts, notify, report |
| `openshift-security-v2.yaml` | v2, ~1825 lines, most comprehensive playbook, full feature set |

### Good (33)

Includes all v2.0 playbooks: `ad-enum-v2`, `api-testing-v2`, `binary-analysis`, `bloodhound-ad`, `c2-operations`, `cloud-aws`, `cloud-azure`, `cloud-enum-v2`, `cloud-gcp`, `cms-assessment`, `container-security`, `data-exfiltration`, `defense-evasion`, `exploit-research`, `forensics-v2`, `forensics-windows-v2`, `full-recon-v2`, `kerberos-attacks`, `ldap-enum`, `linux-privesc`, `log-analysis`, `mobile-pentest`, `network-shares`, `nuclei-full-scan-v2`, `password-audit-v2`, `payload-generation`, `persistence`, `phishing-assessment`, `pivoting-tunneling`, `responder-poisoning`, `sast-scan`, `smb-enum`, `threat-intel`, `web-pentest-v2`, `windows-privesc`, `wireless-audit-v2`

Common minor gaps: preamble in steps instead of `preflight` block, no `pause` between steps.

### Okay (15) — v1-era, Need Upgrades

| Playbook | Issues |
|----------|--------|
| `adcs-certificates.yaml` | No postflight, no notify, report uses `log` |
| `cicd-pentest.yaml` | No postflight, no notify, report uses `log` |
| `graphql-enum.yaml` | No postflight, no notify, no conditional, hardcoded path |
| `http-smuggling.yaml` | No postflight, no notify, no conditional, hardcoded path |
| `insecure-deserialization.yaml` | No postflight, no notify, report uses `log` |
| `jwt-attacks.yaml` | No postflight, no notify, report uses `log`, hardcoded path |
| `llm-prompt-injection.yaml` | No postflight, no notify, report uses `log` |
| `nuclei-custom-scan.yaml` | No preflight, no artifacts, no report, hardcoded path |
| `oauth.yaml` | No postflight, no notify, report uses `log` |
| `ssrf.yaml` | No postflight, no notify, no conditional, hardcoded path |
| `ssti.yaml` | No postflight, no notify, no conditional, hardcoded path |
| `supply-chain.yaml` | No postflight, no notify, no conditional |
| `web-cache-deception.yaml` | No postflight, no notify, no conditional, hardcoded path |
| `xxe.yaml` | No postflight, no notify, no conditional |
| `yara-custom-scan.yaml` | No preflight, no artifacts, no parallel, hardcoded path |

### Poor (10) — Legacy Format, No Version

| Playbook | Issues |
|----------|--------|
| `comprehensive-recon.yaml` | No version, vars, pre/postflight, artifacts, notify, report, parallel, or conditional |
| `forensics-acquisition.yaml` | Same — single-tool script wrapped as playbook |
| `full-pentest.yaml` | Hardcoded paths, no version, vars, pre/postflight, artifacts, notify, report, parallel |
| `internal-network.yaml` | No version, vars, pre/postflight, artifacts, notify, report, parallel |
| `pt-2026-001-retest.yaml` | **Hardcoded Supabase credentials**, no version, minimal structure |
| `quick-recon.yaml` | No version, vars, pre/postflight, artifacts, notify, report, parallel |

---

## Security Issues — Hardcoded Credentials

| Severity | File | Details |
|----------|------|---------|
| **CRITICAL** | `pt-2026-001-retest.yaml` | Hardcoded Supabase `anon_key` JWT + `supabase_ref` |
| **HIGH** | `bloodhound-ad.yaml` | Hardcoded `bh_pass: "Password123!"`, IP `192.168.56.1` |
| **LOW** | 12 other files | Hardcoded wordlist/tool paths (not credentials but reduce portability) |

---

## Recommendations

### 1. Security (Critical)
Move hardcoded credentials to env vars or a secrets file loaded via `vars` + `CC_CONFIG_FILE`.

### 2. Upgrade 15 v1 playbooks to v2
Add `postflight`, `notify`, `report` (using `report` type, not `log`), and `conditional` steps.

### 3. Upgrade 10 legacy playbooks
Add `version`, `vars`, `preflight`/`postflight`, `parallel` execution, artifact declarations, and report generation.

### 4. Standardize paths
Replace hardcoded paths (`/wordlists/...`, `/usr/share/wordlists/...`) with `vars` defaults.

### 5. Add pause between aggressive steps
For network-based playbooks, add `pause: 2` between port scans and service scans to avoid overwhelming targets.

---

## Feature Coverage Summary

```
Feature              Coverage
─────────────────────────────────────────
Has version field    52/62 (84%)
Has vars section     52/62 (84%)
Has preflight block  35/62 (56%)
Has postflight block 40/62 (65%)
Has artifacts        48/62 (77%)
Has timeout          ~55/62 (89%)
Has when/condition   45/62 (73%)
Has notify step      38/62 (61%)
Has report step      52/62 (84%)
Has parallel exec    49/62 (79%)
No hardcoded creds   60/62 (97%)*
No hardcoded paths   48/62 (77%)

* 2 files have hardcoded credentials; 12 more have hardcoded paths
```
