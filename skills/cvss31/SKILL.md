---
name: cvss31
description: Calculate and analyze CVSS v3.1 (Common Vulnerability Scoring System) scores for vulnerabilities. Use this skill whenever a user mentions CVSS, vulnerability scoring, CVE scoring, security severity assessment, or asks to score/calculate/analyze a vulnerability. Also trigger when users share a CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/...) or ask about Base, Temporal, or Environmental scores. This skill provides accurate calculations, vector string generation, metric guidance, and professional vulnerability analysis reports.
---

# CVSS v3.1 Skill

This skill enables precise CVSS v3.1 scoring — calculating Base, Temporal, and Environmental scores, generating vector strings, interpreting existing vectors, and producing professional vulnerability severity reports.

## When to Use This Skill
- User asks to "score a vulnerability" or "calculate CVSS"
- User provides a CVE or vulnerability description and wants scoring guidance
- User provides a CVSS vector string for interpretation or recalculation
- User asks what a CVSS score means or how to score a specific metric
- User wants to generate a pentest or vulnerability report with CVSS data

---

## Workflow

### Step 1: Understand the Request Type

**A) Calculate from scratch** → Ask for metric values (see Metric Reference below), then compute and output score + vector string.

**B) Parse an existing vector** → Extract values, recompute scores, explain each metric.

**C) Guide scoring of a vulnerability description** → Analyze the described vuln and recommend metric values with justification.

**D) Generate a report** → Produce a professional markdown/docx section with the CVSS breakdown.

### Step 2: Gather Metrics (if calculating from scratch)

**Required (Base Metrics):**
Ask for all 8 base metrics. If the user describes a vulnerability without specifying metrics, infer appropriate values and explain your reasoning.

**Optional (Temporal & Environmental):**
Only collect if user asks or if context clearly warrants it.

### Step 3: Calculate Scores

Use the formulas in `references/equations.md`. For quick calculations, use the JavaScript calculator snippet in `scripts/calculator.js`.

### Step 4: Output

Always provide:
1. **Score** (e.g., 9.8 Critical)
2. **Severity Rating** (None/Low/Medium/High/Critical)
3. **Vector String** (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
4. **Metric breakdown** explaining each value and why
5. **Recommendations** (optional but valuable)

---

## Quick Reference: Metric Values

### BASE METRICS (all required)

#### Attack Vector (AV)
| Value | Code | Score | Meaning |
|-------|------|-------|---------|
| Network | N | 0.85 | Remotely exploitable over internet |
| Adjacent | A | 0.62 | Requires same network/VLAN |
| Local | L | 0.55 | Requires local access or social engineering |
| Physical | P | 0.20 | Requires physical device access |

#### Attack Complexity (AC)
| Value | Code | Score | Meaning |
|-------|------|-------|---------|
| Low | L | 0.77 | Repeatable, no special conditions |
| High | H | 0.44 | Requires specific race conditions or extra steps |

#### Privileges Required (PR)
| Value | Code | Score (Unchanged) | Score (Changed) |
|-------|------|-------------------|-----------------|
| None | N | 0.85 | 0.85 |
| Low | L | 0.62 | 0.68 |
| High | H | 0.27 | 0.50 |

#### User Interaction (UI)
| Value | Code | Score |
|-------|------|-------|
| None | N | 0.85 |
| Required | R | 0.62 |

#### Scope (S)
| Value | Code | Meaning |
|-------|------|---------|
| Unchanged | U | Impact limited to vulnerable component |
| Changed | C | Impact can reach beyond vulnerable component |

#### Confidentiality / Integrity / Availability (C/I/A)
| Value | Code | Score |
|-------|------|-------|
| High | H | 0.56 |
| Low | L | 0.22 |
| None | N | 0.00 |

### TEMPORAL METRICS (optional)

#### Exploit Code Maturity (E)
| Value | Code | Multiplier |
|-------|------|------------|
| Not Defined | X | 1.00 |
| High | H | 1.00 |
| Functional | F | 0.97 |
| Proof-of-Concept | P | 0.94 |
| Unproven | U | 0.91 |

#### Remediation Level (RL)
| Value | Code | Multiplier |
|-------|------|------------|
| Not Defined | X | 1.00 |
| Unavailable | U | 1.00 |
| Workaround | W | 0.97 |
| Temporary Fix | T | 0.96 |
| Official Fix | O | 0.95 |

#### Report Confidence (RC)
| Value | Code | Multiplier |
|-------|------|------------|
| Not Defined | X | 1.00 |
| Confirmed | C | 1.00 |
| Reasonable | R | 0.96 |
| Unknown | U | 0.92 |

### ENVIRONMENTAL METRICS (optional)

#### Security Requirements (CR/IR/AR)
| Value | Code | Multiplier |
|-------|------|------------|
| Not Defined | X | 1.00 |
| High | H | 1.50 |
| Medium | M | 1.00 |
| Low | L | 0.50 |

#### Modified Base Metrics (MAV/MAC/MPR/MUI/MS/MC/MI/MA)
Same values as Base metrics, plus Not Defined (X) which defaults to the Base metric value.

---

## Severity Rating Scale

| Rating | Score Range |
|--------|-------------|
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

---

## Formulas (Summary)

Read `references/equations.md` for full equations. Key formulas:

```
ISS = 1 - [(1-C) × (1-I) × (1-A)]

Impact =
  If Scope Unchanged: 6.42 × ISS
  If Scope Changed:   7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15

Exploitability = 8.22 × AV × AC × PR × UI

BaseScore =
  If Impact <= 0: 0
  If Scope Unchanged: Roundup(min(Impact + Exploitability, 10))
  If Scope Changed:   Roundup(min(1.08 × (Impact + Exploitability), 10))

TemporalScore = Roundup(BaseScore × E × RL × RC)
```

For Environmental, see `references/equations.md`.

**Roundup function**: returns smallest value to 1 decimal place ≥ input.

---

## Output Template

When presenting a CVSS score, use this structure:

```
## CVSS v3.1 Score: [SCORE] ([SEVERITY])

**Vector String:** `CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X`

### Base Score: [X.X] ([SEVERITY])

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network (N) | ... |
| Attack Complexity | Low (L) | ... |
| Privileges Required | None (N) | ... |
| User Interaction | None (N) | ... |
| Scope | Unchanged (U) | ... |
| Confidentiality | High (H) | ... |
| Integrity | High (H) | ... |
| Availability | High (H) | ... |

### Temporal Score: [X.X] (if applicable)
### Environmental Score: [X.X] (if applicable)

### Interpretation
[Brief paragraph explaining what this score means for prioritization]
```

---

## Common Vulnerability Patterns

**RCE over network, no auth:**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Base: **9.8 Critical**

**SQL Injection (auth required):**
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → Base: **8.8 High**

**XSS (reflected, user interaction):**
`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → Base: **6.1 Medium**

**Local privilege escalation:**
`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → Base: **7.8 High**

**Physical attack, info disclosure:**
`AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → Base: **4.6 Medium**

---

## Reference Files

- `references/equations.md` — Full mathematical equations with all edge cases
- `references/scoring-guide.md` — Detailed metric selection guidance with examples
- `scripts/calculator.js` — JavaScript implementation for accurate calculation

Read these when you need precision on edge cases or to verify calculations.
