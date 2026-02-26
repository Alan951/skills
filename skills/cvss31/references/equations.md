# CVSS v3.1 Complete Equations Reference

Source: https://www.first.org/cvss/v3.1/specification-document (Section 7)

---

## Helper Functions

### Roundup(x)
Returns the smallest number, specified to 1 decimal place, that is equal to or higher than its input.

**Pseudocode (floating-point safe):**
```
function Roundup(input):
    int_input = round_to_nearest_integer(input × 100000)
    if (int_input mod 10000) == 0:
        return int_input / 100000.0
    else:
        return (floor(int_input / 10000) + 1) / 10.0
```

Examples: `Roundup(4.02) = 4.1`, `Roundup(4.00) = 4.0`, `Roundup(4.005) = 4.1`

### Minimum(a, b)
Returns the smaller of two arguments.

---

## 7.1 Base Score Equations

```
ISS = 1 - [ (1 - C) × (1 - I) × (1 - A) ]

Impact =
    if Scope == Unchanged:  6.42 × ISS
    if Scope == Changed:    7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15

Exploitability = 8.22 × AV × AC × PR × UI

BaseScore =
    if Impact <= 0:  0.0
    if Scope == Unchanged:  Roundup( Minimum(Impact + Exploitability, 10) )
    if Scope == Changed:    Roundup( Minimum(1.08 × (Impact + Exploitability), 10) )
```

**Note on exponent:** The exponent in the Scope Changed Impact formula is **15** (not 13 — that applies only to Environmental).

---

## 7.2 Temporal Score Equation

```
TemporalScore = Roundup(BaseScore × E × RL × RC)
```

Where E, RL, RC use their multiplier values (all default to 1.0 = Not Defined).

---

## 7.3 Environmental Score Equations

```
MISS = Minimum(
    1 - [ (1 - CR × MC) × (1 - IR × MI) × (1 - AR × MA) ],
    0.915
)

ModifiedImpact =
    if ModifiedScope == Unchanged:  6.42 × MISS
    if ModifiedScope == Changed:    7.52 × (MISS - 0.029) - 3.25 × (MISS × 0.9731 - 0.02)^13

ModifiedExploitability = 8.22 × MAV × MAC × MPR × MUI

EnvironmentalScore =
    if ModifiedImpact <= 0:  0.0
    if ModifiedScope == Unchanged:
        Roundup( Roundup[ Minimum(ModifiedImpact + ModifiedExploitability, 10) ]
                 × E × RL × RC )
    if ModifiedScope == Changed:
        Roundup( Roundup[ Minimum(1.08 × (ModifiedImpact + ModifiedExploitability), 10) ]
                 × E × RL × RC )
```

**Key difference from Base:** Environmental uses exponent **13**, double-Roundup, and MISS is capped at 0.915.

**Modified metrics fallback:** When a Modified metric = Not Defined (X), use the corresponding Base metric value.

---

## 7.4 Metric Numerical Values

### Attack Vector (AV) / Modified Attack Vector (MAV)
| Value | Constant |
|-------|----------|
| Network (N) | 0.85 |
| Adjacent (A) | 0.62 |
| Local (L) | 0.55 |
| Physical (P) | 0.20 |

### Attack Complexity (AC) / Modified Attack Complexity (MAC)
| Value | Constant |
|-------|----------|
| Low (L) | 0.77 |
| High (H) | 0.44 |

### Privileges Required (PR) / Modified Privileges Required (MPR)
| Value | Scope Unchanged | Scope Changed |
|-------|----------------|---------------|
| None (N) | 0.85 | 0.85 |
| Low (L) | 0.62 | 0.68 |
| High (H) | 0.27 | 0.50 |

### User Interaction (UI) / Modified User Interaction (MUI)
| Value | Constant |
|-------|----------|
| None (N) | 0.85 |
| Required (R) | 0.62 |

### Confidentiality / Integrity / Availability (C/I/A and MC/MI/MA)
| Value | Constant |
|-------|----------|
| High (H) | 0.56 |
| Low (L) | 0.22 |
| None (N) | 0.00 |

### Exploit Code Maturity (E)
| Value | Multiplier |
|-------|------------|
| Not Defined (X) | 1.00 |
| High (H) | 1.00 |
| Functional (F) | 0.97 |
| Proof-of-Concept (P) | 0.94 |
| Unproven (U) | 0.91 |

### Remediation Level (RL)
| Value | Multiplier |
|-------|------------|
| Not Defined (X) | 1.00 |
| Unavailable (U) | 1.00 |
| Workaround (W) | 0.97 |
| Temporary Fix (T) | 0.96 |
| Official Fix (O) | 0.95 |

### Report Confidence (RC)
| Value | Multiplier |
|-------|------------|
| Not Defined (X) | 1.00 |
| Confirmed (C) | 1.00 |
| Reasonable (R) | 0.96 |
| Unknown (U) | 0.92 |

### Confidentiality/Integrity/Availability Requirement (CR/IR/AR)
| Value | Multiplier |
|-------|------------|
| Not Defined (X) | 1.00 |
| High (H) | 1.50 |
| Medium (M) | 1.00 |
| Low (L) | 0.50 |

---

## Worked Example

**Vulnerability:** Remote code execution, no auth, Scope Unchanged, all impacts High.

```
Metrics: AV=N(0.85), AC=L(0.77), PR=N(0.85), UI=N(0.85), S=U, C=H(0.56), I=H(0.56), A=H(0.56)

ISS = 1 - [(1-0.56)(1-0.56)(1-0.56)]
    = 1 - [0.44 × 0.44 × 0.44]
    = 1 - 0.085184
    = 0.914816

Impact = 6.42 × 0.914816 = 5.873...   (Scope Unchanged)

Exploitability = 8.22 × 0.85 × 0.77 × 0.85 × 0.85
              = 8.22 × 0.472...
              = 3.887...

BaseScore = Roundup(min(5.873 + 3.887, 10))
          = Roundup(min(9.760, 10))
          = Roundup(9.760)
          = 9.8
```

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Score:** 9.8 Critical ✓
