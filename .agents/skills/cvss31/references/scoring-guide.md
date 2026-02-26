# CVSS v3.1 Metric Selection Guide

Source: https://www.first.org/cvss/v3.1/user-guide

---

## Scope (S) — Most Impactful Decision

Scope determines which Impact formula is used and affects PR weights. Decide this FIRST.

**Unchanged (U):** Impact is limited to the vulnerable component itself.
- Example: A web app is vulnerable; only that web app's data is affected.

**Changed (C):** A successful exploit can affect components beyond the vulnerable component.
- Example: A hypervisor vulnerability that allows a VM to affect the host OS.
- Example: XSS where the vulnerable component is the web server, but the impact is in the victim's browser.
- Key indicator: Are there two distinct components? Is one exploited but the other impacted?

---

## Attack Vector (AV)

**Decision tree:**
1. Can it be exploited over the internet (remotely)? → **Network**
2. Requires same physical/logical network (Bluetooth, LAN, VLAN)? → **Adjacent**
3. Requires local OS access, SSH, or social engineering a local user? → **Local**
4. Requires physical presence/device access? → **Physical**

**Common mistakes:**
- An attack via VPN over the internet is still **Network** (not Adjacent)
- An attack requiring a user to open a malicious file locally → **Local** (social engineering)
- Server-side SSRF that needs to reach an internal service → may be **Adjacent**

---

## Attack Complexity (AC)

**Low (L):** Attacker can reliably exploit this every time. No special timing, race conditions, or information needed beyond finding the vulnerability.

**High (H):** Requires extra steps beyond control:
- Race conditions / timing windows
- Gathering specific information about target (not generally available)
- Defeating ASLR/randomized secrets
- MitM position required

**Common mistakes:**
- Authentication bypass is NOT High complexity — that's Privileges Required: None
- Specific payload crafting that's still deterministic = Low
- Needing to know a username = Low (usernames are discoverable)

---

## Privileges Required (PR)

**None (N):** No authentication required at all.

**Low (L):** Basic user-level auth required. Standard user can trigger it without elevated permissions.

**High (H):** Admin/root/privileged access required to exploit.

**Note:** PR is about privileges needed TO EXPLOIT, not the privileges gained after exploitation.

**Scope Changed interaction:** If Scope=Changed, PR weights increase (Low goes from 0.62→0.68, High from 0.27→0.50).

---

## User Interaction (UI)

**None (N):** Attacker can exploit without any victim involvement.

**Required (R):** A legitimate user (other than attacker) must perform an action:
- Click a link
- Open a file
- Visit a page
- Any active participation

**Common mistakes:**
- Admin reviewing logs that contain malicious content → Required
- Background processes that execute automatically → None

---

## Impact Metrics (C/I/A)

Score from the perspective of the **impacted component** (which may differ from the vulnerable component when Scope=Changed).

### Confidentiality (C)
**High (H):** All information disclosed, attacker can read all data, or complete loss of confidentiality.
**Low (L):** Some information disclosed but limited scope; attacker doesn't control what's leaked.
**None (N):** No confidentiality loss.

### Integrity (I)
**High (H):** Total compromise of integrity; attacker can modify any data, or critical data modification possible.
**Low (L):** Some data modification possible but limited scope or impact.
**None (N):** No integrity loss.

### Availability (A)
**High (H):** Complete denial of service; attacker can fully deny access to resource.
**Low (L):** Reduced performance or intermittent availability loss.
**None (N):** No availability impact.

**Common patterns:**
- RCE → C:H/I:H/A:H (typically)
- SQL injection (read-only) → C:H/I:N/A:N
- DoS → C:N/I:N/A:H
- XSS (session theft) → C:L/I:L/A:N or C:H/I:H/A:N depending on impact

---

## Temporal Metrics Guidance

Use these to adjust Base Score based on current threat landscape.

### When to reduce the score:
- Official patch available (RL=Official Fix): -5% of base
- No public exploit exists (E=Unproven): -9% of base
- Vendor hasn't confirmed vuln (RC=Unknown): -8% of base

### When score stays same:
- RL=Unavailable + E=High + RC=Confirmed: same as Base
- All "Not Defined" values: same as Base

**Practical use:** Temporal is useful in vulnerability management workflows to dynamically adjust priority as patches become available or exploits emerge.

---

## Environmental Metrics Guidance

Use these to customize scores for your specific environment.

### Security Requirements (CR/IR/AR)
Ask: "How important is C/I/A to my organization for this asset?"

- Database with PII → CR=High
- Internal dev tool → CR=Low
- Payment system → CR=High, IR=High, AR=High

### Modified Base Metrics
Override individual Base metrics to reflect your actual environment:

**Example:** Vulnerability is rated PR=None, but in your environment the service requires auth → set MPR=High to lower the score.

**Example:** Vendor scored AV=Local, but in your environment the service is internet-exposed → set MAV=Network to raise the score.

---

## Scoring Checklist

Before finalizing, verify:
- [ ] All 8 Base metrics assigned
- [ ] PR considered in light of Scope (if S=C, PR weights are higher)
- [ ] C/I/A scored from impacted component perspective (not vulnerable component)
- [ ] Vector string includes CVSS:3.1/ prefix
- [ ] Vector string includes all mandatory metrics
- [ ] Score falls in expected severity range for vulnerability type

---

## Vector String Format

```
CVSS:3.1/AV:[N|A|L|P]/AC:[L|H]/PR:[N|L|H]/UI:[N|R]/S:[U|C]/C:[N|L|H]/I:[N|L|H]/A:[N|L|H]
```

Optional Temporal suffix:
```
/E:[X|U|P|F|H]/RL:[X|O|T|W|U]/RC:[X|U|R|C]
```

Optional Environmental suffix:
```
/CR:[X|L|M|H]/IR:[X|L|M|H]/AR:[X|L|M|H]/MAV:[X|N|A|L|P]/MAC:[X|L|H]/MPR:[X|N|L|H]/MUI:[X|N|R]/MS:[X|U|C]/MC:[X|N|L|H]/MI:[X|N|L|H]/MA:[X|N|L|H]
```
