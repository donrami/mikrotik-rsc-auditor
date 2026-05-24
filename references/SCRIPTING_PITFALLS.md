# Scripting Pitfalls — RouterOS

> Common RouterOS scripting mistakes that cause silent failures, data corruption,
> or security vulnerabilities. Each pitfall includes the problem, reproduction,
> explanation, and safe alternative.

---

## Pitfall 1: Type Coercion Dangers

**Problem:** RouterOS is weakly typed. Comparisons between different types produce
unexpected results because string comparison uses lexical ordering.

```routeros
# These ALL evaluate to TRUE — silently:
:put ("5" > 3)      # true — string "5" sorted higher than number 3
:put ("abc" > 3)     # true — any non-empty string > number
:put ("" > 0)        # false — empty string = 0
:put ("" = 0)        # true — empty string coerces to 0
```

**Impact:** Silent logic errors in conditionals, incorrect route selection,
broken firewall rules that appear to work but don't match as expected.

**Safe pattern — use explicit conversion before comparisons:**

```routeros
:local expected 3
:local value "5"

# ❌ WRONG — may produce unexpected result
:if ($value > $expected) do={ ... }

# ✅ CORRECT — explicit conversion
:if ([:tonum $value] > $expected) do={ ... }

# Type checking helper
:if ([:typeof $value] = "num") do={
  :put "Value is already numeric"
} else={
  :put "Value type: " . [:typeof $value]
  :local numVal [:tonum $value]
}
```

**Quick conversion reference:**

| Command | Input | Result | Notes |
|---------|-------|--------|-------|
| `:tonum "42"` | `"42"` | `42` | String to number |
| `:tonum "abc"` | `"abc"` | `0` | Invalid conversion returns 0 |
| `:tostr 42` | `42` | `"42"` | Number to string |
| `:toip "192.168.1.1"` | `"192.168.1.1"` | `192.168.1.1` | String to IP |
| `:toip "invalid"` | `"invalid"` | `0.0.0.0` | Invalid IP returns 0.0.0.0 |
| `:toip6 "::1"` | `"::1"` | `::1` | String to IPv6 |
| `:totime "00:05:00"` | `"00:05:00"` | `5m` | String to time |
| `:toarray "a,b,c"` | `"a,b,c"` | `{"a","b","c"}` | String (comma) to array |

---

## Pitfall 2: Closure Scoping Bug — `:set` Inside Nested `do={}`

**Problem:** In RouterOS v7, every `do={...}` block (including `:if`, `:else`,
`:foreach`, `/system script source={...}`) creates a **closure scope**.
Assigning to a global variable inside a nested scope with `:set` creates a
**new local variable** instead of updating the global.

```routeros
# ❌ WRONG — global is never updated
:global myCounter 0

:if (true) do={
  :set myCounter 5        # ← Creates NEW local myCounter, does NOT update global
}

:put ($myCounter)         # Outputs: 0 (global unchanged!)
```

**Why this happens:** The `:set` command resolves variables by looking at the
innermost scope first. Inside `do={...}`, the variable `myCounter` isn't declared
locally, so RouterOS creates a new local on assignment instead of climbing up
to find the global. The global `myCounter` retains its original value.

**✅ Correct pattern — re-declare `:global` inside every inner scope:**

```routeros
:global myCounter 0

:if (true) do={
  :global myCounter        # ← Re-declare (no value) to bind to the existing global
  :set myCounter 5         # ← Now updates the global
}

:put ($myCounter)          # Outputs: 5 (correct)
```

**This applies to ALL nested blocks:**

```routeros
:global counter 0

# :else block also creates a closure:
:if (false) do={
  :put "not reached"
} else={
  :global counter          # ← MUST re-declare
  :set counter 10
}

# :foreach block:
:foreach val in={1..3} do={
  :global counter          # ← MUST re-declare
  :set counter ($counter + $val)
}

# Script source block:
/system script {
  :global counter          # ← MUST re-declare  
  :set counter 100
}
```

---

## Pitfall 3: `:global` Re-declaration Inside Functions Resets the Value

**Problem:** When you call `:global myVar value` inside a function body, it
**resets** the variable to that value every time the function runs. This
destroys any accumulated state.

```routeros
# "Function" using :global do={}
:global incrementCounter do={
  :global counter 0          # ← RESETS counter to 0 every call!
  :set counter ($counter + 1)
  :return $counter
}

:put [$incrementCounter]     # Outputs: 1 (reset to 0, then +1)
:put [$incrementCounter]     # Outputs: 1 (reset to 0, then +1) — not 2!
```

**✅ Correct pattern — separate read and write declarations:**

```routeros
:global counter 0            # ← Initialize once at root scope

:global incrementCounter do={
  :global counter            # ← Read-only bind (no value = no reset)
  :set counter ($counter + 1)
  :return $counter
}

:put [$incrementCounter]     # Outputs: 1
:put [$incrementCounter]     # Outputs: 2 (correct — state preserved)
```

**Rule:**
- `:global myVar` (no value) → **read** the existing global
- `:global myVar value` (with value) → **reset** the global to that value

---

## Pitfall 4: Built-in Variable Name Collisions

**Problem:** RouterOS pre-defines several variables at the global scope.
Re-declaring them with `:local` or `:global` shadows the built-in silently.

```routeros
# Pre-defined built-in variables — DO NOT USE THESE NAMES:
#   $nothing   — represents "no value" / nil
#   $true      — boolean true
#   $false     — boolean false

# ❌ WRONG — shadows the built-in
:local nothing "my value"      # ← Shadows $nothing built-in
:local true 1                  # ← Shadows $true built-in
:local false 0                 # ← Shadows $false built-in

# Now built-in comparisons break:
:if ($nothing = nil) do={       # ← Unexpected: $nothing is now "my value", not nil
  :put "wont reach this"
}
```

**Impact:** Hard-to-diagnose bugs. Code that worked before suddenly breaks
because a variable name collision silently changes behavior. The error is not
obvious because RouterOS does not warn about shadowed variables.

**✅ Safe pattern — use descriptive, unique variable names:**

```routeros
:local itemFound false         # ← OK — 'found' not reserved
:local resultNothing ""        # ← OK — prefix avoids collision
:local isEnabled true          # ← OK — 'isEnabled' not reserved

# Prefer namespaced conventions:
:global MyScript_counter 0
:local myResult ""
:local tmpFile "backup.rsc"
```

**Reserved names to avoid:**
- `nothing`, `true`, `false`
- Any menu property name used in the current context (e.g., `name`, `comment`, `disabled`)

---

## Pitfall 5: Scheduler — Invalid Properties Cause Import Failure

**Problem:** RouterOS scheduler does **not** support several commonly assumed
properties. Importing a scheduler entry with these fails with
`expected end of command` and the entire import aborts.

```routeros
# ❌ INVALID — these properties DO NOT EXIST on /system scheduler:
#   start-delay=10s      — does not exist
#   delay=10s            — does not exist  
#   boot-delay=10s       — does not exist
#   run-after=other-task — does not exist
#   retry=3              — does not exist

# Attempting to import this causes:
#   "failure: expected end of command" at line X
```

**✅ Valid scheduler properties (RouterOS v7):**

| Property | Type | Description |
|----------|------|-------------|
| `name` | string | Unique scheduler entry name |
| `on-event` | string | Script command(s) to execute |
| `interval` | time | How often to run (e.g., `1d`, `1h`, `30m`) |
| `start-date` | date | First execution date (e.g., `2026-01-01`) |
| `start-time` | time | First execution time, or `startup` for boot-time |
| `policy` | string | Script policies (limited — see Pitfall 6) |
| `comment` | string | Description |
| `disabled` | bool | Whether entry is active |

**Workaround for boot delay:**

```routeros
# Instead of a non-existent 'boot-delay', make the script itself wait:
/system scheduler add name="delayed-start" start-time=startup on-event="
  :delay 30s
  /system script run my-boot-script
"
```

---

## Pitfall 6: Scheduler Policy Constraints

**Problem:** Scheduler and Netwatch `on-event` scripts can only use a subset
of policies. Assigning policies outside this subset has **no effect** — the
scheduler silently ignores them.

```routeros
# ❌ These policies in a scheduler on-event are SILENTLY IGNORED:
#   ftp, policy, password, sniff, sensitive, romon, api, dude, tikapp, rest-api

# Example — this script is supposed to read /user but 'policy' is ignored:
/system scheduler add name="audit-users" interval=1d \
    policy=read,write,test,policy \    # ← 'policy' ignored
    on-event="/user print"

# The script runs but /user print may fail or return nothing
# because scheduler's effective policy is only: read,write,test
```

**✅ Valid scheduler policies:**

| Policy | Effect in Scheduler |
|--------|-------------------|
| `read` | ✅ Works |
| `write` | ✅ Works |
| `test` | ✅ Works |
| `reboot` | ✅ Works |
| `ftp` | ❌ Ignored |
| `policy` | ❌ Ignored |
| `password` | ❌ Ignored |
| `sniff` | ❌ Ignored |
| `sensitive` | ❌ Ignored |
| `romon` | ❌ Ignored |
| `api` | ❌ Ignored |
| `dude` | ❌ Ignored |
| `tikapp` | ❌ Ignored |

**To run privileged scripts from scheduler:**

```routeroc
# Workaround (see Pitfall 7 for risks) — use /system script run with dont-require-permissions=yes
# on the target script (only if absolutely necessary):
/system script add name="privileged-task" \
    policy=read,write,test,policy,sensitive \
    dont-require-permissions=yes \
    source="... privileged commands ..."

# Then call from scheduler:
/system scheduler add name="run-privileged" interval=1d \
    policy=read,write,test,reboot \
    on-event="/system script run privileged-task"
```

---

## Pitfall 7: `dont-require-permissions=yes` — Privilege Escalation Risk

**Problem:** Scripts with `dont-require-permissions=yes` bypass the RouterOS
permission system entirely. Any user who can call the script (even with
read-only rights) executes commands with the script's full policy.

```routeros
# ❌ DANGEROUS — creates privilege escalation vulnerability
/system script add name="admin-task" \
    policy=read,write,test,policy,sniff,sensitive,reboot \
    dont-require-permissions=yes \
    source="/user add name=backdoor group=full password=evil"

# A read-only user can now call this and create a full-access admin:
# /system script run admin-task
```

**When to use it (rarely, with audit):**

1. **Boot-time initialization** — Scripts that run at startup before user auth
2. **CAPsMAN provisioning** — Scripts pushed to CAPs that need escalated rights
3. **Niche recovery tools** — Purpose-built scripts with explicit authentication

**✅ Safer alternatives (in order of preference):**

1. **Grant only needed policies** — Don't use `full`; enumerate exact policies
2. **Use `/user group` separation** — Create custom groups per function
3. **Audit all `dont-require-permissions=yes` scripts** — Review quarterly

```routeros
# Better: create a dedicated group with minimal permissions
/user group add name="script-executor" \
    policy=read,write,test

# Create script with that group's effective policies
/system script add name="safe-task" \
    policy=read,write,test \
    source="... commands ..."

# Users who need to run it get added to the group
/user set [find name=operator] group=script-executor
```

---

## Pitfall 8: `use-script-permissions` Behavior

**Problem:** The `use-script-permissions` parameter only takes effect when the
caller's permissions are **insufficient** for the operation. When the caller
already has sufficient permissions, the script runs under the caller's
permissions regardless of the script's own policy.

```routeros
# Script with limited permissions:
/system script add name="restricted-task" \
    policy=read,test \
    use-script-permissions=yes \
    source="..."

# Scenario A: Caller has 'read' only
#   → use-script-permissions activates, script runs 'read,test'
#   → 'write' commands in the script WILL FAIL

# Scenario B: Caller has 'full'
#   → use-script-permissions is IRRELEVANT
#   → Script runs under caller's 'full' permissions — full access granted

# Scenario C: Caller has 'read,write', script has 'read,test'
#   → use-script-permissions activates for 'test' operations
#   → Caller's 'write' still works inside the script
```

**Key insight:** `use-script-permissions=yes` is a **ceiling**, not a **cage**.
It prevents a script from executing above its declared policy, but it does not
restrict a higher-privileged caller from using the script to perform privileged
operations. The script runs with the **intersection** of caller's policies and
script's policies when `use-script-permissions=yes` is set.

**✅ Best practice:**

- Always set `use-script-permissions=yes` to prevent script privilege creep
- But do not rely on it as a security boundary against privileged users
- Use `/user group` restrictions as the primary access control

```routeros
/system script add name="user-task" \
    policy=read,test \
    use-script-permissions=yes \
    source="..."
```

---

## Pitfall 9: `:global` Variable Leakage Between Scripts

**Problem:** RouterOS `:global` variables are shared across ALL scripts running
on the device. Without naming conventions, scripts can accidentally overwrite
each other's state.

```routeros
# Script A — sets a counter:
:global counter 5
:global status "running"

# Script B — unrelated, but uses same names:
:global counter   # ← Intentionally binding to existing global
:set counter 100  # ← Oops — just corrupted Script A's state
:global status "error"  # ← Script A now sees wrong status
```

**✅ Safe pattern — namespace your globals:**

```routeros
# Use a prefix convention: $<ScriptName>_<variable>
:global BackupJob_status "ok"
:global BackupJob_counter 0
:global BackupJob_lastRun ""

# In another script:
:global HealthCheck_status "ok"     # ← Different prefix, no collision
:global BackupJob_status            # ← Explicitly referencing BackupJob's var
```

**Recommended naming convention:**

| Pattern | Example | Scope |
|---------|---------|-------|
| `$ScriptName_varName` | `$BackupJob_status` | Script-specific |
| `$ScriptName_SubName_varName` | `$BackupJob_S3_retries` | Subroutine within script |
| `$PACKAGE_varName` | `$DHCP_serverCount` | Package/feature shared state |

---

## Quick Reference: Pitfall Summary

| # | Pitfall | Symptom | Fix |
|---|---------|---------|-----|
| 1 | Type coercion | `"5" > 3` = true | Use `:tonum`, `:tostr` explicitly |
| 2 | Closure scoping | `:set` inside `do={}` doesn't update global | Re-declare `:global myVar` (no value) inside every nested block |
| 3 | Function global reset | `:global counter 0` inside function resets state | Separate init from read: declare `:global counter` without value |
| 4 | Built-in collision | `$nothing`, `$true`, `$false` shadowed | Use descriptive, unique names with prefixes |
| 5 | Invalid scheduler props | Import fails with "expected end of command" | Only use `name`, `on-event`, `interval`, `start-date`, `start-time`, `policy`, `comment`, `disabled` |
| 6 | Scheduler policy limits | Privileged commands fail in scheduler | Only `read,write,test,reboot` work; use `/system script run` for elevated tasks |
| 7 | `dont-require-permissions=yes` | Privilege escalation from read-only users | Avoid unless audited; enumerate exact policies instead |
| 8 | `use-script-permissions` misdirection | Doesn't restrict privileged callers | Use `/user group` as primary access control, not script permissions |
| 9 | Global variable leakage | Cross-script state corruption | Use prefix naming convention: `$ScriptName_varName` |
