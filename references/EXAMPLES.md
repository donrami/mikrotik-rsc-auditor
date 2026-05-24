# EXAMPLES: Idempotent RouterOS Scripting Patterns

> Copy-paste ready patterns for common RouterOS automation tasks.
> All patterns are idempotent — running them multiple times produces the same result.
> RouterOS v7 compatible unless noted otherwise.

---

## Pattern 1: Idempotent IP Address Add

Add an IP address only if it does not already exist:

```routeros
:local ipAddr "192.168.88.1/24"
:local iface "bridge"
:local comment "lan-gateway"

:if ([:len [/ip address find where address=$ipAddr]] = 0) do={
  /ip address add address=$ipAddr interface=$iface comment=$comment
  :log info ("IP " . $ipAddr . " added to " . $iface)
} else={
  :log info ("IP " . $ipAddr . " already exists on " . $iface)
}
```

**Variation — ensure IP exists on the correct interface:**

```routeros
:local ipAddr "192.168.88.1/24"
:local iface "bridge"

:local existing [/ip address find where address=$ipAddr]
:if ([:len $existing] = 0) do={
  /ip address add address=$ipAddr interface=$iface
  :log info "Created missing IP"
} else={
  :local currentIface [/ip address get $existing interface]
  :if ($currentIface != $iface) do={
    /ip address set $existing interface=$iface
    :log info "Moved IP to correct interface"
  }
}
```

---

## Pattern 2: Idempotent Firewall Rule Add

Add a firewall rule by comment — safe to run repeatedly:

```routeros
:local ruleComment "allow-dhcp"
:local chain "input"
:local action "accept"
:local proto "udp"
:local dstPort "67-68"
:local inIface "bridge"

:if ([:len [/ip firewall filter find where comment=$ruleComment]] = 0) do={
  /ip firewall filter add chain=$chain protocol=$proto dst-port=$dstPort \
      in-interface=$inIface action=$action comment=$ruleComment
  :log info ("Firewall rule '" . $ruleComment . "' created")
} else={
  :log info ("Firewall rule '" . $ruleComment . "' already exists")
}
```

**Ensuring rule order with `place-before`:**

```routeroc
:local ruleComment "allow-established"
:if ([:len [/ip firewall filter find where comment=$ruleComment]] = 0) do={
  /ip firewall filter add chain=$chain connection-state=established,related \
      action=$action comment=$ruleComment place-before=0
  :log info "Created established/related rule at top of chain"
}
```

---

## Pattern 3: Single-Instance Guard Using `:jobname`

Prevent a scheduled script from running multiple overlapping instances:

```routeros
:local scriptName "backup-job"

# Count how many instances of this script are already running
:local instanceCount [:len [/system script job find where jobname=$scriptName]]

:if ($instanceCount > 1) do={
  :log warning ("Backup script already running — skipping this instance")
  :error "Already running"
}

# ── Script body below ──
:log info "Backup script starting..."
:do {
  /system backup save name=($scriptName . "-" . [/system clock get date])
  :log info "Backup completed successfully"
} on-error={
  :log error "Backup failed"
}
```

**Scheduler that uses this guard:**

```routeros
/system scheduler add name=backup-runner interval=1d start-time=03:00 \
    policy=read,write,test,reboot \
    on-event="/system script run backup-job"
```

---

## Pattern 4: Import with Dry-Run + `:onerror` (3-Pass Validation)

Safe import workflow for RouterOS 7.16+:

```routeros
# Pass 1: Syntax validation with dry-run
:local importFile "config.rsc"
:local dryRunOk false

:do {
  import $importFile verbose=yes dry-run
  :set dryRunOk true
  :log info ("Dry-run PASSED for " . $importFile)
} on-error={
  :log error ("Dry-run FAILED for " . $importFile . " — fix syntax errors first")
  :error "Import aborted due to syntax errors"
}

# Pass 2: Apply with on-error parameter (catches import-level errors)
:if ($dryRunOk) do={
  :do {
    :do { import $importFile } on-error={
      :log error ("Import FAILED for " . $importFile)
    }
    :log info ("Import completed for " . $importFile)
  } on-error={
    :log error ("CRITICAL: Import threw unexpected error for " . $importFile)
  }
}
```

**For RouterOS < 7.16 (using `:onerror` wrapper):**

```routeros
:local importFile "config.rsc"

:onerror err in={
  import $importFile
} do={
  :if ($err = "") do={
    :log info ("Import completed for " . $importFile)
  } else={
    :log error ("Import FAILED for " . $importFile . ": " . $err)
  }
}
```

---

## Pattern 5: Retry with Error Handling

Retry a command up to 3 times with exponential backoff:

```routeros
:local maxRetries 3
:local retryDelay 5
:local attempt 1
:local success false

:while ($attempt <= $maxRetries && !$success) do={
  :do {
    /tool fetch url="https://example.com/config.rsc" dst-path=config.rsc
    :set success true
    :log info ("Fetch succeeded on attempt " . $attempt)
  } on-error={
    :if ($attempt < $maxRetries) do={
      :log warning ("Attempt " . $attempt . " failed — retrying in " . \
          $retryDelay . "s")
      :delay $retryDelay
      :set retryDelay ($retryDelay * 2)
    } else={
      :log error ("All " . $maxRetries . " attempts failed")
      :error "Fetch failed after all retries"
    }
  }
  :set attempt ($attempt + 1)
}
```

---

## Pattern 6: Remove by `find where` (Avoid Numeric IDs)

Safe removal using named attributes instead of fragile numeric indices:

```routeroc
# GOOD — remove by comment
:local ruleComment "old-rule-v1"
/ip firewall filter remove [find where comment=$ruleComment]

# GOOD — remove by address
/ip address remove [find where address="192.168.88.100/24"]

# GOOD — remove by name
/interface bridge port remove [find where interface="ether5"]

# BAD — fragile, breaks after any add/remove
/ip firewall filter remove 3

# BAD — unsafe bulk remove
/ip firewall filter remove [find]
```

**Safe bulk remove with explicit where filter:**

```routeros
# Remove ALL firewall rules with a specific prefix comment
:foreach rule in=[/ip firewall filter find where comment~"^temp-"] do={
  /ip firewall filter remove $rule
  :log info ("Removed temporary rule: " . $rule)
}
```

---

## Pattern 7: Scheduler Entry with Correct Properties

Correct scheduler configuration — note what properties are NOT supported:

```routeros
# ✅ VALID — these properties work
/system scheduler add name="daily-check" \
    interval=1d \
    start-date=2026-01-01 \
    start-time=03:00 \
    policy=read,write,test,reboot \
    on-event="/system script run daily-check" \
    disabled=no

# ✅ Run on boot
/system scheduler add name="on-boot-fix" \
    start-time=startup \
    on-event="/system script run boot-fix"

# ⚠ INVALID properties — DO NOT USE
# These will cause "expected end of command" import error:
# /system scheduler add ... delay=10s               ← DOES NOT EXIST
# /system scheduler add ... start-delay=10s         ← DOES NOT EXIST  
# /system scheduler add ... boot-delay=10s          ← DOES NOT EXIST
# /system scheduler add ... run-after=other-task    ← DOES NOT EXIST

# ✅ Workaround for startup delay: make the script itself wait
:delay 30s  # Wait for DHCP/PPPoE before proceeding
```

**Policy constraints for scheduler on-event scripts:**

```routeros
# Scheduler/Netwatch only accept these policies:
# read, write, test, reboot
# 
# Other policies (ftp, policy, password, sniff, sensitive, romon)
# are silently ignored — they have no effect in scheduler context.
```

---

## Pattern 8: Idempotent DHCP Server Config

Set up a DHCP server only if one does not already exist for the interface:

```routeros
:local dhcpIface "bridge"
:local dhcpPool "default-dhcp"
:local dhcpNet "192.168.88.0/24"
:local dhcpGateway "192.168.88.1"
:local dhcpRange "192.168.88.10-192.168.88.254"

# Create pool if missing
:if ([:len [/ip pool find where name=$dhcpPool]] = 0) do={
  /ip pool add name=$dhcpPool ranges=$dhcpRange
  :log info ("DHCP pool " . $dhcpPool . " created")
}

# Add network if missing
:if ([:len [/ip dhcp-server network find where address=$dhcpNet]] = 0) do={
  /ip dhcp-server network add address=$dhcpNet gateway=$dhcpGateway \
      dns-server=$dhcpGateway
  :log info ("DHCP network " . $dhcpNet . " configured")
}

# Add DHCP server if missing for this interface
:if ([:len [/ip dhcp-server find where interface=$dhcpIface]] = 0) do={
  /ip dhcp-server add interface=$dhcpIface address-pool=$dhcpPool \
      name=($dhcpIface . "-dhcp") authoritative=yes lease-time=1h
  :log info ("DHCP server created on " . $dhcpIface)
} else={
  :log info ("DHCP server already exists on " . $dhcpIface)
}
```

---

## Pattern 9: Idempotent Route Add with Health Check

Add a default route with gateway health monitoring:

```routeros
:local gw "192.168.1.1"
:local dst "0.0.0.0/0"
:local comment "default-wan"

:if ([:len [/ip route find where dst-address=$dst gateway=$gw]] = 0) do={
  /ip route add dst-address=$dst gateway=$gw check-gateway=ping \
      distance=1 comment=$comment
  :log info ("Default route via " . $gw . " created")
} else={
  :log info ("Default route via " . $gw . " already exists")
}

# Add backup route with higher distance
:local backupGw "10.10.10.1"
:if ([:len [/ip route find where dst-address=$dst gateway=$backupGw]] = 0) do={
  /ip route add dst-address=$dst gateway=$backupGw check-gateway=ping \
      distance=2 comment="default-backup"
  :log info ("Backup route via " . $backupGw . " created")
}

# For faster failover, configure BFD (v7.14+)
/routing bfd interface add interface=ether1 min-tx=100 min-rx=100 multiplier=3
```

---

## Pattern 10: Idempotent Bridge VLAN Configuration

Configure bridge VLAN filtering without duplicates:

```routeros
:local bridgeName "bridge"
:local vlanId 20
:local taggedPorts "ether1"
:local untaggedPorts "ether2,ether3"

# Enable VLAN filtering on bridge (safe to run repeatedly)
/interface bridge set $bridgeName vlan-filtering=yes

# Add VLAN entry if missing
:local vlanEntry [/interface bridge vlan find where \
    bridge=$bridgeName vlan-ids=$vlanId]

:if ([:len $vlanEntry] = 0) do={
  /interface bridge vlan add bridge=$bridgeName vlan-ids=$vlanId \
      tagged=$taggedPorts untagged=$untaggedPorts
  :log info ("Bridge VLAN " . $vlanId . " configured")
} else={
  # Update existing VLAN entry if ports changed
  /interface bridge vlan set $vlanEntry \
      tagged=$taggedPorts untagged=$untaggedPorts
  :log info ("Bridge VLAN " . $vlanId . " updated")
}

# Set PVID on access ports (idempotent — setting same value is safe)
:foreach port in=[/interface bridge port find where interface~"ether[2-3]"] do={
  /interface bridge port set $port pvid=$vlanId
}
```

---

## Appendix: Quick Reference — Guard Pattern Template

General template for idempotent add operations:

```routeros
:local itemId [/path/to/menu find where unique-field="target-value"]

:if ([:len $itemId] = 0) do={
  /path/to/menu add field1=value1 field2=value2 \
      comment="descriptive-label"
  :log info "Item created"
} else={
  :log info "Item already exists"
  # Optional: update existing
  # /path/to/menu set $itemId field1=new-value
}
```

**Key principles:**
- Always use `find where` with a stable attribute (comment, name, address)
- Never use numeric indices — they change when items are added/removed
- Use `:if ([:len [... find where ...]] = 0) do={ add ... }` for idempotency
- Add `:log` statements for audit trail
- Wrap critical operations in `:do { ... } on-error={ ... }` for error handling
- Use `:jobname` in scheduled scripts to prevent overlapping executions
