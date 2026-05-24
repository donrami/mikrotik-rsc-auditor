#!/usr/bin/env python3
"""
MikroTik RouterOS .rsc Conflict Explanations
=============================================
User-friendly companion module for the conflict analyzer. Provides structured
explanations per conflict type: "what is happening", "why it's problematic",
and "how to fix" with side-effect warnings.

Usage:
    from conflict_explanations import get_explanation, get_fix_guide
    from conflict_analyzer import ConflictType

    explanation = get_explanation(ConflictType.DUPLICATE_RULE)
    print(explanation["what_is_happening"])
    print(explanation["how_to_fix"])

    # Get guidance for a specific conflict result
    guide = get_fix_guide(conflict_type, details)
"""

from typing import Any, Dict, List, Optional
from .conflict_analyzer import ConflictType


# ═══════════════════════════════════════════════════════════════════════════
# Explanation Database
# ═══════════════════════════════════════════════════════════════════════════


CONFLICT_EXPLANATIONS: Dict[ConflictType, Dict[str, Any]] = {
    ConflictType.UNREACHABLE_RULE: {
        "title": "Unreachable Firewall Rule",
        "what_is_happening": (
            "A firewall rule has been placed after a 'catch-all' rule (a rule with "
            "action=drop, accept, or reject and no filtering conditions like "
            "src-address, dst-address, protocol, or port). In RouterOS, firewall "
            "rules are evaluated top-to-bottom. The first matching rule's action "
            "is executed and processing stops. Since the catch-all rule matches "
            "every packet that reaches it, any rules placed after it can never "
            "be evaluated — they are effectively dead code."
        ),
        "why_problematic": (
            "These unreachable rules create a false sense of security. An "
            "administrator might believe a specific allow/deny rule is protecting "
            "a service, but the catch-all above it either accepts or drops all "
            "traffic first, making the later rule irrelevant. This is also "
            "wasteful — the router still parses and loads these rules into "
            "memory even though they will never match.\n\n"
            "Common mistakes that cause this:\n"
            "1. Adding new rules AFTER the default drop rule at the bottom\n"
            "2. Importing a ruleset that appends rules instead of inserting them\n"
            "3. Misunderstanding that RouterOS processes rules top-to-bottom"
        ),
        "how_to_fix": (
            "1. Move all rules BEFORE the catch-all rule.\n"
            "2. Use the 'move' command to reorder rules:\n"
            "   /ip firewall filter move [find comment=\"specific-rule\"] \\\n"
            "       [find comment=\"catch-all-rule\"]\n"
            "3. Alternatively, remove rules that are completely superseded.\n"
            "4. The catch-all should be the LAST rule in the chain (default policy)."
        ),
        "side_effects": (
            "Moving rules before the catch-all changes the firewall behavior. "
            "Traffic that was previously matched by the catch-all may now match "
            "a more specific rule and be handled differently. Always test with "
            "a backup connection before reordering production firewall rules."
        ),
        "prevention": (
            "Always add new rules using 'place-before' to insert before the "
            "catch-all, or use the move command. Keep a consistent rule numbering "
            "scheme where the default drop/accept is always the last rule."
        ),
    },

    ConflictType.NAT_BYPASSES_FIREWALL: {
        "title": "NAT Rule Bypasses Firewall Forward Chain",
        "what_is_happening": (
            "A Destination NAT (DSTNAT) rule on the WAN interface translates "
            "incoming traffic's destination address from a public IP to an "
            "internal IP address (e.g., 10.0.0.10). After NAT translation, "
            "the packet enters the forward chain as a new packet destined for "
            "the internal IP. If the forward chain has a default-drop policy "
            "or does not explicitly allow traffic to that internal IP, the "
            "translated packet will be dropped by the firewall before reaching "
            "its destination."
        ),
        "why_problematic": (
            "The DSTNAT rule appears to be correctly configured, but the "
            "forwarded traffic is silently dropped by the forward chain. This "
            "is a common configuration error that results in 'port forwarding "
            "not working' — the NAT rule looks correct, the router receives "
            "the packets, but the internal server never gets them.\n\n"
            "RouterOS processes traffic in this order:\n"
            "1. RAW (prerouting) → 2. Connection tracking → 3. Mangle (prerouting) "
            "→ 4. DSTNAT → 5. Forward filter → 6. Internal server\n\n"
            "Step 5 is where this conflict occurs — the forward chain must "
            "explicitly accept the post-NAT traffic."
        ),
        "how_to_fix": (
            "Add a forward-chain firewall rule to accept traffic to the "
            "internal IP that the DSTNAT forwards to:\n\n"
            "/ip firewall filter add chain=forward \\\n"
            "    dst-address=INTERNAL_IP \\\n"
            "    protocol=tcp dst-port=PORT \\\n"
            "    action=accept \\\n"
            "    comment=\"Allow DSTNAT traffic to INTERNAL_IP\"\n\n"
            "Make sure this rule is placed BEFORE any default-drop rule "
            "in the forward chain."
        ),
        "side_effects": (
            "Adding a forward accept rule opens a hole in the firewall. "
            "If the internal IP is also reachable from other internal networks "
            "(e.g., guest WiFi), they may now be able to access the forwarded "
            "service directly. Consider adding src-address or in-interface "
            "restrictions to limit access to only the WAN interface."
        ),
        "prevention": (
            "When configuring port forwarding, always add the corresponding "
            "forward accept rule at the same time. Document the relationship "
            "between NAT rules and forward rules in the comment field so they "
            "can be maintained together."
        ),
    },

    ConflictType.ORPHAN_ROUTING_MARK: {
        "title": "Orphaned Routing Mark",
        "what_is_happening": (
            "A mangle rule is configured with 'action=mark-routing' and "
            "'new-routing-mark=SOME_MARK', which tags certain packets with "
            "a routing mark. However, no static route in the routing table "
            "uses 'routing-mark=SOME_MARK'. Packets that receive this mark "
            "will fall back to the main routing table instead of being "
            "routed through the intended custom table."
        ),
        "why_problematic": (
            "The orphaned routing mark indicates either:\n"
            "1. A configuration error — the routing mark was supposed to "
            "direct traffic through a specific gateway or interface, but "
            "the route was never created or was removed.\n"
            "2. Leftover configuration — the mangle rule was kept after "
            "the custom routing was removed, adding unnecessary processing "
            "overhead.\n"
            "3. A forgotten route — a recent config change removed the route "
            "but the mangle rule was overlooked.\n\n"
            "In all cases, the traffic is not behaving as intended — it's "
            "using the default routing instead of the custom path."
        ),
        "how_to_fix": (
            "Option 1 — Add the missing route:\n"
            "/ip route add dst-address=0.0.0.0/0 \\\n"
            "    gateway=<SPECIFIC_GATEWAY> \\\n"
            "    routing-mark=SOME_MARK \\\n"
            "    comment=\"Route for SOME_MARK traffic\"\n\n"
            "Option 2 — If the mark is no longer needed, remove the "
            "mangle rules that set it:\n"
            "/ip firewall mangle remove \\\n"
            "    [find new-routing-mark=SOME_MARK]\n\n"
            "Option 3 — Review all routes to confirm:\n"
            "/ip route print where routing-mark=SOME_MARK"
        ),
        "side_effects": (
            "Adding a route with a routing mark will change the path that "
            "marked traffic takes through the network. If the mark was "
            "intended for policy-based routing (e.g., VPN traffic, guest "
            "traffic), adding the correct route restores proper behavior. "
            "However, removing the mangle rule will cause the marked traffic "
            "to use the main routing table, potentially bypassing intended "
            "traffic controls."
        ),
        "prevention": (
            "When creating policy-based routing:\n"
            "1. Create the routing table/route FIRST\n"
            "2. Add the mangle rule SECOND\n"
            "3. Use consistent naming for routing marks and table names\n"
            "4. Document the purpose of each routing mark in the comment field\n"
            "5. When removing routes, check for orphaned mangle rules"
        ),
    },

    ConflictType.INTERFACE_NOT_IN_LIST: {
        "title": "Active Interface Not in Any Interface List",
        "what_is_happening": (
            "An interface on the router is enabled and operational, but it "
            "has not been added to any named interface list (such as WAN, "
            "LAN, MGMT, or GUEST). In RouterOS, interface lists are used "
            "extensively by firewall rules (in-interface-list / "
            "out-interface-list), NAT rules, and service restrictions to "
            "group interfaces by role. An unlisted interface effectively "
            "falls through these group-based policies."
        ),
        "why_problematic": (
            "If your firewall rules use 'in-interface-list=WAN' or "
            "'out-interface-list=LAN' to control traffic flow, an unlisted "
            "interface is not matched by any of these rules. This means:\n\n"
            "1. Traffic on the unlisted interface may bypass WAN-facing "
            "firewall restrictions.\n"
            "2. The interface may not receive the intended protections "
            "(e.g., brute-force protection applied to WAN list).\n"
            "3. Security monitoring and logging based on interface lists "
            "will not capture traffic on this interface.\n\n"
            "This is especially dangerous if a new WAN interface (e.g., "
            "LTE failover, secondary ISP link) was added but not assigned "
            "to the WAN list, leaving it unprotected."
        ),
        "how_to_fix": (
            "1. Identify the interface's role (WAN, LAN, MGMT, etc.)\n"
            "2. Add it to the appropriate interface list:\n\n"
            "/interface list member add \\\n"
            "    list=<LIST_NAME> \\\n"
            "    interface=<INTERFACE_NAME> \\\n"
            "    comment=\"INTERFACE_NAME added to list\"\n\n"
            "3. Verify all interface lists are complete:\n"
            "/interface list print detail\n"
            "/interface list member print"
        ),
        "side_effects": (
            "Once added to a list, the interface becomes subject to all "
            "firewall rules that reference that list. If the interface was "
            "previously unlisted and traffic was passing freely, adding it "
            "to the WAN list may suddenly block traffic that was previously "
            "allowed. Conversely, adding it to the LAN list may open up "
            "access that was previously blocked."
        ),
        "prevention": (
            "When adding a new interface to RouterOS:\n"
            "1. Immediately assign it to the correct interface list(s)\n"
            "2. Use a provisioning script that enforces list membership\n"
            "3. Periodically audit: /interface list member print\n"
            "4. Consider using interface-list-based firewall rules exclusively, "
            "rather than rules tied to specific interface names"
        ),
    },

    ConflictType.ADDRESS_LIST_CONFLICT: {
        "title": "Address List Conflict — Same IP in Both Allow and Block Lists",
        "what_is_happening": (
            "The same IP address (or subnet) appears in two or more firewall "
            "address lists that have opposite purposes — one list is intended "
            "to allow or whitelist the address, while another list is intended "
            "to block or blacklist it. The router's behavior depends entirely "
            "on which list-referencing rule is processed first in the firewall "
            "filter chain, creating an ambiguous security posture."
        ),
        "why_problematic": (
            "This is a configuration contradiction that creates uncertainty "
            "about which policy is actually enforced:\n\n"
            "1. The actual behavior depends on the order of rules that "
            "reference these lists — the first matching rule wins.\n"
            "2. If rules are reordered (via import or manual change), "
            "the effective policy can silently flip.\n"
            "3. This often indicates stale data — an IP was added to a "
            "block list, but was already in an allow list, or vice versa.\n"
            "4. During troubleshooting, this ambiguity wastes time and "
            "may lead to incorrect conclusions.\n\n"
            "The IP is essentially both trusted and untrusted simultaneously, "
            "which defeats the purpose of either classification."
        ),
        "how_to_fix": (
            "1. Decide whether the IP should be allowed or blocked.\n"
            "2. Remove it from the less-important list:\n\n"
            "/ip firewall address-list remove \\\n"
            "    [find where=address=CONFLICTED_IP \\\n"
            "    list=LIST_TO_REMOVE_FROM]\n\n"
            "3. Or, if firewall rules reference these lists, review which "
            "rule order gives the intended behavior:\n\n"
            "/ip firewall filter print \\\n"
            "    where src-address-list=ALLOW_LIST or \\\n"
            "    dst-address-list=BLOCK_LIST\n\n"
            "4. Consider using a unified address list scheme where addresses "
            "are never added to both allow and block lists."
        ),
        "side_effects": (
            "Removing an address from a list will change firewall behavior "
            "for that address. If the now-unlisted IP was being blocked by "
            "the block list and the allow list rule comes first, removing "
            "it from the block list has no effect (the allow still takes "
            "precedence). If the block list rule comes first, removing it "
            "from the allow list means it becomes blocked."
        ),
        "prevention": (
            "1. Use a single 'trusted' list and a single 'blocked' list — "
            "never create multiple overlapping lists.\n"
            "2. Before adding an IP to any list, check if it already exists:\n"
            "   /ip firewall address-list find where address=X.X.X.X\n"
            "3. Use configuration management that prevents contradictory "
            "address-list assignments.\n"
            "4. Implement a periodic audit to detect address list overlaps."
        ),
    },

    ConflictType.FORWARD_WITHOUT_FASTTRACK: {
        "title": "Many Forward Rules Without FastTrack",
        "what_is_happening": (
            "The firewall's forward chain has several rules configured, but "
            "there is no FastTrack rule to accelerate established connections. "
            "FastTrack is a RouterOS feature that bypasses the normal firewall "
            "processing (filter, mangle, connection tracking) for packets "
            "belonging to established connections by offloading them to a "
            "fast path in the kernel."
        ),
        "why_problematic": (
            "Without FastTrack, every packet traversing the router must go "
            "through the full firewall processing pipeline:\n\n"
            "1. RAW table check\n"
            "2. Connection tracking lookup/creation\n"
            "3. Mangle table (prerouting)\n"
            "4. NAT table (if applicable)\n"
            "5. Forward chain — all rules evaluated\n"
            "6. Mangle table (postrouting)\n"
            "7. NAT table (srcnat)\n\n"
            "On high-throughput links (500 Mbps+), this can cause:\n"
            "- Significant CPU overhead\n"
            "- Reduced maximum throughput\n"
            "- Higher latency due to processing delays\n"
            "- Potential packet drops under load\n\n"
            "Note: FastTrack is NOT compatible with:\n"
            "- Queue trees (per-connection queuing)\n"
            "- Mangle rules (all packets bypass mangle)\n"
            "- Parent queues in simple queues\n"
            "- Packet and connection marking"
        ),
        "how_to_fix": (
            "Add a FastTrack rule as the FIRST rule in the forward chain:\n\n"
            "/ip firewall filter add chain=forward \\\n"
            "    connection-state=established,related \\\n"
            "    action=fasttrack-connection \\\n"
            "    comment=\"FastTrack established/related\"\n\n"
            "This rule must appear before any other forward rules that "
            "you want to apply to new connections only. Established "
            "connections will be fast-tracked and skip the rest of "
            "the forward chain."
        ),
        "side_effects": (
            "WARNING: FastTrack has significant implications:\n\n"
            "1. Mangle rules are bypassed — any connection marking, routing "
            "marking, or packet marking will NOT apply to fast-tracked packets.\n"
            "2. Queue trees do not work — per-connection queuing is disabled "
            "for fast-tracked traffic.\n"
            "3. Connection tracking accounting is skipped — traffic statistics "
            "may show lower byte counts.\n"
            "4. If you need mangle or per-connection QoS, place the FastTrack "
            "rule with specific exclusions, or don't use FastTrack.\n"
            "5. Simple queues still work (they intercept before FastTrack)."
        ),
        "prevention": (
            "Only use FastTrack if:\n"
            "- You don't need per-connection queuing (queue trees)\n"
            "- You don't use mangle rules for traffic management\n"
            "- Your primary concern is throughput, not traffic shaping\n"
            "- You have high-bandwidth links (>100 Mbps)\n\n"
            "If you need mangle + FastTrack, add exclusion rules before "
            "the FastTrack rule to exclude specific traffic types."
        ),
    },

    ConflictType.SHADOWED_RULE: {
        "title": "Shadowed Firewall Rule",
        "what_is_happening": (
            "A firewall rule with broad matching conditions is placed before "
            "a more specific rule in the same chain. For example, a rule "
            "accepting all TCP traffic on ports 80-1000 shadows a later "
            "rule that specifically allows port 443 traffic — the port 443 "
            "rule is never reached because the broader rule already matches "
            "it. The shadowed rule (the specific one) will never be evaluated "
            "because the broader rule above it matches all of the same traffic."
        ),
        "why_problematic": (
            "Shadowed rules are a common misconfiguration that causes:\n\n"
            "1. Security illusions — you think a specific rule is blocking "
            "or allowing certain traffic, but a broader rule above it "
            "overrides your intention.\n"
            "2. Troubleshooting red herrings — when investigating why a "
            "certain service doesn't work, you see the correct rule in "
            "the chain, but don't notice it's shadowed by an earlier rule.\n"
            "3. Wasted resources — the router evaluates both rules, but "
            "the second is never used.\n"
            "4. Compliance issues — audit logs show the expected rule exists, "
            "but it has no effect.\n\n"
            "This is particularly dangerous when a broad 'allow all' rule "
            "shadows a specific 'deny' rule, or vice versa."
        ),
        "how_to_fix": (
            "1. Reorder rules so specific rules come BEFORE broad rules:\n\n"
            "/ip firewall filter move \\\n"
            "    [find comment=\"SPECIFIC_RULE\"] \\\n"
            "    [find comment=\"BROAD_RULE\"]\n\n"
            "This moves the specific rule before the broad one.\n\n"
            "2. Alternatively, if the shadowed rule is redundant, remove it:\n\n"
            "/ip firewall filter remove \\\n"
            "    [find comment=\"SHADOWED_RULE\"]\n\n"
            "3. Consider merging both rules into a single comprehensive rule."
        ),
        "side_effects": (
            "Reversing the order changes firewall behavior. Traffic that was "
            "previously hitting the broad rule first may now match a more "
            "specific rule with a different action. For example, if a broad "
            "'allow all' was shadowing a specific 'block', reversing them "
            "will block the specific traffic. Always verify with a test "
            "connection before changing production firewall rule order."
        ),
        "prevention": (
            "1. Follow the principle: most specific → most general\n"
            "2. Place host-specific rules before network-wide rules\n"
            "3. Place explicit exceptions before broad policies\n"
            "4. Use rule comments to document the logic\n"
            "5. Periodically audit rule order for shadowing"
        ),
    },

    ConflictType.DUPLICATE_RULE: {
        "title": "Duplicate Firewall/NAT/Mangle Rule",
        "what_is_happening": (
            "Two or more rules in the same chain have identical match "
            "parameters — same source, destination, protocol, ports, "
            "interfaces, connection state, and action. The only differences "
            "are typically in the comment or order. One of these rules is "
            "completely redundant: the first one matches the traffic and "
            "the second never executes (RouterOS stops processing rules "
            "after the first match)."
        ),
        "why_problematic": (
            "Duplicate rules are problematic because:\n\n"
            "1. They waste hardware resources — each rule consumes TCAM "
            "space in hardware-accelerated firewalls.\n"
            "2. On devices with limited rule capacity (e.g., hAP ac² with "
            "limited flash), every duplicate reduces available capacity.\n"
            "3. They make the ruleset harder to read and maintain — "
            "troubleshooters may wonder if the second rule is intentional.\n"
            "4. They can cause confusion when counting rules or setting up "
            "log analysis.\n"
            "5. Duplicates often accumulate when configuration management "
            "scripts lack idempotency guards (adding rules without checking "
            "if they already exist).\n\n"
            "While RouterOS can handle duplicates without breaking anything, "
            "they indicate poor configuration hygiene."
        ),
        "how_to_fix": (
            "Remove the duplicate rule(s). Keep only the first occurrence:\n\n"
            "/ip firewall filter remove [find comment=\"DUPLICATE_RULE\"]\n\n"
            "Or, to be safe, disable the duplicate first and verify:\n\n"
            "/ip firewall filter set \\\n"
            "    [find comment=\"SECOND_RULE\"] disabled=yes\n\n"
            "If no breakage occurs after a monitoring period, remove it."
        ),
        "side_effects": (
            "Removing a duplicate is safe because the first occurrence already "
            "handles the traffic. However, if the ruleset uses 'move' or "
            "position-based operations (e.g., /ip firewall filter print shows "
            "rule numbers), removing a rule will renumber all subsequent rules. "
            "Any scripts or documentation referencing rule numbers will break."
        ),
        "prevention": (
            "1. Use idempotent configuration scripts that check for existing "
            "rules before adding new ones:\n"
            ":if ([/ip firewall filter find where=...] = {}) do={\n"
            "    /ip firewall filter add ...\n"
            "}\n"
            "2. Use rule comments for identification\n"
            "3. Periodically audit with: /ip firewall filter print count-only\n"
            "4. Never use 'add' commands in scheduler scripts without guards\n"
            "5. When importing configurations, clean up duplicates first"
        ),
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════


def get_explanation(conflict_type: ConflictType) -> Optional[Dict[str, Any]]:
    """Get the full explanation dict for a conflict type.
    
    Args:
        conflict_type: A ConflictType enum value
    
    Returns:
        Dict with keys: title, what_is_happening, why_problematic,
        how_to_fix, side_effects, prevention. Returns None if type
        is unknown.
    """
    return CONFLICT_EXPLANATIONS.get(conflict_type)


def get_fix_guide(
    conflict_type: ConflictType,
    details: str = "",
) -> Dict[str, str]:
    """Get a concise fix guide for a conflict type with optional context.
    
    Args:
        conflict_type: The conflict type to get guidance for
        details: Optional additional context (e.g., specific IP, port, rule)
    
    Returns:
        Dict with "summary", "fix_steps", and "warning" keys
    """
    explanation = get_explanation(conflict_type)
    if not explanation:
        return {
            "summary": f"Unknown conflict type: {conflict_type}",
            "fix_steps": "Refer to RouterOS documentation.",
            "warning": "",
        }

    fix_steps = explanation["how_to_fix"]
    if details:
        fix_steps = f"Context: {details}\n\n{fix_steps}"

    return {
        "summary": explanation["how_to_fix"].split("\n")[0],
        "fix_steps": fix_steps,
        "warning": explanation["side_effects"],
    }


def get_all_titles() -> Dict[str, str]:
    """Get a mapping of conflict type values to human-readable titles."""
    return {
        ct.value: CONFLICT_EXPLANATIONS[ct]["title"]
        for ct in ConflictType
        if ct in CONFLICT_EXPLANATIONS
    }


def get_type_by_title(title: str) -> Optional[ConflictType]:
    """Look up a ConflictType by its title string (case-insensitive)."""
    title_lower = title.lower()
    for ct, exp in CONFLICT_EXPLANATIONS.items():
        if exp["title"].lower() == title_lower:
            return ct
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Quick Reference
# ═══════════════════════════════════════════════════════════════════════════

QUICK_REFERENCE: Dict[str, str] = {
    ConflictType.UNREACHABLE_RULE.value: (
        "Move specific rules before catch-all rules. Use 'move' command."
    ),
    ConflictType.NAT_BYPASSES_FIREWALL.value: (
        "Add forward-chain accept rule for DSTNAT target IP."
    ),
    ConflictType.ORPHAN_ROUTING_MARK.value: (
        "Add route with routing-mark, or remove orphaned mangle rule."
    ),
    ConflictType.INTERFACE_NOT_IN_LIST.value: (
        "Add interface to appropriate WAN/LAN/MGMT interface list."
    ),
    ConflictType.ADDRESS_LIST_CONFLICT.value: (
        "Remove the IP from one of the conflicting allow/block lists."
    ),
    ConflictType.FORWARD_WITHOUT_FASTTRACK.value: (
        "Add FastTrack rule as first forward rule (if compatible with your setup)."
    ),
    ConflictType.SHADOWED_RULE.value: (
        "Reorder rules: specific rules before broad rules."
    ),
    ConflictType.DUPLICATE_RULE.value: (
        "Remove duplicate rules. Use idempotent add patterns."
    ),
}


def quick_fix(conflict_type: ConflictType) -> str:
    """Get a one-line quick fix suggestion."""
    return QUICK_REFERENCE.get(conflict_type.value, "No quick fix available.")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Print all conflict explanations to stdout."""
    import argparse

    parser = argparse.ArgumentParser(
        description="MikroTik RouterOS Conflict Explanations — Reference Guide",
    )
    parser.add_argument(
        "--type",
        help="Show explanation for a specific conflict type only",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all conflict types with titles",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Show one-line quick fixes for all types",
    )

    args = parser.parse_args()

    if args.list:
        print("Conflict Types:\n")
        for ct in ConflictType:
            exp = get_explanation(ct)
            title = exp["title"] if exp else ct.value
            print(f"  {ct.value:35s} → {title}")
        return

    if args.quick:
        print("Quick Fix Reference:\n")
        for ct in ConflictType:
            print(f"  {ct.value:35s} → {quick_fix(ct)}")
        return

    if args.type:
        try:
            ct = ConflictType(args.type.lower())
            exp = get_explanation(ct)
            if exp:
                print(f"\n{'=' * 76}")
                print(f"  {exp['title']} ({ct.value})")
                print(f"{'=' * 76}")
                print(f"\n  WHAT IS HAPPENING:\n  {exp['what_is_happening']}")
                print(f"\n  WHY IT'S PROBLEMATIC:\n  {exp['why_problematic']}")
                print(f"\n  HOW TO FIX:\n  {exp['how_to_fix']}")
                print(f"\n  SIDE EFFECTS / WARNINGS:\n  {exp['side_effects']}")
                print(f"\n  PREVENTION:\n  {exp['prevention']}")
            else:
                print(f"Unknown type: {args.type}")
        except ValueError:
            print(f"Invalid conflict type: {args.type}")
            print(f"Valid types: {', '.join(t.value for t in ConflictType)}")
        return

    # Print all
    for ct in ConflictType:
        exp = get_explanation(ct)
        if exp:
            print(f"\n{'=' * 76}")
            print(f"  {exp['title']} ({ct.value})")
            print(f"{'=' * 76}")
            print(f"\n  WHAT IS HAPPENING:\n  {exp['what_is_happening']}")
            print(f"\n  WHY IT'S PROBLEMATIC:\n  {exp['why_problematic']}")
            print(f"\n  HOW TO FIX:\n  {exp['how_to_fix']}")
            print(f"\n  SIDE EFFECTS / WARNINGS:\n  {exp['side_effects']}")


if __name__ == "__main__":
    main()
