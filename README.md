
---

# diagraph-ipfire

A minimalist, high-performance Bash utility designed to parse, map, and visualize active `iptables` (Netfilter) rule structures and execution flows native to IPFire routing environments.

**Architects:** H&M  
**Developers:** H&M and Gemini (v1.0.0) | H&M and Claude Sonnet 4.6 (v1.0.1+)

## Features

* **Global Unified Map**: Interrogates all primary Netfilter tables (`raw`, `mangle`, `nat`, `filter`, `security`) simultaneously, grouping root chains and sub-chains into clean visual clusters.
* **Packet Traversal Skeleton**: The three Netfilter packet paths (incoming, forwarded, locally generated) are overlaid as orange arrows with routing decision diamonds, following the packet flow as documented in the Linux kernel Netfilter subsystem.
* **Sequential Chain Flows**: Maps execution order within each root chain — the sub-chains are linked in the order the kernel processes them.
* **Contextual Isolation**: Generates `.dot` graph files renderable by Graphviz (`dot` tool) into high-resolution PNG assets.

## Netfilter Packet Traversal

As documented in the [Linux kernel Netfilter hooks](https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html) and the [iptables traversal reference](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html#TRAVERSINGOFTABLES), each packet traverses the Netfilter stack in a fixed order across all active tables.

### Path 1 — Incoming packet (destined for this machine)

```
NETWORK IN
  → raw/PREROUTING → mangle/PREROUTING → nat/PREROUTING
  → ◇ ROUTING DECISION  (kernel route lookup: destination is local)
  → mangle/INPUT → filter/INPUT → security/INPUT
  → LOCAL PROCESS
```

### Path 2 — Forwarded packet (transiting through the firewall)

```
NETWORK IN
  → raw/PREROUTING → mangle/PREROUTING → nat/PREROUTING
  → ◇ ROUTING DECISION  (kernel route lookup: destination requires forwarding)
  → mangle/FORWARD → filter/FORWARD → security/FORWARD
  → mangle/POSTROUTING → nat/POSTROUTING
  → NETWORK OUT
```

### Path 3 — Locally generated packet (the firewall itself originates it)

```
LOCAL PROCESS
  → raw/OUTPUT → mangle/OUTPUT → nat/OUTPUT → filter/OUTPUT → security/OUTPUT
  → ◇ ROUTING DECISION  (kernel route lookup for outgoing interface)
  → mangle/POSTROUTING → nat/POSTROUTING
  → NETWORK OUT
```

### Key points

- There are **two routing decisions**: one after PREROUTING (local vs forward) and one after OUTPUT (outgoing route selection).
- POSTROUTING is shared by both forwarded and locally-generated packets — both paths converge there before leaving the host.
- The `security` table (AppArmor/SELinux Netfilter hooks) is traversed last in INPUT, FORWARD, and OUTPUT chains. On most IPFire systems it is empty.
- `nat/PREROUTING` is where DNAT (port forwarding) is applied — before the routing decision, so the kernel sees the rewritten destination address when deciding local vs forward.

## Repository Structure

```text
diagraph-ipfire/
├── .gitattributes                    # Enforces LF line endings for shell scripts
├── .gitignore                        # Excludes volatile files and local AI context
├── bin/
│   └── ipfire_firewall_vizualizer.sh # Main script — runs on the IPFire box (root required)
└── templates/                        # Committed snapshots from live system
    ├── ipfire_unified_firewall_core197.dot
    ├── ipfire_unified_firewall_core200.dot
    └── ipfire_unified_firewall_core200_150DPI_LR.png
```

## Dependencies

**On the IPFire box** — only standard tools needed (`iptables`, `iptables-save`). No extra packages required.

**On a Linux workstation** (for PNG rendering):

```bash
sudo apt install graphviz          # Debian/Ubuntu/Mint

# Render a snapshot (LR layout recommended)
dot -Tpng -Gdpi=150 -Grankdir=LR \
    templates/ipfire_unified_firewall_core200.dot \
    -o ipfire_unified_firewall_core200_LR.png
```

## Deployment

```bash
# Push script to IPFire box
scp -p bin/ipfire_firewall_vizualizer.sh ipfire:/root/firewall_diagraph/ipfire_firewall_vizualizer.sh

# Run on the box (generates .dot; Graphviz not needed on IPFire itself)
ssh ipfire "cd /root/firewall_diagraph && bash ipfire_firewall_vizualizer.sh"

# Fetch result back for local rendering
scp ipfire:/root/firewall_diagraph/ipfire_unified_firewall_*.dot templates/
```

---
