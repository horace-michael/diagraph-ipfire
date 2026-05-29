# diagraph-ipfire — Usage Guide

## Prerequisites

| Where | What |
|---|---|
| IPFire box | `iptables`, `iptables-save` (standard on all IPFire installs) |
| IPFire box | Root access (`sudo` or direct root shell) |
| Workstation | `graphviz` package (`dot` binary) |
| Workstation | `ssh` + `scp` with key-based access to the IPFire box |

Graphviz is **not** required on the IPFire box itself — only the workstation renders the image.

---

## Step 1 — Deploy the script to IPFire

Copy the visualizer from your workstation to the IPFire box:

```bash
scp -p src/ipfire_firewall_vizualizer.sh root@ipfire:/tmp/ipfire_firewall_vizualizer.sh
```

> Running from `/tmp` keeps the IPFire filesystem clean. The script writes its output to the
> current working directory, so both the script and the generated `.dot` land in `/tmp`.

---

## Step 2 — Run the script on IPFire

```bash
ssh root@ipfire "cd /tmp && bash /tmp/ipfire_firewall_vizualizer.sh"
```

The script reads the live `iptables` state (requires root) and writes a `.dot` file named after
the detected IPFire core version:

```
/tmp/ipfire_pcb_firewall_core<N>.dot
```

No network activity, no package installs, no side effects — read-only interrogation of the
running firewall state.

---

## Step 3 — Fetch the result

```bash
scp root@ipfire:/tmp/ipfire_pcb_firewall_core<N>.dot templates/
```

Replace `<N>` with the actual core number reported on the IPFire box (e.g. `core200`).

Optional cleanup on the remote box:

```bash
ssh root@ipfire "rm -f /tmp/ipfire_firewall_vizualizer.sh /tmp/ipfire_pcb_firewall_core<N>.dot"
```

---

## Step 4 — Render to PNG

Install Graphviz on the workstation if not already present:

```bash
sudo apt install graphviz          # Debian / Ubuntu / Linux Mint
sudo dnf install graphviz          # Fedora / RHEL
sudo pacman -S graphviz            # Arch
```

### Recommended: TB (top-to-bottom) layout

The TB layout renders the full Netfilter PCB chain map as a tall portrait — every stage
visible top to bottom, dispatch wrappers clearly separated, packet paths readable at a glance.
This is the recommended format.

```bash
dot -Tpng -Gdpi=120 -Grankdir=TB \
    templates/ipfire_pcb_firewall_core200.dot \
    -o ipfire_pcb_firewall_core200_TB.png
```

### Alternative: LR (left-to-right) layout

Wide landscape rendering — useful for very large rule sets or widescreen displays.

```bash
dot -Tpng -Gdpi=150 -Grankdir=LR \
    templates/ipfire_pcb_firewall_core200.dot \
    -o ipfire_pcb_firewall_core200_LR.png
```

### DPI guidance

| DPI | Use case |
|---|---|
| 72 | Quick preview |
| 120 | Standard screen / README embed |
| 150 | Detailed review, zooming in |
| 300 | Print quality |

---

## CLI reference

```
Usage: ipfire_firewall_vizualizer.sh [OPTION]

Options:
  all                          (Default) PCB-style stage layout — full inline serial per dispatcher
  filter|nat|mangle|raw|security   Per-table nested graph (single table only)
  -h | --help                  Show help and version info
  -H | --History               Show full script evolution history
```

Running with no argument is equivalent to `all` — generates the full PCB map.

---

## Automated QA pipeline (development use)

The `utilities/QA_ipfire_pcb_firewall.sh` script automates the full cycle:
deploy → run → fetch → render. Useful during active development.

```bash
bash utilities/QA_ipfire_pcb_firewall.sh ipfire
```

Where `ipfire` is the SSH host alias for the IPFire box. Defaults to `ipfire-qa` if omitted.
The rendered TB PNG is saved into `templates/` automatically.
