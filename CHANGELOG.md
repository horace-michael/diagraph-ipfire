# Changelog

All notable changes to this project will be documented in this file.

## [1.5.0] - 2026-05-29

### Changed
* **Spine eliminated**: Removed shared-spine abstraction. Each dispatcher cluster
  (`cluster_INPUT_zone`, `cluster_FORWARD_zone`) now contains its FULL ordered chain
  sequence exactly matching `iptables -L` execution order.
* Chains shared between dispatchers (BADTCP, HOSTILE, etc.) are instantiated separately
  per track (`inp_HOSTILE`, `fwd_HOSTILE`) at their correct serial positions.
* TCPMSS extension target rendered at its actual FORWARD position (slot 2) instead of
  prepended before all user chains.
* Shared-chain color hint: chains whose name appears in both INPUT and FORWARD get
  `fillcolor="#FFF8DC"` (light gold) in both tracks — visual indicator without a spine.
* **TB layout adopted as default** (`rankdir=TB`): produces a 1120 × 3104px diagram at
  120dpi — readable at full width on any monitor — vs the 5500px+ LR alternative.
* Compact rendering defaults: `ranksep=0.5`, `nodesep=0.4`, `fontsize=9`, `dpi=120`.
* `junc_post` rank anchor updated to `inp_arr[fwd_len + 1]` — ensures `junc_merge →
  junc_post` is a forward arc after the full FORWARD chain sequence.
* OVPNBLOCK duplicate in FORWARD (called twice per `iptables -L`) silently deduped;

### FEATURE Changes
- **Utilities**: 
  - **Build Infrastructure Optimization**: Re-engineered `utilities/make-package.sh` build engine to output zero-dependency target distribution archives (`.tar.gz`) instead of manual installation control layers. Payload packaging formatting models to direct-deflation frameworks that preserve root deployment permission arrays (`755`/`644`) natively inside current target directory extractions.
  - **Automated QA**: automation scripts `QA_ipfire_pcb_firewall.sh` into `utilities/` container track.
- **Source Relocation**: Remapped production visualizer execution binary storage paths from `bin/` directory structures into flat `src/` project directories.

## [1.4.1] - 2026-05-29

### Changed
* Node declarations for INPUT, FORWARD, and OUTPUT tracks wrapped inside
  `subgraph cluster_*_zone` blocks — each dispatcher hook now renders as a
  dashed bounding box (green/blue/amber) enclosing its full chain sequence.
* `newrank=true` added to graph attributes so cross-cluster `{rank=same}`
  constraints are honored globally by dot.
* `junc_post` rank anchored dynamically to `inp_arr[${#out_arr[@]}]` — the
  INPUT chain one depth past the last OUTPUT chain — eliminating the same-column
  backward arc from `out_POLICYOUT`.

## [1.4.0] - 2026-05-29

### Added
* **OUTPUT dispatcher wrapper node**: `filter OUTPUT` rendered as an explicit bold amber
  wrapper box below `LOCAL PROCESS`, representing the locally-generated egress dispatcher.
* **Output chain path**: Dynamically discovers all `filter OUTPUT` user chains and extension
  targets via `get_all_targets`. Traces `LOCAL → OUTPUT_wrapper → [out chains] → junc_merge`,
  joining the POSTROUTING stage alongside the FORWARD path.
* **Dynamic dispatcher classification**: `classify_chain()` now explicitly applies to ANY
  chain (root or user-defined). INPUT, FORWARD, and OUTPUT wrapper bold/plain styling is
  determined at runtime — not hardcoded.
* **Rank alignment**: `OUTPUT_wrapper` pinned to same column as `LOCAL`; output user chains
  included in the per-index spine/branch pairing groups.

### Changed
* `CLAUDE.md`: Layout topography specifications (v2.0 blueprint) documented under
  Implementation Plan — dynamic classification profile and visual trace mappings.

## [1.3.0] - 2026-05-29

### Added
* **Dispatcher wrapper nodes**: `filter INPUT` and `filter FORWARD` rendered as explicit
  bold header boxes at the branch split, classifying them as pure dispatcher chains.
* **Extension target visibility** (`get_all_targets()`): Returns the full ordered jump list
  from a chain including extension targets (TCPMSS, CONNMARK, etc.), not just user chains.
  TCPMSS now appears inline in the FORWARD path, immediately after the FORWARD wrapper.
* **`classify_chain()`**: New helper classifies any chain as `dispatcher` (≥90% bare jumps)
  or `filter` (has match criteria). Implements the architectural distinction from CLAUDE.md.
* **ShellCheck-compliant variable declarations**: All `local` declarations separated from
  command-substitution assignments throughout `generate_pcb_map()`.

## [1.2.0] - 2026-05-29

### Added
* **PCB-style stage-based layout** (`generate_pcb_map()`): New diagram style inspired by the original 2015 IPFire FW chains diagram.
  - Stage columns: PREROUTING | INPUT/FORWARD spine | POSTROUTING, replacing the table-cluster layout.
  - Shared chains (appearing in both INPUT and FORWARD) drawn once on a grey spine; INPUT-only branches above (green), FORWARD-only below (blue).
  - `splines=ortho` with junction dots (`shape=point`) for PCB-style right-angle routing.
  - Network terminals use `shape=doubleoctagon`; dispatcher tables (mangle/nat) use `shape=ellipse`.
  - Security table omitted (empty on IPFire); footnote node added instead.

## [1.0.1] - 2026-05-28

### Fixed
* **BUG-1** `get_subchains_in_root`: Extension targets (`CONNMARK`, `TCPMSS`, `SYNPROXY`) were rendered as fake subchain nodes. Now cross-references targets against the known chain list from `iptables-save`. Critical: uses `printf "%s "` (space-separated) not `print` (newline-separated) — newlines break the awk `index()` lookup.
* **BUG-2** Duplicate node deduplication: Previous check only caught consecutive duplicates. Replaced with an associative array `seen_nodes` so non-consecutive repeats are also suppressed.
* **BUG-3** `core` variable fallback: `echo "$core"` emitted an empty string when the variable was unset. Fixed to `core="${core:-unknown}"`.
* **BUG-4** PNG output filename: Was hardcoded as `ipfire_unified_firewall.png`, losing the core version tag. Now derived as `${output%.dot}.png`.
* **BUG-5** PNG render layout: Default TB layout produced an unreadable tall column for long chains. Switched to LR with `-Grankdir=LR -Gdpi=150`.
* **FIX** `case` statement: `-h|--help` arm was unreachable because the `*` wildcard on the preceding arm matched first. Reordered.

## [1.0.0] - 2026-02-09

### Added
* **Unified Architectural Core**: Implemented memory parsing via standard `iptables-save` to map all internal Netfilter matrix locations (`raw`, `mangle`, `nat`, `filter`, `security`) simultaneously.
* **Structural Isolation Logic**: Incorporated automatic boundary isolation separating Netfilter Root chains (where runtime operational policy satisfies `!= "-"`) from transient sub-chains.
* **Deterministic Sequence Layouts**: Added execution connection tracing (`Next Flow`) layout logic mapping consecutive sub-chain actions inside identical structural blocks.
* **Cluster Subgraph Isolation**: Implemented isolated `subgraph` layout boxes categorized by runtime execution tables (`cluster_table_[name]`) utilizing unique IDs to completely circumvent node naming collisions.
* **Zero-Dependency Fallbacks**: Programmed safe fallback checks mapping structural layouts via plain text processors (`awk`/`sed`) ensuring robust runtime execution on minimalist IPFire configurations without external JSON interpreters (`jq`).
* **Visual Anchor Protection**: Configured invisible structure anchors (`anchor_[table]_[root]`) guaranteeing structural blocks generate even when parent Netfilter hooks contain zero rules.
* **Dual-Channel Syslog Output**: Enabled simultaneous terminal visibility tracking alongside native logging calls piped straight to `logger` via the `IPFIRE_VISUALIZER` subsystem tag.
