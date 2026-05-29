#!/bin/bash
#################################################################################
# Description: map, and visualize active iptables (Netfilter)                   #
# rule structures and execution flows                                           #
# Check CHANGELOG.md for details                                                #
#                                                                               #
# MIT License                                                                   #
#                                                                               #
# Copyright (c) 2026 H&M                                                        #
#                                                                               #
# Permission is hereby granted, free of charge, to any person obtaining a copy  #
# of this software and associated documentation files (the "Software"), to deal #
# in the Software without restriction, including without limitation the rights  #
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     #
# copies of the Software, and to permit persons to whom the Software is         #
# furnished to do so, subject to the following conditions:                      #
#                                                                               #
# The above copyright notice and this permission notice shall be included in all#
# copies or substantial portions of the Software.                               #
#                                                                               #
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    #
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      #
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   #
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        #
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, #
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE #
# SOFTWARE.                                                                     #
#################################################################################

VERSION="1.5.0 20260529"
ARCHITECT="H&M"
DEVELOPER="H&M and Gemini 3.1 (v1.0.0) | H&M and Claude Sonnet 4.6 (v1.0.1+)"
SELF=$(basename "$0")
TABLES="raw mangle nat filter security"
DEBUG=true
core=$(cut -f5 -d ' ' /etc/system-release 2>/dev/null)
core="${core:-unknown}"


HISTORY="
v1.0.0: Unified Big Picture. Root-to-Root links only. No Root-to-Subchain arrows.
v1.0.1: BUG-1 filter fake extension targets (CONNMARK/TCPMSS) from subchain list.
        BUG-2 deduplicate non-consecutive subchain nodes via associative array.
        BUG-3 core variable fallback now produces 'unknown' instead of empty string.
        BUG-4 PNG output filename now includes core version tag.
        BUG-5 PNG render switched to LR layout for readability.
        FIX   case statement: -h|--help moved before wildcard * catch-all.
v1.1.0: Netfilter packet traversal skeleton overlaid on the cluster graph.
        Adds NET_IN, NET_OUT, LOCAL PROCESS terminals and two ROUTING DECISION
        diamonds. Orange bold arrows trace the three real packet paths:
        incoming-to-local, forwarded, and locally-generated.
v1.2.0: PCB-style stage-based layout (generate_pcb_map, new default).
        Shared filter chains drawn once on a grey spine (INPUT ∩ FORWARD).
        INPUT-only branches above (green, dashed).
        FORWARD-only branches below (blue, dashed).
        splines=ortho, junction dots, dispatcher ellipses, security footnote.
v1.3.0: Dispatcher wrapper nodes for filter INPUT and filter FORWARD.
        get_all_targets() exposes extension targets (TCPMSS etc.) inline.
        classify_chain() helper for dispatcher vs filter classification.
        ShellCheck-compliant local variable declarations throughout.
v1.4.0: filter OUTPUT dispatcher wrapper + dynamic classify_chain for all root hooks.
        OUTPUT path: LOCAL -> OUTPUT_wrapper -> [out chains] -> junc_merge.
v1.4.1: cluster_INPUT_zone / cluster_FORWARD_zone / cluster_OUTPUT_zone subgraph boxes.
        junc_post rank anchor eliminates POLICYOUT same-column arc. newrank=true added.
v1.5.0: Eliminate shared spine. Full inline serial representation per dispatcher.
        Shared-chain color hint (#FFF8DC) added. TB layout (rankdir=TB) adopted as
        default — 1120px wide vs 5500px LR, clearly legible at 120dpi.
        junc_post anchor updated to fwd_len+1 for clean forward arc after FORWARD track.
"

# --- PSEUDOCODE ---
# 1. Map all tables/roots/subchains into memory via iptables-save.
# 2. Identify Root chains (policy != '-') vs subchains.
# 3. Create clusters for each ROOT chain (rectangle).
# 4. In each Root: Link Subchain[N] -> Subchain[N+1] (the 'Next' flow).
# 5. Link Subchain -> Subchain (Jump) ONLY within the same table/context.
# 6. Overlay Netfilter packet traversal skeleton (NET_IN → PREROUTING → RD1 → ...).

function history() {
    printf "Script Evolution History:%s\n" "$HISTORY"
    exit 0
}

function help() {
    printf 'Architect: %s | Developer: %s | Version: %s\n' "$ARCHITECT" "$DEVELOPER" "$VERSION"
    printf 'Usage: %s [OPTION]\n' "$SELF"
    printf 'Params:\n'
    printf '  all          : (Default) PCB-style stage layout — inline serial per dispatcher\n'
    printf '  filter|nat|mangle|raw|security : per-table nested graph\n'
    printf '  -h|--help    : This help\n'
    printf '  -H|--History : Script evolution history\n'
    exit 0
}

function log_event() {
    local msg="$1"
    logger -t IPFIRE_VISUALIZER "$msg"
    [[ "$DEBUG" == "true" ]] && printf "DEBUG: %b\n" "$msg"
}


function get_subchains_in_root() {
    # Emit only real user-defined chains jumped from root, not extension targets.
    # CRITICAL: use printf "%s " (space-sep) not print (newline-sep) — awk index()
    # lookup breaks with newlines inside the chains variable.
    local tbl="$1" root="$2"
    local known_chains
    known_chains=$(iptables-save -t "$tbl" | awk '/^:/{printf "%s ", substr($1,2)}')
    iptables -t "$tbl" -n -L "$root" | awk -v chains=" $known_chains " '
        NR > 2 {
            target = $1
            if (index(chains, " " target " ") > 0)
                printf "%s ", target
        }'
}


function get_all_targets() {
    # Return all -j targets from a dispatcher chain in rule order (no filtering).
    local tbl root
    tbl="$1"
    root="$2"
    iptables-save -t "$tbl" | awk -v chain="$root" '
        /^-A/ && $2 == chain {
            for (i = 1; i <= NF; i++) {
                if ($i == "-j") { printf "%s ", $(i+1); break }
            }
        }'
}


function classify_chain() {
    # Classify ANY chain (root or user-defined) as dispatcher (>=90% bare -j jumps, no match
    # criteria) or filter. DISPATCHER chains get bold wrapper treatment in generate_pcb_map().
    local tbl chain total pure result
    tbl="$1"
    chain="$2"
    total=0
    pure=0
    while IFS= read -r rule; do
        [[ "$rule" != "-A $chain "* ]] && continue
        (( total++ ))
        if ! printf '%s' "$rule" | grep -qE ' (-p|--protocol|-m|--match|-s|--source|-d|--dest|-i|--in-interface|-o|--out-interface) '; then
            (( pure++ ))
        fi
    done < <(iptables-save -t "$tbl")
    if [[ $total -eq 0 || $(( pure * 10 )) -ge $(( total * 9 )) ]]; then
        result="dispatcher"
    else
        result="filter"
    fi
    echo "$result"
}


generate_unified_map() {
    # Build full unified graph: table/root/subchain clusters + Netfilter traversal skeleton.
    local output="ipfire_unified_firewall_${core}.dot"
    declare -A cluster_anchor=()
    log_event "Scanning: $TABLES"

    {
        echo "digraph UnifiedFW { rankdir=TB; node [shape=rect, style=filled, fillcolor=white];"
        echo "graph [compound=true, ranksep=2.5, nodesep=1.0, newrank=true];"

        for tbl in $TABLES; do
            ! iptables -t "$tbl" -L -n >/dev/null 2>&1 && continue
            echo "  subgraph \"cluster_table_$tbl\" { label=\"TABLE: $tbl\"; style=filled; fillcolor=ivory; color=blue; penwidth=2;"

            for root in $(iptables-save -t "$tbl" | awk '/^:/ {if ($2 != "-") print substr($1,2)}'); do
                echo "    subgraph \"cluster_${tbl}_${root}\" { label=\"${root}\"; style=filled; fillcolor=lightgrey;"

                subchains=$(get_subchains_in_root "$tbl" "$root")
                if [[ -z "$subchains" ]]; then
                    echo "      \"anchor_${tbl}_${root}\" [label=\"\", style=invis, width=0, height=0];"
                    cluster_anchor["${tbl}_${root}"]="anchor_${tbl}_${root}"
                else
                    prev=""
                    first_node=""
                    declare -A seen_nodes=()
                    for sub in $subchains; do
                        node_id="${tbl}_${root}_${sub}"
                        [[ -n "${seen_nodes[$node_id]}" ]] && continue
                        seen_nodes[$node_id]=1
                        [[ -z "$first_node" ]] && first_node="$node_id"
                        echo "      \"$node_id\" [label=\"${sub}\", fillcolor=white];"
                        if [ -n "$prev" ]; then
                            echo "      \"${prev}\" -> \"$node_id\" [color=blue, weight=10];"
                        fi
                        prev="$node_id"
                    done
                    unset seen_nodes
                    cluster_anchor["${tbl}_${root}"]="$first_node"
                fi
                echo "    }"
            done
            echo "  }"
        done

        # --- Packet traversal skeleton ---
        #
        # Six rank levels (TB, top→bottom):
        #   L1: NETWORK_IN + security  (security = final checkpoint before LOCAL/POSTROUTING)
        #   L2: LOCAL PROCESS + RD2    (exit points / OUTPUT→POSTROUTING decision)
        #   L3: raw table              (first table hit by any packet)
        #   L4: mangle | filter | nat  (main processing, filter centered per user request)
        #   L5: RD1                    (routing decision after PREROUTING)
        #   L6: NETWORK_OUT
        #
        # "Top entry, bottom exit" between clusters is automatic when the source cluster
        # is ranked above the destination — Graphviz clips the edge at the correct faces.
        #
        # Two unavoidable backward arcs: mangle/filter at L4 feed security at L1 for the
        # INPUT and FORWARD paths. These use constraint=false so they curve around without
        # distorting the main level structure. A stage-based redesign (v2.0) eliminates them.
        #
        # PCB bridge arcs at crossings: not natively supported by Graphviz.
        local ts_fwd='color="#E65C00", style=bold, penwidth=2.0, constraint=true'
        local ts_bwd='color="#E65C00", style=bold, penwidth=2.0, constraint=false'
        local a

        # Graph-level rank groups (only graph-level nodes — no cluster-internal nodes here,
        # as mixing rank=same with lhead/ltail breaks compound edge clipping in dot).
        # Cluster positioning is handled exclusively by invisible backbone edges below.
        echo "  {rank=min;  \"NET_IN\"}"       # L1 top
        echo "  {rank=same; \"LOCAL\"; \"RD2\"}"  # L2
        echo "  {rank=same; \"RD1\"}"           # L5
        echo "  {rank=max;  \"NET_OUT\"}"       # L6 bottom

        # Invisible backbone: positions all cluster anchors in correct rank slots.
        # L1→L3: NET_IN above raw table
        local raw_rep="${cluster_anchor[raw_PREROUTING]:-${cluster_anchor[raw_OUTPUT]}}"
        [[ -n "$raw_rep" ]] && \
            echo "  \"NET_IN\" -> \"$raw_rep\" [style=invis, constraint=true];"
        # L3→L4: raw above mangle; mangle/filter/nat side-by-side (filter center)
        [[ -n "$raw_rep" && -n "${cluster_anchor[mangle_PREROUTING]}" ]] && \
            echo "  \"$raw_rep\" -> \"${cluster_anchor[mangle_PREROUTING]}\" [style=invis, constraint=true];"
        # L4 side-by-side hint: mangle — filter — nat (constraint=false = left/right only)
        [[ -n "${cluster_anchor[mangle_PREROUTING]}" && -n "${cluster_anchor[filter_INPUT]}" ]] && \
            echo "  \"${cluster_anchor[mangle_PREROUTING]}\" -> \"${cluster_anchor[filter_INPUT]}\" [style=invis, constraint=false];"
        [[ -n "${cluster_anchor[filter_INPUT]}" && -n "${cluster_anchor[nat_PREROUTING]}" ]] && \
            echo "  \"${cluster_anchor[filter_INPUT]}\" -> \"${cluster_anchor[nat_PREROUTING]}\" [style=invis, constraint=false];"
        # L4→L5: nat PREROUTING above RD1
        [[ -n "${cluster_anchor[nat_PREROUTING]}" ]] && \
            echo "  \"${cluster_anchor[nat_PREROUTING]}\" -> \"RD1\" [style=invis, constraint=true];"
        # security/INPUT above LOCAL (security at L1, LOCAL at L2)
        [[ -n "${cluster_anchor[security_INPUT]}" ]] && \
            echo "  \"${cluster_anchor[security_INPUT]}\" -> \"LOCAL\" [style=invis, constraint=true];"
        # security/OUTPUT above RD2
        [[ -n "${cluster_anchor[security_OUTPUT]}" ]] && \
            echo "  \"${cluster_anchor[security_OUTPUT]}\" -> \"RD2\" [style=invis, constraint=true];"
        # nat POSTROUTING above NET_OUT
        [[ -n "${cluster_anchor[nat_POSTROUTING]}" ]] && \
            echo "  \"${cluster_anchor[nat_POSTROUTING]}\" -> \"NET_OUT\" [style=invis, constraint=true];"

        echo "  // Terminals and routing decisions"
        echo "  \"NET_IN\"  [label=\"NETWORK IN\",    shape=parallelogram, style=filled, fillcolor=\"#D5E8D4\", color=\"#82B366\"];"
        echo "  \"NET_OUT\" [label=\"NETWORK OUT\",   shape=parallelogram, style=filled, fillcolor=\"#DAE8FC\", color=\"#6C8EBF\"];"
        echo "  \"LOCAL\"   [label=\"LOCAL PROCESS\", shape=oval,          style=filled, fillcolor=\"#FFE6CC\", color=\"#D6B656\"];"
        printf '  "RD1" [label="ROUTING\nDECISION", shape=diamond, style=filled, fillcolor="#FFF2CC", color="#D6B656"];\n'
        printf '  "RD2" [label="ROUTING\nDECISION", shape=diamond, style=filled, fillcolor="#FFF2CC", color="#D6B656"];\n'

        echo "  // Path 1+2 shared: PREROUTING (natural top-to-bottom)"
        a="${cluster_anchor[raw_PREROUTING]}"
        [[ -n "$a" ]] && echo "  \"NET_IN\" -> \"$a\" [lhead=\"cluster_raw_PREROUTING\", $ts_fwd];"
        a="${cluster_anchor[mangle_PREROUTING]}"
        [[ -n "$a" && -n "${cluster_anchor[raw_PREROUTING]}" ]] && \
            echo "  \"${cluster_anchor[raw_PREROUTING]}\" -> \"$a\" [ltail=\"cluster_raw_PREROUTING\", lhead=\"cluster_mangle_PREROUTING\", $ts_fwd];"
        a="${cluster_anchor[nat_PREROUTING]}"
        [[ -n "$a" && -n "${cluster_anchor[mangle_PREROUTING]}" ]] && \
            echo "  \"${cluster_anchor[mangle_PREROUTING]}\" -> \"$a\" [ltail=\"cluster_mangle_PREROUTING\", lhead=\"cluster_nat_PREROUTING\", $ts_fwd];"
        [[ -n "${cluster_anchor[nat_PREROUTING]}" ]] && \
            echo "  \"${cluster_anchor[nat_PREROUTING]}\" -> \"RD1\" [ltail=\"cluster_nat_PREROUTING\", $ts_fwd];"

        # RD1→mangle/INPUT is backward in TB (mangle cluster is above nat where RD1 sits).
        # Use constraint=false for that first hop only; the rest of the INPUT path is forward.
        echo "  // Path 1: INPUT (for local)"
        a="${cluster_anchor[mangle_INPUT]}"
        [[ -n "$a" ]] && echo "  \"RD1\" -> \"$a\" [lhead=\"cluster_mangle_INPUT\", label=\"for local\", $ts_bwd];"
        a="${cluster_anchor[filter_INPUT]}"
        [[ -n "$a" && -n "${cluster_anchor[mangle_INPUT]}" ]] && \
            echo "  \"${cluster_anchor[mangle_INPUT]}\" -> \"$a\" [ltail=\"cluster_mangle_INPUT\", lhead=\"cluster_filter_INPUT\", $ts_fwd];"
        a="${cluster_anchor[security_INPUT]}"
        [[ -n "$a" && -n "${cluster_anchor[filter_INPUT]}" ]] && \
            echo "  \"${cluster_anchor[filter_INPUT]}\" -> \"$a\" [ltail=\"cluster_filter_INPUT\", lhead=\"cluster_security_INPUT\", $ts_fwd];"
        [[ -n "${cluster_anchor[security_INPUT]}" ]] && \
            echo "  \"${cluster_anchor[security_INPUT]}\" -> \"LOCAL\" [ltail=\"cluster_security_INPUT\", $ts_fwd];"

        # Same backward issue for RD1→mangle/FORWARD
        echo "  // Path 2: FORWARD"
        a="${cluster_anchor[mangle_FORWARD]}"
        [[ -n "$a" ]] && echo "  \"RD1\" -> \"$a\" [lhead=\"cluster_mangle_FORWARD\", label=\"forward\", $ts_bwd];"
        a="${cluster_anchor[filter_FORWARD]}"
        [[ -n "$a" && -n "${cluster_anchor[mangle_FORWARD]}" ]] && \
            echo "  \"${cluster_anchor[mangle_FORWARD]}\" -> \"$a\" [ltail=\"cluster_mangle_FORWARD\", lhead=\"cluster_filter_FORWARD\", $ts_fwd];"
        a="${cluster_anchor[security_FORWARD]}"
        [[ -n "$a" && -n "${cluster_anchor[filter_FORWARD]}" ]] && \
            echo "  \"${cluster_anchor[filter_FORWARD]}\" -> \"$a\" [ltail=\"cluster_filter_FORWARD\", lhead=\"cluster_security_FORWARD\", $ts_fwd];"

        echo "  // Path 3: OUTPUT (locally generated)"
        a="${cluster_anchor[raw_OUTPUT]}"
        [[ -n "$a" ]] && echo "  \"LOCAL\" -> \"$a\" [lhead=\"cluster_raw_OUTPUT\", $ts_fwd];"
        a="${cluster_anchor[mangle_OUTPUT]}"
        [[ -n "$a" && -n "${cluster_anchor[raw_OUTPUT]}" ]] && \
            echo "  \"${cluster_anchor[raw_OUTPUT]}\" -> \"$a\" [ltail=\"cluster_raw_OUTPUT\", lhead=\"cluster_mangle_OUTPUT\", $ts_fwd];"
        a="${cluster_anchor[nat_OUTPUT]}"
        [[ -n "$a" && -n "${cluster_anchor[mangle_OUTPUT]}" ]] && \
            echo "  \"${cluster_anchor[mangle_OUTPUT]}\" -> \"$a\" [ltail=\"cluster_mangle_OUTPUT\", lhead=\"cluster_nat_OUTPUT\", $ts_fwd];"
        a="${cluster_anchor[filter_OUTPUT]}"
        [[ -n "$a" && -n "${cluster_anchor[nat_OUTPUT]}" ]] && \
            echo "  \"${cluster_anchor[nat_OUTPUT]}\" -> \"$a\" [ltail=\"cluster_nat_OUTPUT\", lhead=\"cluster_filter_OUTPUT\", $ts_fwd];"
        a="${cluster_anchor[security_OUTPUT]}"
        [[ -n "$a" && -n "${cluster_anchor[filter_OUTPUT]}" ]] && \
            echo "  \"${cluster_anchor[filter_OUTPUT]}\" -> \"$a\" [ltail=\"cluster_filter_OUTPUT\", lhead=\"cluster_security_OUTPUT\", $ts_fwd];"
        [[ -n "${cluster_anchor[security_OUTPUT]}" ]] && \
            echo "  \"${cluster_anchor[security_OUTPUT]}\" -> \"RD2\" [ltail=\"cluster_security_OUTPUT\", $ts_fwd];"

        echo "  // Shared POSTROUTING (Path 2 FORWARD + Path 3 OUTPUT converge here)"
        a="${cluster_anchor[mangle_POSTROUTING]}"
        if [[ -n "$a" ]]; then
            echo "  \"RD2\" -> \"$a\" [lhead=\"cluster_mangle_POSTROUTING\", $ts_fwd];"
            [[ -n "${cluster_anchor[security_FORWARD]}" ]] && \
                echo "  \"${cluster_anchor[security_FORWARD]}\" -> \"$a\" [ltail=\"cluster_security_FORWARD\", lhead=\"cluster_mangle_POSTROUTING\", $ts_fwd];"
        fi
        a="${cluster_anchor[nat_POSTROUTING]}"
        [[ -n "$a" && -n "${cluster_anchor[mangle_POSTROUTING]}" ]] && \
            echo "  \"${cluster_anchor[mangle_POSTROUTING]}\" -> \"$a\" [ltail=\"cluster_mangle_POSTROUTING\", lhead=\"cluster_nat_POSTROUTING\", $ts_fwd];"
        [[ -n "${cluster_anchor[nat_POSTROUTING]}" ]] && \
            echo "  \"${cluster_anchor[nat_POSTROUTING]}\" -> \"NET_OUT\" [ltail=\"cluster_nat_POSTROUTING\", $ts_fwd];"

        echo "}"
    } > "$output"

    local png_output="${output%.dot}.png"
    if command -v dot >/dev/null; then
        dot -Tpng -Gdpi=120 -Grankdir=LR "$output" -o "$png_output"
        log_event "Success: Image created: $png_output"
    else
        log_event "No image created: dot utility missing.\n     Run: dot -Tpng -Gdpi=120 -Grankdir=LR ${output} -o ${png_output}"
    fi
}

generate_pcb_map() {
    # PCB-style stage layout: PREROUTING dispatchers | INPUT/FORWARD wrapper nodes | shared spine | POSTROUTING dispatchers.
    local output png_output
    local known_chains all_input_targets all_forward_targets all_output_targets raw_pre_chains
    local skip_targets
    local input_user input_ext forward_user forward_ext output_user output_ext
    #local shared input_only forward_only
    local inp_class fwd_class out_class
    #local -A fwd_set inp_set
    local -a out_arr

    output="ipfire_pcb_firewall_${core}.dot"
    png_output="${output%.dot}.png"
    log_event "Generating PCB-style map: $output"

    # Terminal targets — never shown as nodes
    skip_targets=" ACCEPT DROP REJECT LOG RETURN MASQUERADE DNAT SNAT REDIRECT MARK NFQUEUE NFLOG TCPOPTSTRIP "

    # Build known chain list for the filter table
    known_chains=$(iptables-save -t filter | awk '/^:/{printf "%s ", substr($1,2)}')

    # Get full ordered jump lists from INPUT and FORWARD (user chains + extension targets)
    all_input_targets=$(get_all_targets filter INPUT)
    all_forward_targets=$(get_all_targets filter FORWARD)

    # Separate user chains from extension targets for INPUT
    input_user=""
    input_ext=""
    for t in $all_input_targets; do
        [[ "$skip_targets" == *" $t "* ]] && continue
        if [[ " $known_chains " == *" $t "* ]]; then
            input_user+="$t "
        else
            input_ext+="$t "
        fi
    done

    # Separate user chains from extension targets for FORWARD
    forward_user=""
    forward_ext=""
    for t in $all_forward_targets; do
        [[ "$skip_targets" == *" $t "* ]] && continue
        if [[ " $known_chains " == *" $t "* ]]; then
            forward_user+="$t "
        else
            forward_ext+="$t "
        fi
    done

    # Mark chain names that appear in BOTH input and forward (for shared-chain color hint)
    local -A shared_names
    local t
    for t in $all_input_targets;   do shared_names[$t]=i; done
    for t in $all_forward_targets; do
        [[ "${shared_names[$t]}" == "i" ]] && shared_names[$t]=both
    done

    # Separate user chains from extension targets for OUTPUT
    all_output_targets=$(get_all_targets filter OUTPUT)
    output_user=""
    output_ext=""
    for t in $all_output_targets; do
        [[ "$skip_targets" == *" $t "* ]] && continue
        if [[ " $known_chains " == *" $t "* ]]; then
            output_user+="$t "
        else
            output_ext+="$t "
        fi
    done

    # Classify all three root dispatcher hooks dynamically
    inp_class=$(classify_chain filter INPUT)
    fwd_class=$(classify_chain filter FORWARD)
    out_class=$(classify_chain filter OUTPUT)

    # raw PREROUTING user chains
    raw_pre_chains=$(get_subchains_in_root raw PREROUTING)

    {
        printf 'digraph PCB_FW {\n'
        printf '  rankdir=TB; splines=ortho; nodesep=0.4; ranksep=0.5; newrank=true;\n'
        printf '  node [shape=rect, style=filled, fillcolor=white, fontname="Helvetica", fontsize=9, width=0.5, height=0.2];\n'
        printf '\n'

        # --- Terminal nodes ---
        printf '  "NET_IN"  [label="NETWORK IN",    shape=doubleoctagon, fillcolor="#D5E8D4", color="#82B366"];\n'
        printf '  "NET_OUT" [label="NETWORK OUT",   shape=doubleoctagon, fillcolor="#DAE8FC", color="#6C8EBF"];\n'
        printf '  "LOCAL"   [label="LOCAL\nPROCESS", shape=doubleoctagon, fillcolor="#FFE6CC", color="#D6B656"];\n'
        printf '\n'

        # --- Dispatcher ellipses (mangle/nat PREROUTING and POSTROUTING) ---
        printf '  "mangle_PRE"  [label="mangle\nPREROUTING",  shape=ellipse, fillcolor="#FFD966", color="#B8860B"];\n'
        printf '  "nat_PRE"     [label="nat\nPREROUTING",     shape=ellipse, fillcolor="#FFD966", color="#B8860B"];\n'
        printf '  "mangle_POST" [label="mangle\nPOSTROUTING", shape=ellipse, fillcolor="#FFD966", color="#B8860B"];\n'
        printf '  "nat_POST"    [label="nat\nPOSTROUTING",    shape=ellipse, fillcolor="#FFD966", color="#B8860B"];\n'
        printf '\n'

        # --- cluster_INPUT_zone: filter INPUT dispatcher — full serial order ---
        printf '  subgraph cluster_INPUT_zone {\n'
        printf '    label="filter INPUT (Dispatcher)"; style="filled,dashed"; fillcolor="#F2F9F2"; color="#006600"; penwidth=2;\n'
        if [[ "$inp_class" == "dispatcher" ]]; then
            printf '    "INPUT_wrapper" [label="filter\nINPUT", style="filled,bold", fillcolor="#C8F0C8", color="#006600", penwidth=2];\n'
        else
            printf '    "INPUT_wrapper" [label="filter\nINPUT", style="filled", fillcolor="#C8F0C8", color="#006600"];\n'
        fi
        local -A seen_inp
        local fill_c
        for t in $all_input_targets; do
            [[ "$skip_targets" == *" $t "* ]] && continue
            [[ -n "${seen_inp[$t]}" ]] && continue
            seen_inp[$t]=1
            if [[ " $known_chains " == *" $t "* ]]; then
                [[ "${shared_names[$t]}" == "both" ]] && fill_c="#FFF8DC" || fill_c="#E8FFE8"
                printf '    "inp_%s" [label="%s", fillcolor="%s"];\n' "$t" "$t" "$fill_c"
            else
                printf '    "inp_ext_%s" [label="%s", fillcolor="#D8F0D8", color="#006600"];\n' "$t" "$t"
            fi
        done
        printf '  }\n\n'

        # --- cluster_FORWARD_zone: filter FORWARD dispatcher — full serial order ---
        printf '  subgraph cluster_FORWARD_zone {\n'
        printf '    label="filter FORWARD (Dispatcher)"; style="filled,dashed"; fillcolor="#F2F6FA"; color="#000099"; penwidth=2;\n'
        if [[ "$fwd_class" == "dispatcher" ]]; then
            printf '    "FORWARD_wrapper" [label="filter\nFORWARD", style="filled,bold", fillcolor="#C8C8F0", color="#000099", penwidth=2];\n'
        else
            printf '    "FORWARD_wrapper" [label="filter\nFORWARD", style="filled", fillcolor="#C8C8F0", color="#000099"];\n'
        fi
        local -A seen_fwd
        for t in $all_forward_targets; do
            [[ "$skip_targets" == *" $t "* ]] && continue
            [[ -n "${seen_fwd[$t]}" ]] && continue
            seen_fwd[$t]=1
            if [[ " $known_chains " == *" $t "* ]]; then
                [[ "${shared_names[$t]}" == "both" ]] && fill_c="#FFF8DC" || fill_c="#E8E8FF"
                printf '    "fwd_%s" [label="%s", fillcolor="%s"];\n' "$t" "$t" "$fill_c"
            else
                printf '    "fwd_ext_%s" [label="%s", fillcolor="#D8D8F8", color="#000099"];\n' "$t" "$t"
            fi
        done
        printf '  }\n\n'

        # --- cluster_OUTPUT_zone: filter OUTPUT dispatcher + OUTPUT chains ---
        printf '  subgraph cluster_OUTPUT_zone {\n'
        printf '    label="filter OUTPUT (Dispatcher)"; style="filled,dashed"; fillcolor="#FFFDF0"; color="#D6B656"; penwidth=2;\n'
        if [[ "$out_class" == "dispatcher" ]]; then
            printf '    "OUTPUT_wrapper" [label="filter\nOUTPUT", style="filled,bold", fillcolor="#FFE6CC", color="#D6B656", penwidth=2];\n'
        else
            printf '    "OUTPUT_wrapper" [label="filter\nOUTPUT", style="filled", fillcolor="#FFE6CC", color="#D6B656"];\n'
        fi
        for c in $output_ext;  do printf '    "out_ext_%s" [label="%s", fillcolor="#FFD8A8", color="#D6B656"];\n' "$c" "$c"; done
        for c in $output_user; do printf '    "out_%s" [label="%s", fillcolor="#FFF0D8"];\n' "$c" "$c"; done
        printf '  }\n\n'

        # --- Junction dots ---
        printf '  "junc_split" [shape=point, width=0.18, fillcolor=black, color=black];\n'
        printf '  "junc_merge" [shape=point, width=0.18, fillcolor=black, color=black];\n'
        # junc_post: where FORWARD (via junc_merge) and OUTPUT paths converge before POSTROUTING
        printf '  "junc_post"  [shape=point, width=0.18, fillcolor=black, color=black];\n'
        printf '\n'

        # --- Raw PREROUTING subchain nodes ---
        printf '  // raw PREROUTING subchains\n'
        for c in $raw_pre_chains; do
            printf '  "raw_PRE_%s" [label="%s", fillcolor="#EEEEEE"];\n' "$c" "$c"
        done
        printf '\n'

        # --- Security footnote ---
        printf "  \"SEC_NOTE\" [label=\"(Generated on IPFire Core Update \${core}. Note: security table omitted\\\\n\xe2\x80\x94 empty on this system)\", shape=note, fillcolor=\"#F5F5F5\", color=grey, fontsize=9];\n"
        printf '\n'

        # --- PREROUTING flow: NET_IN → raw chains → mangle_PRE → nat_PRE → junc_split ---
        printf '  // PREROUTING flow\n'
        local prev
        prev=""
        printf '  "NET_IN" -> '
        for c in $raw_pre_chains; do
            [[ -n "$prev" ]] && printf '  "raw_PRE_%s" -> ' "$c"
            prev="$c"
        done
        if [[ -n "$prev" ]]; then
            printf '"raw_PRE_%s";\n' "$prev"
            printf '  "raw_PRE_%s" -> "mangle_PRE";\n' "$prev"
        else
            printf '"mangle_PRE";\n'
        fi
        prev=""
        for c in $raw_pre_chains; do
            [[ -n "$prev" ]] && printf '  "raw_PRE_%s" -> "raw_PRE_%s";\n' "$prev" "$c"
            prev="$c"
        done
        printf '  "mangle_PRE" -> "nat_PRE";\n'
        printf '  "nat_PRE" -> "junc_split";\n'
        printf '\n'

        # --- INPUT branch: junc_split → INPUT_wrapper → [all input targets in serial order] → LOCAL ---
        printf '  // INPUT branch (green, dashed)\n'
        printf '  "junc_split" -> "INPUT_wrapper" [style=dashed, color="#006600"];\n'
        prev="INPUT_wrapper"
        local -A seen_inp_e
        local inode
        for t in $all_input_targets; do
            [[ "$skip_targets" == *" $t "* ]] && continue
            [[ -n "${seen_inp_e[$t]}" ]] && continue
            seen_inp_e[$t]=1
            if [[ " $known_chains " == *" $t "* ]]; then inode="inp_$t"; else inode="inp_ext_$t"; fi
            printf '  "%s" -> "%s" [style=dashed, color="#006600"];\n' "$prev" "$inode"
            prev="$inode"
        done
        printf '  "%s" -> "LOCAL" [style=dashed, color="#006600"];\n' "$prev"
        printf '\n'

        # --- FORWARD branch: junc_split → FORWARD_wrapper → [all forward targets in serial order] → junc_merge ---
        printf '  // FORWARD branch (blue, dashed)\n'
        printf '  "junc_split" -> "FORWARD_wrapper" [style=dashed, color="#000099"];\n'
        prev="FORWARD_wrapper"
        local -A seen_fwd_e
        local fnode
        for t in $all_forward_targets; do
            [[ "$skip_targets" == *" $t "* ]] && continue
            [[ -n "${seen_fwd_e[$t]}" ]] && continue
            seen_fwd_e[$t]=1
            if [[ " $known_chains " == *" $t "* ]]; then fnode="fwd_$t"; else fnode="fwd_ext_$t"; fi
            printf '  "%s" -> "%s" [style=dashed, color="#000099"];\n' "$prev" "$fnode"
            prev="$fnode"
        done
        printf '  "%s" -> "junc_merge" [style=dashed, color="#000099"];\n' "$prev"
        printf '\n'

        # --- OUTPUT branch: LOCAL → OUTPUT_wrapper → [ext targets] → user chains → junc_merge ---
        # constraint=false on the LOCAL→OUTPUT_wrapper arc: LOCAL sits far right (end of long
        # INPUT chain); OUTPUT_wrapper is positioned by its forward edges to output chains.
        # Marking this arc constraint=false lets Graphviz place OUTPUT_wrapper near junc_merge
        # and draws the LOCAL hookup as a return wire without distorting the main LR spine.
        printf '  // OUTPUT branch (amber, dashed — locally generated egress)\n'
        printf '  "LOCAL" -> "OUTPUT_wrapper" [style=dashed, color="#D6B656", constraint=false];\n'
        prev="OUTPUT_wrapper"
        for c in $output_ext; do
            printf '  "%s" -> "out_ext_%s" [style=dashed, color="#D6B656"];\n' "$prev" "$c"
            prev="out_ext_$c"
        done
        local last_out
        last_out=""
        for c in $output_user; do
            printf '  "%s" -> "out_%s" [style=dashed, color="#D6B656"];\n' "$prev" "$c"
            prev="out_$c"
            last_out="$c"
        done
        if [[ -n "$last_out" ]]; then
            printf '  "out_%s" -> "junc_post" [style=dashed, color="#D6B656"];\n' "$last_out"
        elif [[ -n "$output_ext" ]]; then
            printf '  "%s" -> "junc_post" [style=dashed, color="#D6B656"];\n' "$prev"
        else
            printf '  "OUTPUT_wrapper" -> "junc_post" [style=dashed, color="#D6B656"];\n'
        fi
        printf '\n'

        # --- POSTROUTING flow: junc_merge → junc_post → mangle_POST → nat_POST → NET_OUT ---
        # FORWARD terminates at junc_merge; OUTPUT terminates at junc_post.
        # Both converge before entering the POSTROUTING dispatchers.
        printf '  // POSTROUTING flow\n'
        printf '  "junc_merge" -> "junc_post";\n'
        printf '  "junc_post"  -> "mangle_POST";\n'
        printf '  "mangle_POST" -> "nat_POST";\n'
        printf '  "nat_POST" -> "NET_OUT";\n'
        printf '\n'

        # --- Rank alignment: input/forward/output node pairing by index ---
        printf '  // Rank alignment\n'
        printf '  {rank=same; "INPUT_wrapper"; "FORWARD_wrapper"; "OUTPUT_wrapper"}\n'

        local -a inp_arr fwd_arr out_arr
        inp_arr=()
        fwd_arr=()
        out_arr=()
        local -A seen_ia seen_fa
        for t in $all_input_targets; do
            [[ "$skip_targets" == *" $t "* ]] && continue
            [[ -n "${seen_ia[$t]}" ]] && continue
            seen_ia[$t]=1
            inp_arr+=("$t")
        done
        for t in $all_forward_targets; do
            [[ "$skip_targets" == *" $t "* ]] && continue
            [[ -n "${seen_fa[$t]}" ]] && continue
            seen_fa[$t]=1
            fwd_arr+=("$t")
        done
        for t in $output_user; do out_arr+=("$t"); done

        # Anchor junc_post two ranks past the last FORWARD chain so junc_merge → junc_post
        # is a forward arc. fwd_arr[fwd_len-1] is at rank R+fwd_len; junc_merge at R+fwd_len+1;
        # junc_post at R+fwd_len+2 (= inp_arr[fwd_len+1]).
        local fwd_len anchor_name
        fwd_len=${#fwd_arr[@]}
        if [[ $fwd_len -gt 0 && -n "${inp_arr[$((fwd_len + 1))]}" ]]; then
            if [[ " $known_chains " == *" ${inp_arr[$((fwd_len + 1))]} "* ]]; then
                anchor_name="inp_${inp_arr[$((fwd_len + 1))]}"
            else
                anchor_name="inp_ext_${inp_arr[$((fwd_len + 1))]}"
            fi
            printf '  {rank=same; "junc_post"; "%s"}\n' "$anchor_name"
        fi

        local max_len i rank_line node_count inp_node fwd_node
        max_len=${#inp_arr[@]}
        [[ ${#fwd_arr[@]} -gt $max_len ]] && max_len=${#fwd_arr[@]}
        [[ ${#out_arr[@]} -gt $max_len ]] && max_len=${#out_arr[@]}

        for (( i=0; i<max_len; i++ )); do
            rank_line='  {rank=same;'
            node_count=0
            if [[ -n "${inp_arr[$i]}" ]]; then
                if [[ " $known_chains " == *" ${inp_arr[$i]} "* ]]; then
                    inp_node="inp_${inp_arr[$i]}"
                else
                    inp_node="inp_ext_${inp_arr[$i]}"
                fi
                rank_line+=" \"$inp_node\";"
                (( node_count++ ))
            fi
            if [[ -n "${fwd_arr[$i]}" ]]; then
                if [[ " $known_chains " == *" ${fwd_arr[$i]} "* ]]; then
                    fwd_node="fwd_${fwd_arr[$i]}"
                else
                    fwd_node="fwd_ext_${fwd_arr[$i]}"
                fi
                rank_line+=" \"$fwd_node\";"
                (( node_count++ ))
            fi
            [[ -n "${out_arr[$i]}" ]] && { rank_line+=" \"out_${out_arr[$i]}\";"; (( node_count++ )); }
            [[ $node_count -gt 1 ]] && printf '%s}\n' "$rank_line"
        done
        printf '\n'

        printf '}\n'
    } > "$output"

    if command -v dot >/dev/null; then
        dot -Tpng -Gdpi=120 "$output" -o "$png_output"
        log_event "Success: Image created: $png_output"
    else
        log_event "No image created: dot utility missing.\n     Run: dot -Tpng -Gdpi=120 ${output} -o ${png_output}"
    fi
}

function generate_nested_graph() {
    local table="$1"
    local output="${table}_flow.dot"
    log_event "Architecting Nested Flow for: $table and generating ${table}_flow.dot"

    iptables-save -t "$table" | awk -v tbl="$table" '
        BEGIN {
            print "digraph " tbl " { rankdir=TB; node [shape=rect]; compound=true;"
        }
        /^:/ {
            chain=substr($1,2); policy=$2
            if (policy != "-") roots[chain] = 1
            else subchains[chain] = 1
        }
        /^-A/ {
            p=$2; target="";
            for(i=1;i<=NF;i++) if($i=="-j" || $i=="-g") target=$(i+1)
            if (target != "" && target !~ /^(ACCEPT|DROP|REJECT|LOG|RETURN|MASQUERADE|DNAT|SNAT|REDIRECT)$/) {
                if (roots[p]) {
                    order[p] = order[p] target " "
                } else {
                    jumps[p] = jumps[p] target " "
                }
            }
        }
        END {
            for (r in roots) {
                print "  subgraph \"cluster_" r "\" { label=\"" r "\"; style=filled; fillcolor=lightgrey;"
                n = split(order[r], s, " ")
                for (i=1; i<=n; i++) {
                    print "    \"" s[i] "\" [fillcolor=white, style=filled];"
                    if (i < n) print "    \"" s[i] "\" -> \"" s[i+1] "\" [color=blue, style=bold];"
                }
                print "  }"
            }
            for (src in jumps) {
                split(jumps[src], targets, " ")
                for (t in targets) print "  \"" src "\" -> \"" targets[t] "\" [color=red, constraint=false];"
            }
            print "}"
        }
    ' > "$output"

    log_event "File $output generated."

    if command -v dot >/dev/null; then
        dot -Tpng "$output" -o "${output%.dot}.png"
        log_event "Image created: ${output%.dot}.png"
    fi
}

function generate_chain_graph() {
    local table="$1"
    local output="${table}_chains.dot"
    if ! iptables -t "$table" -L -n >/dev/null 2>&1; then return; fi

    {
        echo "digraph $table {"
        echo "  rankdir=TB; node [shape=rect, style=filled, fillcolor=white];"
        iptables-save -t "$table" | awk '
            /^:/ { print "  \"" substr($1,2) "\";" }
            /^-A/ {
                p=$2; t="";
                for(i=1;i<=NF;i++) if($i=="-j" || $i=="-g") t=$(i+1)
                if (t != "" && t !~ /^(ACCEPT|DROP|REJECT|LOG|RETURN|MASQUERADE|DNAT|SNAT|REDIRECT)$/) {
                    edge = "\"" p "\" -> \"" t "\""
                    if (!seen[edge]++) print "  " edge ";"
                }
            }'
        echo "}"
    } > "$output"

    log_event "File $output generated."
}

case "$1" in
    -h|--help)    help ;;
    -H|--History) history ;;
    filter|nat|mangle|raw|security) generate_nested_graph "$1" ;;
    all|ALL|*)    generate_pcb_map ;;
esac
