#!/bin/bash

# ==============================================================================
# Script Name: make-package.sh
# Description: Simplifies the compilation pipeline by packing raw contents 
#              directly out of the src container without manifest descriptors.
# ==============================================================================

# --- Pseudocode Block ---
# function run_build_pipeline() {
#   1. Initialize debug modes and log tracking tags.
#   2. Compute the repository root directory absolute location paths.
#   3. Extract version information strings from the core visualizer engine.
#   4. Re-create clean workspace build folders on disk.
#   5. Synchronize documents and apply safe execution permission bits.
#   6. Compress raw files into a direct-deflate deployment distribution.
#   7. Formulate a sha256 authentication tracking check value string.
# }

run_build_pipeline() {
    local debug log_prefix repo_root build_dir name viz_script version package_name
    
    debug=true
    log_prefix="[PACKAGER]"
    repo_root="$(cd "$(dirname "$0")/.." && pwd)"
    build_dir="${repo_root}/build"
    name="diagraph-ipfire"
    viz_script="${repo_root}/src/ipfire_firewall_vizualizer.sh"
    
    if [[ -f "${viz_script}" ]]; then
        version=$(grep -E '^VERSION=' "${viz_script}" | head -n1 | cut -d'"' -f2 | cut -d' ' -f1)
    fi
    version="${version:-1.6.0}"
    package_name="${name}-v${version}.tar.gz"

    if [[ "${debug}" == true ]]; then
        printf "%s Commencing flat-archive assembly track for %s (v%s)\n" "${log_prefix}" "${name}" "${version}"
    fi

    logger -t "ipfire-packager" "${log_prefix} Compiling zero-installer delivery archive for v${version}"

    # Step 1: Initialize temporary build spaces
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}/staging"

    # Step 2: Verify structural operational prerequisites
    if [[ ! -f "${viz_script}" ]]; then
        printf "%s [ERROR] Visualizer source payload missing at: %s\n" "${log_prefix}" "${viz_script}"
        return 1
    fi

    # Step 3: Populate staging tree directly
    cp "${viz_script}" "${build_dir}/staging/"
    [[ -f "${repo_root}/CHANGELOG.md" ]] && cp "${repo_root}/CHANGELOG.md" "${build_dir}/staging/"
    [[ -f "${repo_root}/README.md" ]] && cp "${repo_root}/README.md" "${build_dir}/staging/"

    # Step 4: Sanitize permission bit arrays
    chmod 755 "${build_dir}/staging/ipfire_firewall_vizualizer.sh"
    [[ -f "${build_dir}/staging/CHANGELOG.md" ]] && chmod 644 "${build_dir}/staging/CHANGELOG.md"
    [[ -f "${build_dir}/staging/README.md" ]] && chmod 644 "${build_dir}/staging/README.md"

    # Step 5: Generate single direct deflation tarball archive
    cd "${build_dir}/staging" || return 1
    tar --owner=0 --group=0 -czf "${build_dir}/${package_name}" ./*

    # Step 6: Formulate system integrity check codes
    cd "${build_dir}" || return 1
    sha256sum "${package_name}" > "${package_name}.sha256"

    # Step 7: Clear operational footprints
    rm -rf "${build_dir}/staging"

    if [[ "${debug}" == true ]]; then
        printf "%s Direct package build completed successfully:\n" "${log_prefix}"
        printf "     TARGET RELEASE: %s/%s\n" "${build_dir}" "${package_name}"
        printf "     VERIFICATION:   %s/%s.sha256\n" "${build_dir}" "${package_name}"
    fi
}

run_build_pipeline