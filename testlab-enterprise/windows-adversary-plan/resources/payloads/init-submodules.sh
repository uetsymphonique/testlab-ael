#!/bin/bash
# Run from repo root: bash testlab-enterprise/windows-adversary-plan/resources/payloads/init-submodules.sh

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

git submodule update --init

payload_base="testlab-enterprise/windows-adversary-plan/resources/payloads"

declare -A submodules=(
    ["rce-and-c2"]="dnscat2 react2shell-tool"
    ["persistence"]="windows-service"
    ["user-trigger"]="T1189"
    ["impact"]="ImpactPayload"
    ["process-injection"]="CWLHerpaderping"
    ["priv-escalation"]="EfsPotato"
    ["cred-access"]="LsassReflectDumping NtdsRawDump"
    ["lateral-movement"]="go-thehash"
)

for name in "${!submodules[@]}"; do
    path="$repo_root/$payload_base/$name"
    folders=${submodules[$name]}

    echo "[$name] sparse-checkout: $folders"
    cd "$path"
    git sparse-checkout init --cone
    git sparse-checkout set $folders
done

cd "$repo_root"
echo "Done."
