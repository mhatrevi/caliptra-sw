#!/bin/bash
# Licensed under the Apache-2.0 license

cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -z $1 ]; then
    echo "Usage:"
    echo "./update.sh [revision]"
    echo "Where [revision] has to be one of the revisions under /hw (latest, rev-2_1, ...)."
    exit 1
fi

echo $"Updating /hw/$1/"

caliptra_ss_dir="../hw/$1/caliptra-ss"
caliptra_rtl_dir="$caliptra_ss_dir/third_party/caliptra-rtl"
i3c_core_dir="$caliptra_ss_dir/third_party/i3c-core"

for repo_dir in "$caliptra_ss_dir" "$caliptra_rtl_dir" "$i3c_core_dir"; do
    if ! git -C "$repo_dir" rev-parse --git-dir >/dev/null 2>&1; then
        echo "$repo_dir is not populated"
        echo "Please run 'git submodule update --init --recursive hw/$1/caliptra-ss'"
        exit 1
    fi
done

cargo run --manifest-path bin/generator/Cargo.toml -- "$caliptra_ss_dir" bin/extra-rdl/ "../hw/$1/registers/src/"
