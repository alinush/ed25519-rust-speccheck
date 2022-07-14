#!/bin/bash
#
# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the APACHE 2.0 license found in
# the LICENSE file in the root directory of this source tree.

SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

main() {

cd "$SOURCE_DIR"
# Dalek, Zebra, BoringSSL, libra-crypto
cargo test -- --nocapture --test-threads 1

}

main > results.md  2>/dev/null

# This seems to filter out the debug output of `cargo test` into a file called `results.mdre`
sed -ire  '/^|/!d' results.md
sort -f results.md -o results-temp.md

truncate --size 0 results.md
echo "|[CGN20e] Alg.2 | X | X | V | V | V | V | X | X | X | X | X | X |" >results.md
cat results-temp.md >>results.md
rm results-temp.md

cat results.md
