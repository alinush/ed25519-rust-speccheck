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

RED='\\033[0;31m'
GREEN='\\033[0;32m'
BOLDPURPLE='\\033[1;35m'
NC='\\033[0m' # No color

color_output() {
    sed "s/X/${RED}X${NC}/g" |
    sed "s/V/${GREEN}V${NC}/g" |
    sed "s/aptos-crypto/${BOLDPURPLE}aptos-crypto${NC}/g" |
    sed "s/\[CGN20e\] Alg.2/${GREEN}\[CGN20e] Alg.2${NC}/g"
}

out=`cat results.md \
    | grep -v aptos-crypto \
    | grep -v CGN20e \
    | grep -v Dalek \
    | color_output
`
out_dalek=`cat results.md \
    | grep Dalek \
    | color_output \
`
out_aptos=`cat results.md \
    | grep aptos-crypto \
    | color_output \
`
out_cgn20e=`cat results.md \
    | grep CGN20e \
    | color_output \
`
echo -e "$out"
echo "|---------------|-----------------------------------------------|"
echo -e "$out_dalek"
echo "|---------------|-----------------------------------------------|"
echo -e "$out_aptos"
echo -e "$out_cgn20e"
