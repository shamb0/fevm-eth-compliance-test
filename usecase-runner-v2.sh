#!/bin/sh

for pkg in "$@"
do
  RUST_LOG=evm_eth_compliance=trace
  VECTOR="$pkg" cargo run --release -- statetest
done
