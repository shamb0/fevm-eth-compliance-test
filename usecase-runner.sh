#!/bin/sh

cat usecase.txt | while read pkg; do
  RUST_LOG=evm_eth_compliance=trace
  VECTOR="$pkg" cargo run --retail -- statetest
done
