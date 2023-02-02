# Tool for applying test vectors from Ethereum on FEVM

* [Requirements | devgrants/fvm-ethereum-test-vectors.md at fvm_ethereum_test · storswiftlabs/devgrants · GitHub](https://github.com/storswiftlabs/devgrants/blob/fvm_ethereum_test/rfps/fvm-ethereum-test-vectors.md)

* [Design Proposal](https://docs.google.com/presentation/d/1u_-CamlnGZAVuY2ci3JSNnFq51l4X_TH/edit?usp=sharing&ouid=105194677015683983388&rtpof=true&sd=true)

**Related Deliverables**

* [DashBoard | Test Report](https://docs.google.com/spreadsheets/d/1g0FLXqMUnCs85eGbvT9_0TdToqqKc0yHAGY_XQStZKo/edit#gid=1092754439)

* [Execution Trace](https://github.com/shamb0/fevm-eth-compliance-test-trace/tree/main/GeneralStateTests)


## Howto Run the test

1, Pull the Eth Test vectors (`https://github.com/ethereum/tests.git`)

```
git submodule update --init
```

2, Launch the test for single test vector json file.

```
RUST_LOG=trace \
	VECTOR=test_evm_eth_compliance/test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00.json \
	cargo run --release -p test_fevm_eth_compliance \
	-- statetest
```

3, Launch all the test under the folder.

```
RUST_LOG=trace \
	VECTOR=test_evm_eth_compliance/test-vectors/tests/GeneralStateTests/EIPTests \
	cargo run --release -p test_fevm_eth_compliance \
	-- statetest
```
