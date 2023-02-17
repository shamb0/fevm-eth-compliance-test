use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::Path;
use std::str::FromStr;
use std::time::Instant;

use fil_actors_runtime::runtime::builtins::Type as ActorType;
use fvm::executor::ApplyKind;
use fvm::gas::Gas;
use fvm::state_tree::ActorState;
use fvm_integration_tests::bundle;
use fvm_integration_tests::dummy::DummyExterns;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::tuple::*;
use fvm_ipld_encoding::{strict_bytes, BytesDe, RawBytes};
use fvm_ipld_kamt::Config as KamtConfig;
use fvm_shared::address::Address;
use fvm_shared::bigint::BigInt;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use fvm_shared::state::StateTreeVersion;
use fvm_shared::version::NetworkVersion;
use fvm_shared::ActorID;
use hex_literal::hex;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::models::{SpecName, Test, TestSuit, TestUnit};
use super::{ExecStatus, Runner};
use crate::common::tester::{Account, Tester, TesterCore};
use crate::common::{merkle_trie, Error, B160, B256, H160, SKIP_TESTS};

const ENOUGH_GAS: Gas = Gas::new(99_900_000_000_000);

const WAT: &str = r#"
;; Mock invoke function
(module
  (func (export "invoke") (param $x i32) (result i32)
    (i32.const 1)
  )
)
"#;

lazy_static::lazy_static! {
    // The Solidity compiler creates contiguous array item keys.
    // To prevent the tree from going very deep we use extensions,
    // which the Kamt supports and does in all cases.
    //
    // There are maximum 32 levels in the tree with the default bit width of 8.
    // The top few levels will have a higher level of overlap in their hashes.
    // Intuitively these levels should be used for routing, not storing data.
    //
    // The only exception to this is the top level variables in the contract
    // which solidity puts in the first few slots. There having to do extra
    // lookups is burdensome, and they will always be accessed even for arrays
    // because that's where the array length is stored.
    //
    // However, for Solidity, the size of the KV pairs is 2x256, which is
    // comparable to a size of a CID pointer plus extension metadata.
    // We can keep the root small either by force-pushing data down,
    // or by not allowing many KV pairs in a slot.
    //
    // The following values have been set by looking at how the charts evolved
    // with the test contract. They might not be the best for other contracts.
    static ref KAMT_CONFIG: KamtConfig = KamtConfig {
        min_data_depth: 0,
        bit_width: 5,
        max_array_width: 1
    };
}

#[derive(Serialize_tuple, Deserialize_tuple, Clone, Debug)]
struct State {
    empty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct ContractParams(#[serde(with = "strict_bytes")] pub Vec<u8>);

lazy_static::lazy_static! {
    pub static ref MAP_CALLER_KEYS: HashMap<B256, B160> = {
        vec![
        (
            B256(hex!(
                "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
            )),
            B160(hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b")),
        ),
        (
            B256(hex!(
                "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4"
            )),
            B160(hex!("cd2a3d9f938e13cd947ec05abc7fe734df8dd826")),
        ),
        (
            B256(hex!(
                "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d"
            )),
            B160(hex!("82a978b3f5962a5b0957d9ee9eef472ee55b42f1")),
        ),
        (
            B256(hex!(
                "6a7eeac5f12b409d42028f66b0b2132535ee158cfda439e3bfdd4558e8f4bf6c"
            )),
            B160(hex!("c9c5a15a403e41498b6f69f6f89dd9f5892d21f7")),
        ),
        (
            B256(hex!(
                "a95defe70ebea7804f9c3be42d20d24375e2a92b9d9666b832069c5f3cd423dd"
            )),
            B160(hex!("3fb1cd2cd96c6d5c0b5eb3322d807b34482481d4")),
        ),
        (
            B256(hex!(
                "fe13266ff57000135fb9aa854bbfe455d8da85b21f626307bf3263a0c2a8e7fe"
            )),
            B160(hex!("dcc5ba93a1ed7e045690d722f2bf460a51c61415")),
        ),
    ]
    .into_iter()
    .collect()
    };
}

const EAM_ACTOR_ID: ActorID = 10;

struct Executor<'a, T: Tester> {
    trace_prefix: String,
    pre_contract_cache: HashMap<B160, ActorID>,
    tester: &'a mut T,
    sender: Vec<Account>,
}

impl<'a, T: Tester> Executor<'a, T> {
    fn new(path: &Path, tester: &'a mut T, arg_sender: &[Account]) -> Self {
        let pre_contract_cache: HashMap<B160, ActorID> = HashMap::new();

        let sender = arg_sender.to_vec();

        Executor {
            trace_prefix: path.file_name().unwrap().to_string_lossy().to_string(),
            pre_contract_cache,
            tester,
            sender,
        }
    }

    pub fn process_post_block<RUN: Runner + Clone>(
        &mut self,
        runner: RUN,
        name: &str,
        unit: &TestUnit,
    ) -> bool {
        let sender =
            if let Some(caller) = MAP_CALLER_KEYS.get(&unit.transaction.secret_key.unwrap()) {
                *caller
            } else {
                warn!(
                    "Test Skipped, Unknow caller private key {:#?}",
                    unit.transaction.secret_key.unwrap()
                );
                return false;
            };

        let sender_actor_id = *self.pre_contract_cache.get(&sender).unwrap();

        // Process the "Post" & "transaction" block
        unit.post.iter().for_each(|(spec_name, tests)| {
            tests.iter().for_each(|test| {
                info!(
                    "Entering Post Block => {:#?} {:#?}",
                    spec_name, test.indexes.data
                );

                if Self::skip_post_test(name, spec_name, test.indexes.data) {
                    let path_tag: String = format!("{}::{}::post", self.trace_prefix, name);

                    let status_msg: String = format!("{:?} | {:?}", spec_name, test.indexes.data);

                    runner.update_exe_status(ExecStatus::Skip, path_tag, status_msg);

                    return;
                }

                let _execu_status = self.process_post_block_internal(
                    runner.clone(),
                    sender_actor_id,
                    name,
                    spec_name,
                    unit,
                    test,
                );

                // TODO :: Howto verify the post.hash ?
            });
        });

        true
    }

    fn skip_post_test(test_name: &str, chain_spec: &SpecName, data_index: usize) -> bool {
        let rval = SKIP_TESTS.state.iter().any(|state_test| {
            state_test.post_tests.as_ref().map_or_else(
                || false,
                |maybe_post_tests| {
                    maybe_post_tests.get(test_name).map_or_else(
                        || false,
                        |post_test| {
                            post_test.skip_ids.get(chain_spec).map_or_else(
                                || false,
                                |data_indexes| {
                                    data_indexes[0] == "*"
                                        || data_indexes.contains(&data_index.to_string())
                                },
                            )
                        },
                    )
                },
            )
        });

        if rval {
            warn!(
                "Skipping Post Test test_name: '{:#?}', chain_spec: '{:#?}', data_index: {:#?}",
                test_name, chain_spec, data_index
            );
        }

        rval
    }

    fn process_post_block_internal<RUN: Runner + Clone>(
        &mut self,
        runner: RUN,
        sender_id: ActorID,
        name: &str,
        spec_name: &SpecName,
        unit: &TestUnit,
        test: &Test,
    ) -> bool {
        let gas_limit = *unit.transaction.gas_limit.get(test.indexes.gas).unwrap();
        let tx_gas_limit = u64::try_from(gas_limit).unwrap_or(u64::MAX);
        let tx_data = unit.transaction.data.get(test.indexes.data).unwrap();
        let _tx_value = *unit.transaction.value.get(test.indexes.value).unwrap();

        // TODO-Review :: `&& !tx_data.is_empty()` how to handle the context with empty
        // transaction data.

        if !(unit.transaction.to.is_some()
            && self
                .pre_contract_cache
                .contains_key(&unit.transaction.to.unwrap()))
        {
            warn!(
                "Skipping TestCase no valid actor {:#?}::{:#?}::{:#?}",
                name, spec_name, test.indexes.data
            );
            warn!("Path : {:#?}", self.trace_prefix);
            warn!("TX len : {:#?}", tx_data.len());

            let path_tag: String = format!("{}::{}", self.trace_prefix, name);
            let status_msg: String = format!(
                "{:?} | {:?} | transaction.to empty",
                spec_name, test.indexes.data
            );

            runner.update_exe_status(ExecStatus::Skip, path_tag, status_msg);

            return false;
        }

        info!(
            "Executing TestCase {:#?}::{:#?}::{:#?}",
            name, spec_name, test.indexes.data
        );
        info!("Path : {:#?}", self.trace_prefix);
        info!("TX len : {:#?}", tx_data.len());

        let raw_params = RawBytes::serialize(ContractParams(tx_data.to_vec())).unwrap();

        let actor_id = self
            .pre_contract_cache
            .get(&unit.transaction.to.unwrap())
            .unwrap();

        let actor_address = Address::new_id(*actor_id);

        let sender_addr = Address::new_id(sender_id);

        let sender_address = Address::new_delegated(EAM_ACTOR_ID, &sender_addr.to_bytes()).unwrap();

        let sender_state = self.tester.get_actor(sender_id).unwrap().unwrap();

        // Gas::new(tx_gas_limit).as_milligas(),
        // Gas::from_milligas(tx_gas_limit).as_milligas()
        // (tx_gas_limit.saturating_mul(20i64))
        // ENOUGH_GAS.as_milligas()

        // Send message
        let message = Message {
            from: sender_address,
            to: actor_address,
            sequence: sender_state.sequence,
            gas_limit: tx_gas_limit.saturating_mul(20u64),
            method_num: fil_actor_evm::Method::InvokeContract as u64,
            params: raw_params,
            ..Message::default()
        };

        let call_result = self
            .tester
            .execute_message(message, ApplyKind::Explicit, 100)
            .unwrap();

        info!("Post Hash Check ::");

        let state_trie_hash = self.state_merkle_trie_root();

        info!("Calc :: {:#?}", state_trie_hash);
        info!("Actual :: {:#?}", test.hash);

        let path_tag: String = format!("{}::{}", self.trace_prefix, name);
        let status_msg: String = format!(
            "{:?} | {:?} | {:?}",
            spec_name, test.indexes.data, call_result.msg_receipt.exit_code
        );

        let update_status = if call_result.msg_receipt.exit_code.is_success() {
            ExecStatus::Ok
        } else {
            ExecStatus::Ko
        };

        runner.update_exe_status(update_status, path_tag, status_msg);

        if !call_result.msg_receipt.exit_code.is_success() {
            warn!("Execution Failed => {:#?}", call_result.msg_receipt);
            warn!("failure_info => {:#?}", call_result.failure_info);
        } else {
            info!("Execution Success => {:#?}", call_result.msg_receipt);
            let BytesDe(_return_value) = call_result
                .msg_receipt
                .return_data
                .deserialize()
                .expect("failed to deserialize results");
        }

        true
    }

    fn state_merkle_trie_root(&mut self) -> B256 {
        let vec = self
            .pre_contract_cache
            .iter()
            .map(|(address, actor_id)| {
                info!(
                    "State info for => {:#?}",
                    hex::encode(address.to_fixed_bytes())
                );

                let acc_root = self
                    .tester
                    .get_fevm_trie_account_rlp(*actor_id, KAMT_CONFIG.clone())
                    .unwrap();

                (H160::from_slice(&address.to_fixed_bytes()), acc_root)
            })
            .collect();

        merkle_trie::trie_root(vec)
    }

    fn skip_pre_test(test_name: &str, owner_address: &B160) -> bool {
        let rval = SKIP_TESTS.state.iter().any(|state_test| {
            state_test.pre_tests.as_ref().map_or_else(
                || false,
                |maybe_pre_tests| {
                    if let Some(pre_test) = maybe_pre_tests.get(test_name) {
                        let owner_address_str = format!("{:#?}", owner_address);
                        pre_test.pre_owners[0] == "*"
                            || pre_test.pre_owners.contains(&owner_address_str)
                    } else {
                        false
                    }
                },
            )
        });

        if rval {
            warn!(
                "Skipping Pre Test test_name: '{:#?}', owner_address: '{:#?}'",
                test_name, owner_address,
            );
        }

        rval
    }

    pub fn process_pre_block(&mut self, name: &str, unit: &TestUnit) -> bool {
        // Process the "pre" block & deploy the contracts
        unit.pre
            .iter()
            .enumerate()
            .for_each(|(test_id, (address, info))| {
                info!("Pre-Block Iteration :: {:#?}", test_id);

                if Self::skip_pre_test(name, address) {
                    return;
                }

                let addr = Address::new_delegated(EAM_ACTOR_ID, address.as_bytes()).unwrap();

                // Deploy a placeholder to the target address.
                {
                    let message = Message {
                        from: self.sender[test_id].1,
                        to: addr,
                        gas_limit: ENOUGH_GAS.as_milligas(),
                        method_num: 0,
                        params: RawBytes::default(),
                        ..Message::default()
                    };

                    let create_result = self
                        .tester
                        .execute_message(message, ApplyKind::Explicit, 100)
                        .unwrap();

                    assert!(
						create_result.msg_receipt.exit_code.is_success(),
						"failed to create the new actor :: {:#?} | Path :: {:#?} | Address :: {:#?}",
						create_result.msg_receipt,
						self.trace_prefix,
						address
					);
                }

                let evm_code_cid = self.tester.code_by_id(ActorType::EVM as u32).unwrap();
                let evm_state_cid = self
                    .tester
                    .init_fevm(
                        info.code.clone(),
                        info.nonce,
                        &info.storage,
                        KAMT_CONFIG.clone(),
                    )
                    .expect("failed to store state");

                let actor_state = ActorState::new(
                    evm_code_cid,
                    evm_state_cid,
                    TokenAmount::from_atto(
                        BigInt::from_str(&format!("{}", &info.balance)).unwrap(),
                    ),
                    info.nonce,
                    None,
                );

                let actor_id = self
                    .tester
                    .set_actor(&addr, actor_state)
                    .expect("EVM actor state mutation failed");

                info!("New State ID Updated");

                self.pre_contract_cache.insert(*address, actor_id);
            });
        true
    }
}

pub fn execute_test_suit<RUN: Runner + Clone>(runner: RUN, path: &Path) -> Result<(), Error> {
    let json_reader = std::fs::read(path).unwrap();
    let suit: TestSuit = serde_json::from_reader(&*json_reader)?;

    let store = MemoryBlockstore::default();
    let bundle_root = bundle::import_bundle(&store, actors_v10::BUNDLE_CAR).unwrap();

    let mut tester = TesterCore::new(
        NetworkVersion::V18,
        StateTreeVersion::V5,
        bundle_root,
        store,
    )
    .unwrap();

    let sender: [Account; 300] = tester.create_accounts().unwrap();

    // Get wasm bin
    let wasm_bin = wat::parse_str(WAT).unwrap();

    // Set actor state
    let actor_state = State { empty: true };
    let state_cid = tester.set_state(&actor_state).unwrap();

    // Set actor
    let actor_address = Address::new_id(10000);

    tester
        .set_actor_from_bin(&wasm_bin, state_cid, actor_address, TokenAmount::zero())
        .unwrap();

    // Instantiate machine
    tester.instantiate_machine(DummyExterns).unwrap();

    let timer = Instant::now();

    let mut executor = Executor::new(path, &mut tester, &sender);

    for (name, unit) in suit.0.iter() {
        // info!("{:#?}:{:#?}", name, unit);

        if !executor.process_pre_block(name, unit) {
            continue;
        }

        if !executor.process_post_block(runner.clone(), name, unit) {
            continue;
        }

        // TODO :: Process env block, is it needed for FEVM context ?
    }

    runner.update_elapsed_duration(timer.elapsed());

    Ok(())
}
