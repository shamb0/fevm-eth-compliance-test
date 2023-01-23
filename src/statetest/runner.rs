use std::collections::HashMap;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arrayref::array_ref;
use cid::multihash::{Code, MultihashDigest};
use fil_actor_eam::EthAddress;
use fil_actor_evm::interpreter::system::{StateKamt};
use fil_actor_evm::state::{BytecodeHash, State as EvmState};
use fvm::executor::{ApplyKind, Executor};
use fvm::gas::Gas;
use fvm::machine::Machine;
use fvm::state_tree::ActorState;
use fvm_integration_tests::bundle;
use fvm_integration_tests::dummy::DummyExterns;
use fvm_ipld_blockstore::{Block, Blockstore, MemoryBlockstore};
use fvm_ipld_encoding::tuple::*;
use fvm_ipld_encoding::{strict_bytes, BytesDe, CborStore, RawBytes};
use fvm_ipld_kamt::Config as KamtConfig;
use fvm_shared::address::Address;
use fvm_shared::bigint::BigInt;
use fvm_shared::crypto::hash::SupportedHashes;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use fvm_shared::state::StateTreeVersion;
use fvm_shared::version::NetworkVersion;
use fvm_shared::{ActorID, IPLD_RAW};
use hex_literal::hex;
use indicatif::ProgressBar;
use libsecp256k1::SecretKey;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, trace, warn};

use super::models::{SpecName, TestSuit};
use crate::common::tester::{Account, Tester, INITIAL_ACCOUNT_BALANCE};
use crate::common::{B160, B256, SKIP_TESTS};

#[derive(Debug, Error)]
pub enum TestError {
    // #[error(" Test:{spec_id:?}:{id}, Root missmatched, Expected: {expect:?} got:{got:?}")]
    // RootMissmatch {
    //     spec_id: SpecId,
    //     id: usize,
    //     got: B256,
    //     expect: B256,
    // },
    #[error("Serde json error")]
    SerdeDeserialize(#[from] serde_json::Error),
    #[error("Internal system error")]
    SystemError,
    // #[error("Unknown private key: {private_key:?}")]
    // UnknownPrivateKey { private_key: B256 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct ContractParams(#[serde(with = "strict_bytes")] pub Vec<u8>);

const WAT: &str = r#"
;; Mock invoke function
(module
  (func (export "invoke") (param $x i32) (result i32)
    (i32.const 1)
  )
)
"#;

#[derive(Serialize_tuple, Deserialize_tuple, Clone, Debug)]
struct State {
    empty: bool,
}

const ENOUGH_GAS: Gas = Gas::new(999_00_000_000_000);

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

#[allow(dead_code)]
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

fn execute_test_suit(path: &Path, elapsed: &Arc<Mutex<Duration>>) -> Result<(), TestError> {
    const EAM_ACTOR_ID: ActorID = 10;
    const EAM_ACTOR_ADDR: Address = Address::new_id(EAM_ACTOR_ID);

    let json_reader = std::fs::read(path).unwrap();
    let suit: TestSuit = serde_json::from_reader(&*json_reader)?;

    let store = MemoryBlockstore::default();
    let bundle_root = bundle::import_bundle(&store, actors_v10::BUNDLE_CAR).unwrap();
    let mut tester = Tester::new(
        NetworkVersion::V18,
        StateTreeVersion::V5,
        bundle_root,
        store,
    )
    .unwrap();

    let sender: [Account; 100] = tester.create_accounts().unwrap();

    let mut pre_contract_cache: HashMap<B160, ActorID> = HashMap::new();

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

    for (name, unit) in suit.0.iter() {
        // info!("{:#?}:{:#?}", name, unit);

        // TODO :: Process env block, is it needed for FEVM context ?

        // Process the "pre" block & deploy the contracts
        for (test_id, (address, info)) in unit.pre.iter().enumerate() {
            info!("Pre-Block Iteration :: {:#?}", test_id);

            if skip_pre_test(name.as_ref(), address) {
                continue;
            }

            // TODO-Review :: Hit with error ExitCode::USR_UNSPECIFIED

            // let raw_params = RawBytes::serialize(fil_actor_eam::CreateExternalParams (
            //     address.as_bytes().to_vec(),
            // ))
            // .unwrap();

            // // Send message
            // let message = Message {
            //     from: sender[test_id].1,
            //     to: EAM_ACTOR_ADDR,
            //     gas_limit: ENOUGH_GAS.as_milligas(),
            //     method_num: fil_actor_eam::Method::CreateExternal as u64,
            //     params: raw_params,
            //     ..Message::default()
            // };

            let raw_params = RawBytes::serialize(fil_actor_eam::InitAccountParams {
                eth_address: EthAddress(address.as_bytes().try_into().unwrap()),
            })
            .unwrap();

            // Send message
            let message = Message {
                from: sender[test_id].1,
                to: EAM_ACTOR_ADDR,
                gas_limit: ENOUGH_GAS.as_milligas(),
                method_num: fil_actor_eam::Method::CreateAccount as u64,
                params: raw_params,
                ..Message::default()
            };

            let create_result = tester
                .executor
                .as_mut()
                .unwrap()
                .execute_message(message, ApplyKind::Explicit, 100)
                .unwrap();

            assert!(
                create_result.msg_receipt.exit_code.is_success(),
                "failed to create the new actor :: {:#?} | Path :: {:#?} | Address :: {:#?}",
                create_result.msg_receipt,
                path,
                address
            );

            let create_return: fil_actor_eam::Create2Return = create_result
                .msg_receipt
                .return_data
                .deserialize()
                .expect("failed to decode results");

            info!(
                "Dummy Place Holder Contract got deployed with Actor ID [{:#?}]",
                create_return.actor_id,
            );

            let new_evm_state_cid = tester.executor.as_ref().map(|maybe_executor| {
                let maybe_state_tree = maybe_executor.state_tree();

                let hasher = Code::try_from(SupportedHashes::Keccak256 as u64).unwrap();
                let code_hash = multihash::Multihash::wrap(
                    SupportedHashes::Keccak256 as u64,
                    &hasher.digest(&info.code).to_bytes(),
                )
                .expect("failed to hash bytecode with keccak");

                let code_cid = maybe_state_tree
                    .store()
                    .put(Code::Blake2b256, &Block::new(IPLD_RAW, info.code.clone()))
                    .expect("failed to write bytecode");

                let mut slots =
                    StateKamt::new_with_config(maybe_state_tree.store(), KAMT_CONFIG.clone());

                let mut evm_state = maybe_state_tree
                    .get_actor(create_return.actor_id)
                    .map(|actor_state| {
                        maybe_state_tree
                            .store()
                            .get_cbor::<EvmState>(&actor_state.unwrap().state)
                            .unwrap()
                            .unwrap()
                    })
                    .expect("Invalid evm actor state");

                evm_state.bytecode = code_cid;

                evm_state.bytecode_hash =
                    BytecodeHash::try_from(&code_hash.to_bytes()[..32]).unwrap();

                evm_state.contract_state = slots.flush().expect("failed to flush contract state");

                evm_state.nonce = info.nonce;

                let evm_state_cid = maybe_state_tree
                    .store()
                    .put_cbor(&evm_state, Code::Blake2b256)
                    .unwrap();

                info!("New State ID Updated");

                evm_state_cid
            });

            if new_evm_state_cid.is_none() {
                warn!(
                    "Err => Skipping Pre-Block {:#?} Executor {:#?}",
                    address,
                    tester.executor.is_some(),
                );
                continue;
            }

            tester
                .executor
                .as_mut()
                .unwrap()
                .state_tree_mut()
                .mutate_actor(create_return.actor_id, |actor_state: &mut ActorState| {
                    actor_state.state = new_evm_state_cid.unwrap();
                    actor_state.sequence = info.nonce;
                    actor_state.balance = TokenAmount::from_atto(
                        BigInt::from_str(&format!("{}", &info.balance)).unwrap(),
                    );
                    Ok(())
                })
                .expect("EVM actor state mutation failed");

            pre_contract_cache.insert(*address, create_return.actor_id);
        }

        let sender_account = unit.transaction.secret_key.map(|trans_sender_key| {
            let priv_key =
                SecretKey::parse(array_ref!(trans_sender_key.as_bytes(), 0, 32)).unwrap();

            tester
                .make_secp256k1_account_v2(priv_key, INITIAL_ACCOUNT_BALANCE.clone())
                .unwrap()
        });

        if sender_account.is_none() {
            warn!("Skipping TestCase invalid sender {:#?}", name,);
            warn!("Path : {:#?}", path);
            continue;
        }

        // Process the "Post" & "transaction" block
        for (spec_name, tests) in &unit.post {
            for test in tests.iter() {
                info!(
                    "Entering Post Block => {:#?} {:#?}",
                    spec_name, test.indexes.data
                );

                if skip_post_test(name.as_ref(), spec_name, test.indexes.data) {
                    continue;
                }

                let gas_limit = *unit.transaction.gas_limit.get(test.indexes.gas).unwrap();
                let gas_limit = u64::try_from(gas_limit).unwrap_or(u64::MAX);
                let _tx_gas_limit = gas_limit;
                let tx_data = unit.transaction.data.get(test.indexes.data).unwrap();
                let _tx_value = *unit.transaction.value.get(test.indexes.value).unwrap();

                // TODO-Review :: `&& !tx_data.is_empty()` how to handle the context with empty
                // transaction data.

                if !(unit.transaction.to.is_some()
                    && pre_contract_cache.contains_key(&unit.transaction.to.unwrap()))
                {
                    warn!(
                        "Skipping TestCase no valid actor {:#?}::{:#?}::{:#?}",
                        name, spec_name, test.indexes.data
                    );
                    warn!("Path : {:#?}", path);
                    warn!("TX len : {:#?}", tx_data.len());
                    continue;
                }

                info!(
                    "Executing TestCase {:#?}::{:#?}::{:#?}",
                    name, spec_name, test.indexes.data
                );
                info!("Path : {:#?}", path);
                info!("TX len : {:#?}", tx_data.len());
                info!(
                    "Tracing Status : {:#?}",
                    tester.executor.as_ref().unwrap().context().tracing
                );

                let raw_params = RawBytes::serialize(ContractParams(tx_data.to_vec())).unwrap();

                let actor_id = pre_contract_cache
                    .get(&unit.transaction.to.unwrap())
                    .unwrap();

                let actor_address = Address::new_id(*actor_id);

                let sender_state = tester
                    .executor
                    .as_mut()
                    .unwrap()
                    .state_tree()
                    .get_actor(sender_account.unwrap().0)
                    .unwrap()
                    .unwrap();

                // ENOUGH_GAS.as_milligas()

                // i64::try_from(tx_gas_limit).unwrap(),

                // Send message
                let message = Message {
                    from: sender_account.unwrap().1,
                    to: actor_address,
                    sequence: sender_state.sequence,
                    gas_limit: ENOUGH_GAS.as_milligas(),
                    method_num: fil_actor_evm::Method::InvokeContract as u64,
                    params: raw_params.clone(),
                    ..Message::default()
                };

                let call_result = tester
                    .executor
                    .as_mut()
                    .unwrap()
                    .execute_message(message, ApplyKind::Explicit, 100)
                    .unwrap();

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

                // TODO :: Howto verify the post.hash ?
            }
        }
    }

    let timer = timer.elapsed();

    *elapsed.lock().unwrap() += timer;

    Ok(())
}

pub fn run(test_files: Vec<PathBuf>, num_threads: usize) -> Result<(), TestError> {
    let endjob = Arc::new(AtomicBool::new(false));
    let console_bar = Arc::new(ProgressBar::new(test_files.len() as u64));
    let mut joins: Vec<std::thread::JoinHandle<Result<(), TestError>>> = Vec::new();
    let queue = Arc::new(Mutex::new((0, test_files.clone())));
    let elapsed = Arc::new(Mutex::new(std::time::Duration::ZERO));

    let num_threads = if num_threads > num_cpus::get() {
        num_cpus::get()
    } else {
        num_threads
    };

    for _ in 0..num_threads {
        let queue = queue.clone();
        let endjob = endjob.clone();
        let console_bar = console_bar.clone();
        let elapsed = elapsed.clone();

        joins.push(
            std::thread::Builder::new()
                .stack_size(50 * 1024 * 1024)
                .spawn(move || loop {
                    let (index, test_path) = {
                        let mut queue = queue.lock().unwrap();
                        if queue.1.len() <= queue.0 {
                            return Ok(());
                        }
                        let test_path = queue.1[queue.0].clone();
                        queue.0 += 1;
                        (queue.0 - 1, test_path)
                    };

                    if endjob.load(Ordering::SeqCst) {
                        return Ok(());
                    }

                    trace!("Calling testfile => {:#?}", test_path);

                    if let Err(err) = execute_test_suit(&test_path, &elapsed) {
                        endjob.store(true, Ordering::SeqCst);
                        error!(
                            "Test Failed => [{:#?}] path:{:#?} err:{:#?}",
                            index, test_path, err
                        );
                        return Err(err);
                    }

                    trace!("TestDone => {:#?}", test_path);
                    console_bar.inc(1);
                })
                .unwrap(),
        );
    }

    for handler in joins {
        handler.join().map_err(|_| TestError::SystemError)??;
    }

    console_bar.finish();
    info!(
        "Finished Processing of {:#?} Files in Time:{:#?}",
        test_files.len(),
        elapsed.lock().unwrap()
    );
    Ok(())
}
