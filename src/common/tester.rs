// Copyright 2021-2023 Protocol Labs
// SPDX-License-Identifier: Apache-2.0, MIT
use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use cid::multihash::{Code, MultihashDigest};
use cid::Cid;
use fil_actor_evm::interpreter::system::StateKamt;
use fil_actor_evm::{BytecodeHash, State as EvmState};
use fil_actors_evm_shared::uints::U256 as evm_U256;
use fvm::call_manager::DefaultCallManager;
use fvm::engine::EnginePool;
use fvm::executor::{ApplyKind, ApplyRet, DefaultExecutor, Executor as FVMExecutor};
use fvm::externs::Externs;
use fvm::machine::{DefaultMachine, Machine, MachineContext, NetworkConfig};
use fvm::state_tree::{ActorState, StateTree};
use fvm::{init_actor, system_actor, DefaultKernel};
use fvm_ipld_blockstore::{Block, Blockstore};
use fvm_ipld_encoding::{ser, CborStore};
use fvm_ipld_kamt::Config as KamtConfig;
use fvm_shared::address::{Address, Protocol};
use fvm_shared::crypto::hash::SupportedHashes;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use fvm_shared::state::StateTreeVersion;
use fvm_shared::version::NetworkVersion;
use fvm_shared::{ActorID, IPLD_RAW};
use lazy_static::lazy_static;
use libsecp256k1::{PublicKey, SecretKey};
use rlp::RlpStream;
use tracing::info;

use super::builtin::{fetch_builtin_code_cid, set_eam_actor, set_init_actor, set_sys_actor};
use super::error::Error;
use super::{merkle_trie, B256, H256, U256};

lazy_static! {
    pub static ref INITIAL_ACCOUNT_BALANCE: TokenAmount = TokenAmount::from_atto(10000 * 10000);
}

pub trait Store: Blockstore + Sized + 'static {}

pub type IntegrationExecutor<B, E> =
    DefaultExecutor<DefaultKernel<DefaultCallManager<DefaultMachine<B, E>>>>;

pub type Account = (ActorID, Address);

pub trait Tester {
    fn create_account(
        &mut self,
        secret_key: SecretKey,
        init_balance: TokenAmount,
    ) -> Result<Account>;
    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> anyhow::Result<ApplyRet>;
    fn code_by_id(&self, id: u32) -> Option<Cid>;
    fn get_actor(&mut self, id: ActorID) -> Result<Option<ActorState>>;
    fn get_actor_id(&mut self, actor_address: &Address) -> Option<ActorID>;
    fn set_actor(&mut self, actor_address: &Address, state: ActorState) -> Result<ActorID>;
    fn init_fevm(
        &mut self,
        code: Bytes,
        nonce: u64,
        storage: &HashMap<U256, U256>,
        kamt_config: KamtConfig,
    ) -> Result<Cid>;
    fn get_fevm_trie_account_rlp(&mut self, id: ActorID, kamt_config: KamtConfig) -> Result<Bytes>;
}

pub struct TesterCore<B, E>
where
    B: Blockstore + 'static,
    E: Externs + 'static,
{
    // Network version used in the test
    nv: NetworkVersion,
    // Builtin actors root Cid used in the Machine
    builtin_actors: Cid,
    // Accounts actor cid
    accounts_code_cid: Cid,
    // Custom code cid deployed by developer
    code_cids: Vec<Cid>,
    // Executor used to interact with deployed actors.
    pub executor: Option<IntegrationExecutor<B, E>>,
    // State tree constructed before instantiating the Machine
    pub state_tree: Option<StateTree<B>>,
}

impl<B, E> TesterCore<B, E>
where
    B: Blockstore + 'static,
    E: Externs + 'static,
{
    pub fn new(
        nv: NetworkVersion,
        stv: StateTreeVersion,
        builtin_actors: Cid,
        blockstore: B,
    ) -> Result<Self> {
        let (manifest_version, manifest_data_cid): (u32, Cid) =
            match blockstore.get_cbor(&builtin_actors)? {
                Some((manifest_version, manifest_data)) => (manifest_version, manifest_data),
                None => return Err(Error::NoManifestInformation(builtin_actors).into()),
            };

        // Get sys and init actors code cid
        let (sys_code_cid, init_code_cid, accounts_code_cid, _placeholder_code_cid, eam_code_cid) =
            fetch_builtin_code_cid(&blockstore, &manifest_data_cid, manifest_version)?;

        // Initialize state tree
        let init_state = init_actor::State::new_test(&blockstore);
        let mut state_tree = StateTree::new(blockstore, stv).map_err(anyhow::Error::from)?;

        // Deploy init, sys, and eam actors
        let sys_state = system_actor::State { builtin_actors };
        set_sys_actor(&mut state_tree, sys_state, sys_code_cid)?;
        set_init_actor(&mut state_tree, init_code_cid, init_state)?;
        set_eam_actor(&mut state_tree, eam_code_cid)?;

        Ok(TesterCore {
            nv,
            builtin_actors,
            executor: None,
            code_cids: vec![],
            state_tree: Some(state_tree),
            accounts_code_cid,
        })
    }

    /// Creates new accounts in the testing context
    /// Inserts the specified number of accounts in the state tree, all with 1000 FIL，returning their IDs and Addresses.
    pub fn create_accounts<const N: usize>(&mut self) -> Result<[Account; N]> {
        use rand::SeedableRng;

        let rng = &mut rand_chacha::ChaCha8Rng::seed_from_u64(8);

        let mut ret: [Account; N] = [(0, Address::default()); N];
        for account in ret.iter_mut().take(N) {
            let priv_key = SecretKey::random(rng);
            *account = self.make_secp256k1_account(priv_key, INITIAL_ACCOUNT_BALANCE.clone())?;
        }
        Ok(ret)
    }

    /// Set a new state in the state tree
    pub fn set_state<S: ser::Serialize>(&mut self, state: &S) -> Result<Cid> {
        // Put state in tree
        let state_cid = self
            .state_tree
            .as_mut()
            .unwrap()
            .store()
            .put_cbor(state, Code::Blake2b256)?;

        Ok(state_cid)
    }

    /// Set a new at a given address, provided with a given token balance
    /// and returns the CodeCID of the installed actor
    pub fn set_actor_from_bin(
        &mut self,
        wasm_bin: &[u8],
        state_cid: Cid,
        actor_address: Address,
        balance: TokenAmount,
    ) -> Result<Cid> {
        // Register actor address (unless it's an ID address)
        let actor_id = match actor_address.id() {
            Ok(id) => id,
            Err(_) => self
                .state_tree
                .as_mut()
                .unwrap()
                .register_new_address(&actor_address)
                .unwrap(),
        };

        // Put the WASM code into the blockstore.
        let code_cid = put_wasm_code(self.state_tree.as_mut().unwrap().store(), wasm_bin)?;

        // Add code cid to list of deployed contract
        self.code_cids.push(code_cid);

        // Initialize actor state
        let actor_state = ActorState::new(
            code_cid,
            state_cid,
            balance,
            1,
            match actor_address.protocol() {
                Protocol::ID | Protocol::Actor => None,
                _ => Some(actor_address),
            },
        );

        // Create actor
        self.state_tree
            .as_mut()
            .unwrap()
            .set_actor(actor_id, actor_state);

        Ok(code_cid)
    }

    /// Sets the Machine and the Executor in our Tester structure.
    pub fn instantiate_machine(&mut self, externs: E, base_fee: TokenAmount) -> Result<()> {
        self.instantiate_machine_with_config(base_fee, externs, |_| (), |_| ())
    }

    /// Sets the Machine and the Executor in our Tester structure.
    ///
    /// The `configure_nc` and `configure_mc` functions allows the caller to adjust the
    /// `NetworkConfiguration` and `MachineContext` before they are used to instantiate
    /// the rest of the components.
    pub fn instantiate_machine_with_config<F, G>(
        &mut self,
        base_fee: TokenAmount,
        externs: E,
        configure_nc: F,
        configure_mc: G,
    ) -> Result<()>
    where
        F: FnOnce(&mut NetworkConfig),
        G: FnOnce(&mut MachineContext),
    {
        // Take the state tree and leave None behind.
        let mut state_tree = self.state_tree.take().unwrap();

        // Calculate the state root.
        let state_root = state_tree
            .flush()
            .map_err(anyhow::Error::from)
            .context(Error::FailedToFlushTree)?;

        // Consume the state tree and take the blockstore.
        let blockstore = state_tree.into_store();

        let mut nc = NetworkConfig::new(self.nv);
        nc.override_actors(self.builtin_actors);
        nc.enable_actor_debugging();

        // Custom configuration.
        configure_nc(&mut nc);

        let mut mc = nc.for_epoch(0, 0, state_root);
        mc.set_base_fee(base_fee).enable_tracing();

        // Custom configuration.
        configure_mc(&mut mc);

        let engine = EnginePool::new_default((&mc.network.clone()).into())?;
        engine.acquire().preload(&blockstore, &self.code_cids)?;

        let machine = DefaultMachine::new(&mc, blockstore, externs)?;

        let executor =
            DefaultExecutor::<DefaultKernel<DefaultCallManager<DefaultMachine<B, E>>>>::new(
                engine, machine,
            )?;

        self.executor = Some(executor);

        Ok(())
    }

    /// Put account with specified private key and balance
    pub fn make_secp256k1_account(
        &mut self,
        priv_key: SecretKey,
        init_balance: TokenAmount,
    ) -> Result<Account> {
        let pub_key = PublicKey::from_secret_key(&priv_key);
        let pub_key_addr = Address::new_secp256k1(&pub_key.serialize())?;

        let state_tree = self
            .state_tree
            .as_mut()
            .ok_or_else(|| anyhow!("unable get state tree"))?;
        let assigned_addr = state_tree.register_new_address(&pub_key_addr).unwrap();
        let state = fvm::account_actor::State {
            address: pub_key_addr,
        };

        let cid = state_tree.store().put_cbor(&state, Code::Blake2b256)?;

        let actor_state = ActorState {
            code: self.accounts_code_cid,
            state: cid,
            sequence: 0,
            balance: init_balance,
            delegated_address: None,
        };

        state_tree.set_actor(assigned_addr, actor_state);

        Ok((assigned_addr, pub_key_addr))
    }

    /// Put account with specified private key and balance
    pub fn make_secp256k1_account_v2(
        &mut self,
        priv_key: SecretKey,
        init_balance: TokenAmount,
    ) -> Result<Account> {
        let pub_key = PublicKey::from_secret_key(&priv_key);
        let pub_key_addr = Address::new_secp256k1(&pub_key.serialize())?;

        let state_tree = self.executor.as_mut().unwrap().state_tree_mut();

        let assigned_addr = state_tree.register_new_address(&pub_key_addr).unwrap();
        let state = fvm::account_actor::State {
            address: pub_key_addr,
        };

        let cid = state_tree.store().put_cbor(&state, Code::Blake2b256)?;

        let actor_state = ActorState {
            code: self.accounts_code_cid,
            state: cid,
            sequence: 0,
            balance: init_balance,
            delegated_address: None,
        };

        state_tree.set_actor(assigned_addr, actor_state);

        Ok((assigned_addr, pub_key_addr))
    }
}

impl<B, E> Tester for TesterCore<B, E>
where
    B: Blockstore + 'static,
    E: Externs + 'static,
{
    fn create_account(
        &mut self,
        secret_key: SecretKey,
        init_balance: TokenAmount,
    ) -> Result<Account> {
        self.make_secp256k1_account_v2(secret_key, init_balance)
    }

    fn execute_message(
        &mut self,
        msg: Message,
        apply_kind: ApplyKind,
        raw_length: usize,
    ) -> Result<ApplyRet> {
        self.executor
            .as_mut()
            .unwrap()
            .execute_message(msg, apply_kind, raw_length)
    }

    fn code_by_id(&self, id: u32) -> Option<Cid> {
        self.executor
            .as_ref()
            .unwrap()
            .builtin_actors()
            .code_by_id(id)
            .copied()
    }

    fn get_actor(&mut self, id: ActorID) -> Result<Option<ActorState>> {
        self.executor
            .as_mut()
            .unwrap()
            .state_tree()
            .get_actor(id)
            .map_err(anyhow::Error::from)
    }

    fn get_actor_id(&mut self, actor_address: &Address) -> Option<ActorID> {
        let state_tree = self.executor.as_mut().unwrap().state_tree_mut();
        state_tree
            .lookup_id(actor_address)
            .expect("failed to lookup actor")
    }

    fn set_actor(&mut self, actor_address: &Address, state: ActorState) -> Result<ActorID> {
        let state_tree = self.executor.as_mut().unwrap().state_tree_mut();

        let actor_id = state_tree
            .lookup_id(actor_address)
            .expect("failed to lookup actor")
            .expect("actor does not exist");

        let _ = state_tree.mutate_actor(actor_id, |actor_state| {
            actor_state.state = state.state;
            actor_state.code = state.code;
            actor_state.sequence = state.sequence;
            actor_state.balance = state.balance;
            Ok(())
        });

        Ok(actor_id)
    }

    fn init_fevm(
        &mut self,
        code: Bytes,
        nonce: u64,
        storage: &HashMap<U256, U256>,
        kamt_config: KamtConfig,
    ) -> Result<Cid> {
        let state_tree = self.executor.as_mut().unwrap().state_tree_mut();

        let hasher = Code::try_from(SupportedHashes::Keccak256 as u64).unwrap();
        let mhash = hasher.digest(&code);
        let digest = mhash.digest();

        let code_cid = state_tree
            .store()
            .put(Code::Blake2b256, &Block::new(IPLD_RAW, code))
            .expect("failed to write bytecode");

        let mut slots = StateKamt::new_with_config(state_tree.store(), kamt_config);

        if !storage.is_empty() {
            storage.iter().for_each(|(k, v)| {
                if *v != U256::ZERO {
                    let _ = slots
                        .set(
                            evm_U256::from_dec_str(&format!("{}", *k)).unwrap(),
                            evm_U256::from_dec_str(&format!("{}", *v)).unwrap(),
                        )
                        .unwrap();
                }
            });
        }

        let evm_state = EvmState {
            bytecode: code_cid,
            bytecode_hash: BytecodeHash::try_from(digest).unwrap(),
            contract_state: slots.flush().expect("failed to flush contract state"),
            nonce,
            tombstone: None,
        };

        state_tree.store().put_cbor(&evm_state, Code::Blake2b256)
    }

    fn get_fevm_trie_account_rlp(&mut self, id: ActorID, kamt_config: KamtConfig) -> Result<Bytes> {
        let state_tree = self.executor.as_mut().unwrap().state_tree_mut();

        let actor_state = state_tree
            .get_actor(id)
            .unwrap()
            .expect("failed to get actor state");

        let evm_state: EvmState = state_tree
            .store()
            .get_cbor(&actor_state.state)
            .unwrap()
            .unwrap();

        let slots =
            StateKamt::load_with_config(&evm_state.contract_state, state_tree.store(), kamt_config)
                .expect("state not in blockstore");

        let mut stream = RlpStream::new_list(4);

        stream.append(&evm_state.nonce);
        info!("nonce :: {:#?}", &actor_state.sequence);

        let balance = format!("{}", &actor_state.balance.atto());
        let balance = primitive_types::U256::from_dec_str(&balance).unwrap();
        stream.append(&balance);
        info!("balance :: {:#?}", &balance);

        let mut slots_entry = vec![];

        slots
            .for_each(|&k, v| {
                let val = primitive_types::U256::from_dec_str(&format!("{}", &v)).unwrap();

                if !val.is_zero() {
                    slots_entry.push((H256::from_slice(&k.to_bytes()), rlp::encode(&val)));
                }
                Ok(())
            })
            .unwrap();

        stream.append(&{
            merkle_trie::sec_trie_root::<merkle_trie::KeccakHasher, _, _, _>(slots_entry.clone())
        });
        info!("slots :: {:#?}", &slots_entry);

        let bytecode_hash = B256::from_slice(evm_state.bytecode_hash.as_slice());

        stream.append(&bytecode_hash.0.as_ref());
        info!(
            "bytecode_hash.0 :: {}",
            hex::encode(bytecode_hash.0.as_ref())
        );

        Ok(stream.out().freeze())
    }
}

/// Inserts the WASM code for the actor into the blockstore.
fn put_wasm_code(blockstore: &impl Blockstore, wasm_binary: &[u8]) -> Result<Cid> {
    let cid = blockstore.put(
        Code::Blake2b256,
        &Block {
            codec: IPLD_RAW,
            data: wasm_binary,
        },
    )?;
    Ok(cid)
}
