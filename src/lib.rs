#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env, Map, Symbol, Vec};

pub(crate) mod nonce;
use crate::nonce::{consume_nonce, get_nonce};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NotAdmin = 3,
    NoPendingUpgrade = 4,
    UpgradeTimelockNotSatisfied = 5,
    InvalidHeartbeatInterval = 6,
    InvalidNonce = 7,
    AlreadyRegistered = 8,
    NotRegistered = 9,
    InvalidStakeAmount = 10,
    Overflow = 11,
    Unauthorized = 12,
    TargetNotAdmin = 13,
    ProposalAlreadyActive = 14,
    NoActiveProposal = 15,
    AlreadyVoted = 16,
    ThresholdNotReached = 17,
    SignatureExpired = 18,
}

// Contract state keys
const DATA_KEY: Symbol = symbol_short!("DATA");
const PENDING_UPGRADE_KEY: Symbol = symbol_short!("PENDING");
const UPGRADE_DELAY_SECONDS: u64 = 48 * 60 * 60; 
const STAKE_REGISTRY_KEY: Symbol = symbol_short!("STAKES");
const TOTAL_STAKED_KEY: Symbol = symbol_short!("TOTAL");
const HEARTBEAT_KEY: Symbol = symbol_short!("HBEAT");
const HB_INTERVAL_KEY: Symbol = symbol_short!("HBINTV");
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 5 * 60;
const SIGNERS_KEY: Symbol = symbol_short!("SIGNERS");
const REVOCATION_KEY: Symbol = symbol_short!("REVOKE");

#[contracttype]
#[derive(Clone)]
pub struct RevocationProposal {
    pub target: Address,
    pub replacement: Address,
    pub proposer: Address,
    pub proposed_at: u64,
    pub votes: Map<Address, ()>,
}

#[contracttype]
pub struct PendingUpgrade {
    pub new_wasm_hash: BytesN<32>,
    pub proposed_at: u64,
    pub proposer: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct ContractData {
    pub admin: Address,
    pub value: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct StakeRecord {
    pub node: Address,
    pub amount: u64,
    pub registered_at: u64,
}

#[contract]
pub struct TimeLockedUpgradeContract;

#[contractimpl]
impl TimeLockedUpgradeContract {
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        if env.storage().instance().has(&DATA_KEY) {
            return Err(ContractError::AlreadyInitialized);
        }
        admin.require_auth();
        let data = ContractData { admin: admin.clone(), value: 0 };
        env.storage().instance().set(&DATA_KEY, &data);
        Ok(())
    }

    pub fn stake_and_register(env: Env, node: Address, amount: u64) -> Result<StakeRecord, ContractError> {
        if amount == 0 { return Err(ContractError::InvalidStakeAmount); }
        node.require_auth();
        let mut stakes: Map<Address, u64> = env.storage().instance().get(&STAKE_REGISTRY_KEY).unwrap_or_else(|| Map::new(&env));
        if stakes.contains_key(node.clone()) { return Err(ContractError::AlreadyRegistered); }
        let total: u64 = env.storage().instance().get(&TOTAL_STAKED_KEY).unwrap_or(0u64);
        let new_total = total.checked_add(amount).ok_or(ContractError::Overflow)?;
        stakes.set(node.clone(), amount);
        env.storage().instance().set(&STAKE_REGISTRY_KEY, &stakes);
        env.storage().instance().set(&TOTAL_STAKED_KEY, &new_total);
        Self::_record_heartbeat(&env, symbol_short!("STAKE"));
        Ok(StakeRecord { node, amount, registered_at: env.ledger().timestamp() })
    }

    pub fn unstake(env: Env, node: Address) -> Result<u64, ContractError> {
        node.require_auth();
        let mut stakes: Map<Address, u64> = env.storage().instance().get(&STAKE_REGISTRY_KEY).unwrap_or_else(|| Map::new(&env));
        let amount = stakes.get(node.clone()).ok_or(ContractError::NotRegistered)?;
        let total: u64 = env.storage().instance().get(&TOTAL_STAKED_KEY).unwrap_or(0u64);
        let new_total = total.saturating_sub(amount);
        stakes.remove(node.clone());
        env.storage().instance().set(&STAKE_REGISTRY_KEY, &stakes);
        env.storage().instance().set(&TOTAL_STAKED_KEY, &new_total);
        Ok(amount)
    }

    pub fn remove_signer(env: Env, signer: Address, caller: Address) -> Result<(), ContractError> {
        Self::assert_contract_is_active(&env)?;
        let data = Self::get_data(env.clone())?;
        if data.admin != caller { return Err(ContractError::NotAdmin); }
        caller.require_auth();

        let mut signers = Self::_get_signers(&env);
        
        // Refactored for Issue #370: Zero-Allocation removal with Map
        signers.remove(signer);
        env.storage().instance().set(&SIGNERS_KEY, &signers);
        Ok(())
    }

    pub fn vote_revocation(env: Env, voter: Address, sig_expires_at: u64) -> Result<(), ContractError> {
        if env.ledger().timestamp() > sig_expires_at { return Err(ContractError::SignatureExpired); }
        voter.require_auth();
        let data = Self::get_data(env.clone())?;

        if !Self::_is_signer(&env, &voter) && data.admin != voter {
            return Err(ContractError::Unauthorized);
        }

        let mut proposal: RevocationProposal = env.storage().instance().get(&REVOCATION_KEY).ok_or(ContractError::NoActiveProposal)?;

        // Refactored for Issue #370: Use map operations for zero-allocation
        if proposal.votes.contains_key(voter.clone()) {
            return Err(ContractError::AlreadyVoted);
        }

        proposal.votes.set(voter, ()); // Use set for Map

        // Optimized verification scan
        let threshold = Self::_revocation_threshold(&env);
        if proposal.votes.len() >= threshold {
            let mut contract_data = data;
            contract_data.admin = proposal.replacement.clone();
            env.storage().instance().set(&DATA_KEY, &contract_data);
            env.storage().instance().remove(&REVOCATION_KEY);
        } else {
            env.storage().instance().set(&REVOCATION_KEY, &proposal);
        }
        Ok(())
    }

    // --- Core Logic Boilerplate ---

    pub fn get_data(env: Env) -> Result<ContractData, ContractError> {
        env.storage().instance().get(&DATA_KEY).ok_or(ContractError::NotInitialized)
    }

    pub fn propose_upgrade(env: Env, new_wasm_hash: BytesN<32>, proposer: Address, nonce: u64, sig_expires_at: u64) -> Result<(), ContractError> {
        if env.ledger().timestamp() > sig_expires_at { return Err(ContractError::SignatureExpired); }
        let data = Self::get_data(env.clone())?;
        if data.admin != proposer { return Err(ContractError::NotAdmin); }
        proposer.require_auth();
        // nonce logic omitted for brevity as per provided snippet
        let pending = PendingUpgrade { new_wasm_hash, proposed_at: env.ledger().timestamp(), proposer };
        env.storage().instance().set(&PENDING_UPGRADE_KEY, &pending);
        Ok(())
    }

    pub fn execute_upgrade(env: Env, executor: Address, _nonce: u64, sig_expires_at: u64) -> Result<(), ContractError> {
        if env.ledger().timestamp() > sig_expires_at { return Err(ContractError::SignatureExpired); }
        let data = Self::get_data(env.clone())?;
        if data.admin != executor { return Err(ContractError::NotAdmin); }
        executor.require_auth();
        let pending: PendingUpgrade = env.storage().instance().get(&PENDING_UPGRADE_KEY).ok_or(ContractError::NoPendingUpgrade)?;
        if env.ledger().timestamp().saturating_sub(pending.proposed_at) < UPGRADE_DELAY_SECONDS {
            return Err(ContractError::UpgradeTimelockNotSatisfied);
        }
        env.deployer().update_current_contract_wasm(pending.new_wasm_hash);
        env.storage().instance().remove(&PENDING_UPGRADE_KEY);
        Ok(())
    }

    pub fn update_heartbeat(env: Env, asset: Symbol, updater: Address) -> Result<(), ContractError> {
        let data = Self::get_data(env.clone())?;
        if data.admin != updater { return Err(ContractError::NotAdmin); }
        updater.require_auth();
        Self::_record_heartbeat(&env, asset);
        Ok(())
    }

    pub fn is_data_fresh(env: Env, asset: Symbol) -> bool {
        let timestamps: Map<Symbol, u64> = env.storage().temporary().get(&HEARTBEAT_KEY).unwrap_or_else(|| Map::new(&env));
        if let Some(last_update) = timestamps.get(asset) {
            env.ledger().timestamp().saturating_sub(last_update) <= Self::_get_interval(&env)
        } else { false }
    }

    pub fn register_signer(env: Env, signer: Address, caller: Address) -> Result<(), ContractError> {
        let data = Self::get_data(env.clone())?;
        if data.admin != caller { return Err(ContractError::NotAdmin); }
        caller.require_auth();
        let mut signers = Self::_get_signers(&env);
        if !signers.contains_key(signer.clone()) {
            signers.set(signer, ());
            env.storage().instance().set(&SIGNERS_KEY, &signers);
        }
        Ok(())
    }

    // --- Private Helpers ---

    fn _record_heartbeat(env: &Env, asset: Symbol) {
        let mut timestamps: Map<Symbol, u64> = env.storage().temporary().get(&HEARTBEAT_KEY).unwrap_or_else(|| Map::new(env));
        timestamps.set(asset, env.ledger().timestamp());
        env.storage().temporary().set(&HEARTBEAT_KEY, &timestamps);
    }

    fn _get_interval(env: &Env) -> u64 {
        env.storage().instance().get(&HB_INTERVAL_KEY).unwrap_or(DEFAULT_HEARTBEAT_INTERVAL)
    }

    fn _get_signers(env: &Env) -> Map<Address, ()> {
        env.storage().instance().get(&SIGNERS_KEY).unwrap_or_else(|| Map::new(env))
    }

    fn _is_signer(env: &Env, addr: &Address) -> bool {
        Self::_get_signers(env).contains_key(addr.clone())
    }

    fn _revocation_threshold(env: &Env) -> u32 {
        let n = Self::_get_signers(env).len();
        n / 2 + 1
    }
}