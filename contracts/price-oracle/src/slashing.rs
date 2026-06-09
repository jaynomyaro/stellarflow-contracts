//! Slashing module — malicious node collateral slashing (issue #260).
//!
//! When the off-chain monitoring engine flags bad data or extended downtime,
//! governance can penalise a relayer by calling `execute_slash` (direct admin
//! path) or by going through the full propose → vote → execute pipeline
//! (`propose_action` with `action_type = 5`).
//!
//! # Flow
//! 1. Admin(s) call `propose_action(action_type=5, target=bad_relayer, data="<amount>")`.
//! 2. Other admins vote via `vote_for_action`.
//! 3. Once the threshold is met, any admin calls `execute_proposed_action`.
//!    Internally this calls `execute_slash_internal` below.
//!
//! Alternatively, a single authorized admin can call `execute_slash` directly
//! (suitable for single-admin deployments or emergency situations).
//!
//! # Storage layout
//! | Key                              | Type      | Description                              |
//! |----------------------------------|-----------|------------------------------------------|
//! | `DataKey::ProviderStake(addr)`             | `i128`    | Staked collateral per relayer (stroops)          |
//! | `DataKey::ProviderConsecutiveMissedBlocks(addr)` | `u32`     | Consecutive missed-block infractions for a relayer |
//! | `DataKey::ProviderUptimeStreakStart(addr)` | `u64`     | Timestamp when a relayer began a healthy uptime streak |
//! | `DataKey::SlashToken`                      | `Address` | SEP-41 token used for staking/slashing           |
//! | `DataKey::InsuranceReserve`                | `Address` | Destination for slashed funds                    |

use soroban_sdk::{token, Address, Env, String, Symbol};

use crate::types::DataKey;
use crate::Error;
use crate::SlashExecutedEvent;

const UPTIME_RESET_SECONDS: u64 = 48 * 60 * 60;

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read the staked balance for a relayer. Returns 0 if no stake has been deposited.
pub fn get_stake(env: &Env, relayer: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::ProviderStake(relayer.clone()))
        .unwrap_or(0)
}

/// Overwrite the staked balance for a relayer.
fn set_stake(env: &Env, relayer: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::ProviderStake(relayer.clone()), &amount);
}

/// Read the current consecutive missed-block counter for a relayer.
pub fn get_consecutive_missed_blocks(env: &Env, relayer: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::ProviderConsecutiveMissedBlocks(relayer.clone()))
        .unwrap_or(0)
}

/// Overwrite the missed-block counter for a relayer.
fn set_consecutive_missed_blocks(env: &Env, relayer: &Address, count: u32) {
    env.storage().persistent().set(
        &DataKey::ProviderConsecutiveMissedBlocks(relayer.clone()),
        &count,
    );
}

/// Remove the missed-block counter for a relayer.
fn clear_consecutive_missed_blocks(env: &Env, relayer: &Address) {
    env.storage()
        .persistent()
        .remove(&DataKey::ProviderConsecutiveMissedBlocks(relayer.clone()));
}

/// Read the relayer uptime streak start timestamp.
pub fn get_uptime_streak_start(env: &Env, relayer: &Address) -> Option<u64> {
    env.storage()
        .persistent()
        .get(&DataKey::ProviderUptimeStreakStart(relayer.clone()))
}

/// Store or clear a relayer uptime streak start timestamp.
fn set_uptime_streak_start(env: &Env, relayer: &Address, timestamp: Option<u64>) {
    if let Some(ts) = timestamp {
        env.storage()
            .persistent()
            .set(&DataKey::ProviderUptimeStreakStart(relayer.clone()), &ts);
    } else {
        env.storage()
            .persistent()
            .remove(&DataKey::ProviderUptimeStreakStart(relayer.clone()));
    }
}

/// Calculate the exponential slash multiplier from the current consecutive
/// missed-block counter.
///
/// The baseline floor is `1` and the penalty scales exponentially with every
/// additional consecutive missed block.
fn calculate_exponential_multiplier(count: u32) -> Result<i128, Error> {
    if count == 0 {
        return Ok(1);
    }
    let exponent = count.saturating_sub(1);
    if exponent >= 126 {
        return Ok(i128::MAX);
    }
    Ok(1_i128
        .checked_shl(exponent)
        .ok_or(Error::InvalidInfractionCount)?)
}

/// Get the effective slashing multiplier for the relayer.
pub fn get_slash_multiplier(env: &Env, relayer: &Address) -> Result<i128, Error> {
    let count = get_consecutive_missed_blocks(env, relayer);
    calculate_exponential_multiplier(count)
}

/// Report that a relayer missed one or more consecutive blocks.
///
/// This increments the infraction counter and clears any uptime streak. The
/// resulting multiplier will scale future slashes exponentially.
pub fn report_missed_blocks(
    env: &Env,
    relayer: &Address,
    missed_blocks: u32,
) -> Result<i128, Error> {
    if missed_blocks == 0 {
        return Err(Error::InvalidInfractionCount);
    }

    let current = get_consecutive_missed_blocks(env, relayer);
    let next = current
        .checked_add(missed_blocks)
        .ok_or(Error::InvalidInfractionCount)?;
    set_consecutive_missed_blocks(env, relayer, next);
    set_uptime_streak_start(env, relayer, None);

    calculate_exponential_multiplier(next)
}

/// Report a period of uninterrupted uptime for a relayer.
///
/// The relayer's infraction counter is reset only after a full 48-hour streak
/// of healthy uptime.
pub fn report_successful_uptime(env: &Env, relayer: &Address) -> Result<bool, Error> {
    let current = get_consecutive_missed_blocks(env, relayer);
    if current == 0 {
        return Ok(false);
    }

    let now = env.ledger().timestamp();
    match get_uptime_streak_start(env, relayer) {
        None => {
            set_uptime_streak_start(env, relayer, Some(now));
            Ok(false)
        }
        Some(start_ts) => {
            if now >= start_ts.saturating_add(UPTIME_RESET_SECONDS) {
                clear_consecutive_missed_blocks(env, relayer);
                set_uptime_streak_start(env, relayer, None);
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

/// Parse a slash amount from the governance proposal's `data` string.
///
/// The data field is expected to contain a plain decimal integer string,
/// e.g. `"5000000000"` (5 000 000 000 stroops = 500 tokens at 7 decimals).
///
/// Returns `Error::InvalidSlashAmount` if the string is empty, contains
/// non-digit characters, or would overflow `i128`.
pub fn parse_slash_amount(_env: &Env, data: &String) -> Result<i128, Error> {
    let len = data.len() as usize;
    if len == 0 {
        return Err(Error::InvalidSlashAmount);
    }

    // i128::MAX is 39 digits; 40 bytes is a safe upper bound.
    if len > 39 {
        return Err(Error::InvalidSlashAmount);
    }

    // Copy the string bytes into a stack-allocated buffer.
    let mut buf = [0u8; 39];
    data.copy_into_slice(&mut buf[..len]);

    let mut result: i128 = 0;
    for i in 0..len {
        let ch = buf[i];
        if ch < b'0' || ch > b'9' {
            return Err(Error::InvalidSlashAmount);
        }
        let digit = (ch - b'0') as i128;
        result = result
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(Error::InvalidSlashAmount)?;
    }

    if result <= 0 {
        return Err(Error::InvalidSlashAmount);
    }

    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Core slash logic
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a slash against a relayer's staked collateral.
///
/// This is the single authoritative implementation called by both:
/// - `PriceOracle::execute_slash` (direct admin path), and
/// - the `AdminAction::Slash` arm inside `execute_proposed_action` (governance pipeline).
///
/// # Preconditions (checked by callers before this function is invoked)
/// - Contract is not destroyed.
/// - Contract is not frozen.
/// - `executor` has provided auth and is an authorized admin.
///
/// # Checks performed here
/// - `amount` must be > 0.
/// - `SlashToken` must be configured.
/// - `InsuranceReserve` must be configured.
/// - `bad_relayer` must have a stake ≥ the scaled penalty amount.
///
/// The slashing amount is scaled by the relayer's current consecutive missed-
/// block multiplier, which grows exponentially with repeated outages.
///
/// # Effects
/// 1. Calculates the effective slashing penalty after multiplier scaling.
/// 2. Deducts that amount from `bad_relayer`'s on-chain stake balance.
/// 3. Transfers the scaled amount from the contract's custody to the insurance reserve.
/// 4. If the relayer's remaining stake reaches zero, removes them from the
///    active provider whitelist (they can re-stake and be re-added later).
/// 5. Emits a `SlashExecutedEvent`.
pub fn execute_slash_internal(
    env: &Env,
    executor: &Address,
    bad_relayer: &Address,
    amount: i128,
) -> Result<(), Error> {
    // ── Validate amount ──────────────────────────────────────────────────────
    if amount <= 0 {
        return Err(Error::InvalidSlashAmount);
    }

    // ── Compute scaled penalty based on relayer uptime/downtime history. ─────
    let multiplier = get_slash_multiplier(env, bad_relayer)?;
    let slashed_amount = amount
        .checked_mul(multiplier)
        .ok_or(Error::InvalidSlashAmount)?;

    // ── Resolve token and reserve ────────────────────────────────────────────
    let token_address: Address = env
        .storage()
        .persistent()
        .get(&DataKey::SlashToken)
        .ok_or(Error::SlashTokenNotSet)?;

    let reserve: Address = env
        .storage()
        .persistent()
        .get(&DataKey::InsuranceReserve)
        .ok_or(Error::InsuranceReserveNotSet)?;

    // ── Check stake balance ──────────────────────────────────────────────────
    let current_stake = get_stake(env, bad_relayer);
    if slashed_amount > current_stake {
        return Err(Error::InsufficientStake);
    }

    // ── Deduct stake ─────────────────────────────────────────────────────────
    let remaining_stake = current_stake - slashed_amount;
    set_stake(env, bad_relayer, remaining_stake);

    // ── Transfer slashed tokens to the insurance reserve ─────────────────────
    // The contract holds the staked tokens in its own custody, so we transfer
    // from `current_contract_address()` to the reserve.
    let token_client = token::Client::new(env, &token_address);
    token_client.transfer(&env.current_contract_address(), &reserve, &slashed_amount);

    // ── Auto-delist relayer if fully slashed ─────────────────────────────────
    // A relayer with zero stake can no longer be trusted to submit prices.
    // Remove them from the whitelist so they cannot submit until they re-stake
    // and are explicitly re-added by an admin.
    if remaining_stake == 0 {
        crate::auth::_remove_provider(env, bad_relayer);
    }

    // ── Emit event ───────────────────────────────────────────────────────────
    env.events().publish(
        (Symbol::new(env, "slash_executed_event"),),
        (
            bad_relayer.clone(),
            amount,
            reserve.clone(),
            executor.clone(),
        ),
    );

    // Also publish a plain tuple event for off-chain indexers that don't parse
    // the typed event schema.
    env.events().publish(
        (Symbol::new(env, "slash_executed"),),
        (
            bad_relayer.clone(),
            slashed_amount,
            reserve,
            executor.clone(),
            remaining_stake,
        ),
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Deviation-based tiered slashing
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a price submission's deviation from the consensus median.
///
/// Tiers are expressed in basis points (bps), where 100 bps = 1 %.
/// The `Noise` tier (< 50 bps) represents normal network variance and carries
/// no penalty.  Higher tiers indicate increasingly intentional manipulation and
/// attract proportionally larger slash multipliers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeviationTier {
    /// < 50 bps — network noise or minor communication delay.  No penalty.
    Noise,
    /// 50 – 199 bps — minor deviation.  1× base multiplier.
    Minor,
    /// 200 – 499 bps — moderate deviation.  3× base multiplier.
    Moderate,
    /// 500 – 999 bps — significant deviation.  7× base multiplier.
    Significant,
    /// ≥ 1 000 bps — extreme deviation consistent with price manipulation.  15× base multiplier.
    Manipulation,
}

/// Map a raw deviation in basis points to the corresponding [`DeviationTier`].
pub fn classify_deviation(deviation_bps: u32) -> DeviationTier {
    if deviation_bps < 50 {
        DeviationTier::Noise
    } else if deviation_bps < 200 {
        DeviationTier::Minor
    } else if deviation_bps < 500 {
        DeviationTier::Moderate
    } else if deviation_bps < 1_000 {
        DeviationTier::Significant
    } else {
        DeviationTier::Manipulation
    }
}

/// Return the slash multiplier associated with a [`DeviationTier`].
///
/// A multiplier of `0` means no slash is applied (Noise tier).
/// The multiplier is applied on top of the relayer's existing missed-block
/// multiplier inside [`report_price_deviation`], so the total penalty grows
/// proportionally with *both* the severity of the deviation *and* the
/// relayer's prior infraction history.
pub fn deviation_multiplier(tier: DeviationTier) -> i128 {
    match tier {
        DeviationTier::Noise => 0,
        DeviationTier::Minor => 1,
        DeviationTier::Moderate => 3,
        DeviationTier::Significant => 7,
        DeviationTier::Manipulation => 15,
    }
}

/// Evaluate a relayer's price submission against the finalized consensus median
/// and apply a proportional slash when the deviation crosses a meaningful threshold.
///
/// This function distinguishes accidental network hiccups (< 50 bps) from
/// deliberate price manipulation (≥ 1 000 bps), applying a larger penalty the
/// further the submitted price strays from the consensus.
///
/// # Penalty model
/// ```text
/// final_penalty = base_slash_amount × tier_multiplier × missed_blocks_multiplier
/// ```
/// where `tier_multiplier` comes from [`deviation_multiplier`] and
/// `missed_blocks_multiplier` is the exponential penalty already accumulated
/// from the relayer's downtime history (see [`execute_slash_internal`]).
///
/// # Parameters
/// - `executor`: the admin address triggering this evaluation.
/// - `relayer`: the provider whose submission is under review.
/// - `submitted_price`: price the relayer submitted, normalized to 9 decimals.
/// - `consensus_price`: finalized median price at the same precision.
/// - `base_slash_amount`: base token amount to slash before tier scaling.
///
/// # Returns
/// The tier-scaled amount passed to the slash engine (`0` for the Noise tier),
/// or an error.  The actual token deducted from the relayer's stake is
/// `base_slash_amount × tier_multiplier × missed_blocks_multiplier`.
pub fn report_price_deviation(
    env: &Env,
    executor: &Address,
    relayer: &Address,
    submitted_price: i128,
    consensus_price: i128,
    base_slash_amount: i128,
) -> Result<i128, Error> {
    let deviation_bps =
        crate::math::calculate_deviation_bps(submitted_price, consensus_price)?;
    let tier = classify_deviation(deviation_bps);
    let tier_mult = deviation_multiplier(tier);

    // Persist for audit and off-chain indexing regardless of tier.
    env.storage()
        .persistent()
        .set(&DataKey::ProviderLastDeviationBps(relayer.clone()), &deviation_bps);

    // Noise tier — record only, no slash.
    if tier_mult == 0 {
        return Ok(0);
    }

    // Scale the base amount by the tier multiplier.
    // execute_slash_internal will then further multiply by the missed-blocks
    // multiplier, yielding: final = base × tier_mult × missed_blocks_mult.
    let tier_scaled = base_slash_amount
        .checked_mul(tier_mult)
        .ok_or(Error::InvalidSlashAmount)?;

    execute_slash_internal(env, executor, relayer, tier_scaled)?;

    env.events().publish(
        (Symbol::new(env, "deviation_slash"),),
        (
            relayer.clone(),
            submitted_price,
            consensus_price,
            deviation_bps,
            tier_mult,
            tier_scaled,
        ),
    );

    Ok(tier_scaled)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod slashing_tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Env, String};

    // ── parse_slash_amount ────────────────────────────────────────────────────

    #[test]
    fn test_parse_slash_amount_valid() {
        let env = Env::default();
        let s = String::from_str(&env, "5000000000");
        assert_eq!(parse_slash_amount(&env, &s).unwrap(), 5_000_000_000_i128);
    }

    #[test]
    fn test_parse_slash_amount_single_digit() {
        let env = Env::default();
        let s = String::from_str(&env, "1");
        assert_eq!(parse_slash_amount(&env, &s).unwrap(), 1_i128);
    }

    #[test]
    fn test_parse_slash_amount_empty_fails() {
        let env = Env::default();
        let s = String::from_str(&env, "");
        assert_eq!(parse_slash_amount(&env, &s), Err(Error::InvalidSlashAmount));
    }

    #[test]
    fn test_parse_slash_amount_zero_fails() {
        let env = Env::default();
        let s = String::from_str(&env, "0");
        assert_eq!(parse_slash_amount(&env, &s), Err(Error::InvalidSlashAmount));
    }

    #[test]
    fn test_parse_slash_amount_non_digit_fails() {
        let env = Env::default();
        let s = String::from_str(&env, "100abc");
        assert_eq!(parse_slash_amount(&env, &s), Err(Error::InvalidSlashAmount));
    }

    // ── get_stake / set_stake ─────────────────────────────────────────────────

    #[test]
    fn test_get_stake_returns_zero_when_unset() {
        let env = Env::default();
        let relayer = Address::generate(&env);
        assert_eq!(get_stake(&env, &relayer), 0);
    }

    #[test]
    fn test_set_and_get_stake() {
        let env = Env::default();
        let relayer = Address::generate(&env);
        set_stake(&env, &relayer, 1_000_000);
        assert_eq!(get_stake(&env, &relayer), 1_000_000);
    }

    #[test]
    fn test_report_missed_blocks_updates_count_and_multiplier() {
        let env = Env::default();
        let relayer = Address::generate(&env);

        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 0);
        assert_eq!(get_slash_multiplier(&env, &relayer).unwrap(), 1);

        let multiplier = report_missed_blocks(&env, &relayer, 1).unwrap();
        assert_eq!(multiplier, 1);
        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 1);
        assert_eq!(get_slash_multiplier(&env, &relayer).unwrap(), 1);

        let multiplier = report_missed_blocks(&env, &relayer, 1).unwrap();
        assert_eq!(multiplier, 2);
        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 2);
        assert_eq!(get_slash_multiplier(&env, &relayer).unwrap(), 2);
    }

    #[test]
    fn test_report_successful_uptime_resets_after_48_hours() {
        let env = Env::default();
        let relayer = Address::generate(&env);

        report_missed_blocks(&env, &relayer, 2).unwrap();
        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 2);
        assert_eq!(get_slash_multiplier(&env, &relayer).unwrap(), 2);

        env.ledger().set_timestamp(1_000);
        assert_eq!(report_successful_uptime(&env, &relayer).unwrap(), false);
        assert_eq!(get_uptime_streak_start(&env, &relayer), Some(1_000));
        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 2);

        env.ledger().set_timestamp(1_000 + UPTIME_RESET_SECONDS - 1);
        assert_eq!(report_successful_uptime(&env, &relayer).unwrap(), false);
        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 2);

        env.ledger().set_timestamp(1_000 + UPTIME_RESET_SECONDS);
        assert_eq!(report_successful_uptime(&env, &relayer).unwrap(), true);
        assert_eq!(get_consecutive_missed_blocks(&env, &relayer), 0);
        assert_eq!(get_uptime_streak_start(&env, &relayer), None);
        assert_eq!(get_slash_multiplier(&env, &relayer).unwrap(), 1);
    }

    // ── classify_deviation ────────────────────────────────────────────────────

    #[test]
    fn test_classify_deviation_noise() {
        assert_eq!(classify_deviation(0), DeviationTier::Noise);
        assert_eq!(classify_deviation(49), DeviationTier::Noise);
    }

    #[test]
    fn test_classify_deviation_minor() {
        assert_eq!(classify_deviation(50), DeviationTier::Minor);
        assert_eq!(classify_deviation(199), DeviationTier::Minor);
    }

    #[test]
    fn test_classify_deviation_moderate() {
        assert_eq!(classify_deviation(200), DeviationTier::Moderate);
        assert_eq!(classify_deviation(499), DeviationTier::Moderate);
    }

    #[test]
    fn test_classify_deviation_significant() {
        assert_eq!(classify_deviation(500), DeviationTier::Significant);
        assert_eq!(classify_deviation(999), DeviationTier::Significant);
    }

    #[test]
    fn test_classify_deviation_manipulation() {
        assert_eq!(classify_deviation(1_000), DeviationTier::Manipulation);
        assert_eq!(classify_deviation(u32::MAX), DeviationTier::Manipulation);
    }

    // ── deviation_multiplier ──────────────────────────────────────────────────

    #[test]
    fn test_deviation_multiplier_noise_is_zero() {
        assert_eq!(deviation_multiplier(DeviationTier::Noise), 0);
    }

    #[test]
    fn test_deviation_multiplier_tiers() {
        assert_eq!(deviation_multiplier(DeviationTier::Minor), 1);
        assert_eq!(deviation_multiplier(DeviationTier::Moderate), 3);
        assert_eq!(deviation_multiplier(DeviationTier::Significant), 7);
        assert_eq!(deviation_multiplier(DeviationTier::Manipulation), 15);
    }

    // ── calculate_deviation_bps (via math module) ─────────────────────────────

    #[test]
    fn test_deviation_bps_identical_prices() {
        assert_eq!(crate::math::calculate_deviation_bps(10_000, 10_000), Ok(0));
    }

    #[test]
    fn test_deviation_bps_one_percent() {
        // submitted is 1 % above consensus → 100 bps
        assert_eq!(crate::math::calculate_deviation_bps(10_100, 10_000), Ok(100));
    }

    #[test]
    fn test_deviation_bps_below_consensus() {
        // submitted is 2 % below consensus → 200 bps
        assert_eq!(crate::math::calculate_deviation_bps(9_800, 10_000), Ok(200));
    }

    #[test]
    fn test_deviation_bps_zero_consensus_returns_error() {
        assert_eq!(
            crate::math::calculate_deviation_bps(500, 0),
            Err(crate::Error::DeviationConsensusZero)
        );
    }

    #[test]
    fn test_deviation_bps_extreme_submitted_saturates() {
        // i128::MAX submitted vs consensus 1 — overflows internally, saturates to u32::MAX
        let result = crate::math::calculate_deviation_bps(i128::MAX, 1);
        assert_eq!(result, Ok(u32::MAX));
    }
}
