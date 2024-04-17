use crate::constants::FEE_MULTIPLIER;
use crate::errors::LiquidityPoolError;
use crate::plane::update_plane;
use crate::plane_interface::Plane;
use crate::pool;
use crate::pool::get_amount_out;
use crate::pool_interface::{
    LiquidityPoolCrunch, LiquidityPoolTrait, RewardsTrait, UpgradeableContractTrait,
};
use crate::rewards::get_rewards_manager;
use crate::storage::{
    get_fee_fraction, get_plane, get_reserve_a, get_reserve_b, get_router, get_token_a,
    get_token_b, has_plane, put_fee_fraction, put_reserve_a, put_reserve_b, put_token_a,
    put_token_b, set_plane, set_router,
};
use crate::token::{create_contract, get_balance_a, get_balance_b, transfer_a, transfer_b};
use access_control::access::{AccessControl, AccessControlTrait};
use liquidity_pool_events::Events as PoolEvents;
use liquidity_pool_events::LiquidityPoolEvents;
use liquidity_pool_validation_errors::LiquidityPoolValidationError;
use rewards::storage::{PoolRewardConfig, RewardsStorageTrait};
use soroban_fixed_point_math::SorobanFixedPoint;
use soroban_sdk::token::TokenClient as SorobanTokenClient;
use soroban_sdk::{
    contract, contractimpl, contractmeta, panic_with_error, symbol_short, Address, BytesN, Env,
    IntoVal, Map, Symbol, Val, Vec, U256,
};
use token_share::{
    burn_shares, get_balance_shares, get_token_share, get_total_shares, get_user_balance_shares,
    mint_shares, put_token_share, Client as LPTokenClient,
};
use utils::bump::bump_instance;
use utils::u256_math::ExtraMath;

// Metadata that is added on to the WASM custom section
contractmeta!(
    key = "Description",
    val = "Constant product AMM with configurable swap fee"
);

#[contract]
pub struct LiquidityPool;

#[contractimpl]
impl LiquidityPoolCrunch for LiquidityPool {
    fn initialize_all(
        e: Env,
        admin: Address,
        router: Address,
        lp_token_wasm_hash: BytesN<32>,
        tokens: Vec<Address>,
        fee_fraction: u32,
        reward_token: Address,
        plane: Address,
    ) {
        // merge whole initialize process into one because lack of caching of VM components
        // https://github.com/stellar/rs-soroban-env/issues/827
        Self::set_pools_plane(e.clone(), plane);
        Self::initialize(
            e.clone(),
            admin,
            router,
            lp_token_wasm_hash,
            tokens,
            fee_fraction,
        );
        Self::initialize_rewards_config(e.clone(), reward_token);
    }
}

#[contractimpl]
impl LiquidityPoolTrait for LiquidityPool {
    fn pool_type(e: Env) -> Symbol {
        Symbol::new(&e, "constant_product")
    }

    fn initialize(
        e: Env,
        admin: Address,
        router: Address,
        lp_token_wasm_hash: BytesN<32>,
        tokens: Vec<Address>,
        fee_fraction: u32,
    ) {
        let access_control = AccessControl::new(&e);
        if access_control.has_admin() {
            panic_with_error!(&e, LiquidityPoolError::AlreadyInitialized);
        }
        access_control.set_admin(&admin);
        set_router(&e, &router);

        if tokens.len() != 2 {
            panic_with_error!(&e, LiquidityPoolValidationError::WrongInputVecSize);
        }

        let token_a = tokens.get(0).unwrap();
        let token_b = tokens.get(1).unwrap();

        if token_a >= token_b {
            panic_with_error!(&e, LiquidityPoolValidationError::TokensNotSorted);
        }

        let share_contract = create_contract(&e, lp_token_wasm_hash, &token_a, &token_b);
        LPTokenClient::new(&e, &share_contract).initialize(
            &e.current_contract_address(),
            &7u32,
            &"Pool Share Token".into_val(&e),
            &"POOL".into_val(&e),
        );

        // 0.01% = 1; 1% = 100; 0.3% = 30
        if fee_fraction > 9999 {
            panic_with_error!(&e, LiquidityPoolValidationError::FeeOutOfBounds);
        }
        put_fee_fraction(&e, fee_fraction);

        put_token_a(&e, token_a);
        put_token_b(&e, token_b);
        put_token_share(&e, share_contract);
        put_reserve_a(&e, 0);
        put_reserve_b(&e, 0);

        let rewards = get_rewards_manager(&e);
        rewards.manager().initialize();

        // update plane data for every pool update
        update_plane(&e);
    }

    fn share_id(e: Env) -> Address {
        get_token_share(&e)
    }

    fn get_total_shares(e: Env) -> u128 {
        get_total_shares(&e)
    }

    fn get_tokens(e: Env) -> Vec<Address> {
        Vec::from_array(&e, [get_token_a(&e), get_token_b(&e)])
    }

    fn deposit(
        e: Env,
        user: Address,
        desired_amounts: Vec<u128>,
        min_shares: u128,
    ) -> (Vec<u128>, u128) {
        // Depositor needs to authorize the deposit
        user.require_auth();

        if desired_amounts.len() != 2 {
            panic_with_error!(&e, LiquidityPoolValidationError::WrongInputVecSize);
        }

        let (reserve_a, reserve_b) = (get_reserve_a(&e), get_reserve_b(&e));

        // Before actual changes were made to the pool, update total rewards data and refresh/initialize user reward
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        let pool_data = rewards.manager().update_rewards_data(total_shares);
        rewards
            .manager()
            .update_user_reward(&pool_data, &user, user_shares);
        rewards.storage().bump_user_reward_data(&user);

        let desired_a = desired_amounts.get(0).unwrap();
        let desired_b = desired_amounts.get(1).unwrap();

        if (reserve_a == 0 && reserve_b == 0) && (desired_a == 0 || desired_b == 0) {
            panic_with_error!(&e, LiquidityPoolValidationError::AllCoinsRequired);
        }

        let token_a_client = SorobanTokenClient::new(&e, &get_token_a(&e));
        let token_b_client = SorobanTokenClient::new(&e, &get_token_b(&e));
        // transfer full amount then return back remaining parts to have tx auth deterministic
        token_a_client.transfer(&user, &e.current_contract_address(), &(desired_a as i128));
        token_b_client.transfer(&user, &e.current_contract_address(), &(desired_b as i128));

        let (min_a, min_b) = (0, 0);

        // Calculate deposit amounts
        let amounts =
            pool::get_deposit_amounts(&e, desired_a, min_a, desired_b, min_b, reserve_a, reserve_b);

        if amounts.0 < desired_a {
            token_a_client.transfer(
                &e.current_contract_address(),
                &user,
                &((desired_a - amounts.0) as i128),
            );
        }
        if amounts.1 < desired_b {
            token_b_client.transfer(
                &e.current_contract_address(),
                &user,
                &((desired_b - amounts.1) as i128),
            );
        }

        // Now calculate how many new pool shares to mint
        let (balance_a, balance_b) = (get_balance_a(&e), get_balance_b(&e));
        let total_shares = get_total_shares(&e);

        let zero = 0;
        let new_total_shares = if reserve_a > zero && reserve_b > zero {
            let shares_a = balance_a.fixed_mul_floor(&e, total_shares, reserve_a);
            let shares_b = balance_b.fixed_mul_floor(&e, total_shares, reserve_b);
            shares_a.min(shares_b)
        } else {
            // if .mul doesn't fail, sqrt also won't -> safe to unwrap
            U256::from_u128(&e, balance_a)
                .mul(&U256::from_u128(&e, balance_b))
                .sqrt()
                .to_u128()
                .unwrap()
        };

        let shares_to_mint = new_total_shares - total_shares;
        if shares_to_mint < min_shares {
            panic_with_error!(&e, LiquidityPoolValidationError::OutMinNotSatisfied);
        }
        mint_shares(&e, user, shares_to_mint as i128);
        put_reserve_a(&e, balance_a);
        put_reserve_b(&e, balance_b);

        // update plane data for every pool update
        update_plane(&e);

        let amounts_vec = Vec::from_array(&e, [amounts.0, amounts.1]);
        PoolEvents::new(&e).deposit_liquidity(
            Self::get_tokens(e.clone()),
            amounts_vec.clone(),
            shares_to_mint,
        );

        (amounts_vec, shares_to_mint)
    }

    fn swap(
        e: Env,
        user: Address,
        in_idx: u32,
        out_idx: u32,
        in_amount: u128,
        out_min: u128,
    ) -> u128 {
        user.require_auth();

        if in_idx == out_idx {
            panic_with_error!(&e, LiquidityPoolValidationError::CannotSwapSameToken);
        }

        if in_idx > 1 {
            panic_with_error!(&e, LiquidityPoolValidationError::InTokenOutOfBounds);
        }

        if out_idx > 1 {
            panic_with_error!(&e, LiquidityPoolValidationError::OutTokenOutOfBounds);
        }

        let reserve_a = get_reserve_a(&e);
        let reserve_b = get_reserve_b(&e);
        let reserves = Vec::from_array(&e, [reserve_a, reserve_b]);
        let tokens = Self::get_tokens(e.clone());

        let reserve_sell = reserves.get(in_idx).unwrap();
        let reserve_buy = reserves.get(out_idx).unwrap();
        if reserve_sell == 0 || reserve_buy == 0 {
            panic_with_error!(&e, LiquidityPoolValidationError::EmptyPool);
        }

        let (out, fee) = get_amount_out(&e, in_amount, reserve_sell, reserve_buy);

        if out < out_min {
            panic_with_error!(&e, LiquidityPoolValidationError::OutMinNotSatisfied);
        }

        // Transfer the amount being sold to the contract
        let sell_token = tokens.get(in_idx).unwrap();
        let sell_token_client = SorobanTokenClient::new(&e, &sell_token);
        sell_token_client.transfer(&user, &e.current_contract_address(), &(in_amount as i128));

        let (balance_a, balance_b) = (get_balance_a(&e), get_balance_b(&e));

        // residue_numerator and residue_denominator are the amount that the invariant considers after
        // deducting the fee, scaled up by FEE_MULTIPLIER to avoid fractions
        let residue_numerator = FEE_MULTIPLIER - (get_fee_fraction(&e) as u128);
        let residue_denominator = U256::from_u128(&e, FEE_MULTIPLIER);

        let new_invariant_factor = |balance: u128, reserve: u128, out: u128| {
            if balance - reserve > out {
                residue_denominator.mul(&U256::from_u128(&e, reserve)).add(
                    &(U256::from_u128(&e, residue_numerator)
                        .mul(&U256::from_u128(&e, balance - reserve - out))),
                )
            } else {
                residue_denominator
                    .mul(&U256::from_u128(&e, reserve))
                    .add(&residue_denominator.mul(&U256::from_u128(&e, balance)))
                    .sub(&(residue_denominator.mul(&U256::from_u128(&e, reserve + out))))
            }
        };

        let (out_a, out_b) = if out_idx == 0 { (out, 0) } else { (0, out) };

        let new_inv_a = new_invariant_factor(balance_a, reserve_a, out_a);
        let new_inv_b = new_invariant_factor(balance_b, reserve_b, out_b);
        let old_inv_a = residue_denominator.mul(&U256::from_u128(&e, reserve_a));
        let old_inv_b = residue_denominator.mul(&U256::from_u128(&e, reserve_b));

        if new_inv_a.mul(&new_inv_b) < old_inv_a.mul(&old_inv_b) {
            panic_with_error!(&e, LiquidityPoolError::InvariantDoesNotHold);
        }

        if out_idx == 0 {
            transfer_a(&e, user.clone(), out_a);
        } else {
            transfer_b(&e, user.clone(), out_b);
        }

        put_reserve_a(&e, balance_a - out_a);
        put_reserve_b(&e, balance_b - out_b);

        // update plane data for every pool update
        update_plane(&e);

        PoolEvents::new(&e).trade(
            user,
            sell_token,
            tokens.get(out_idx).unwrap(),
            in_amount,
            out,
            fee,
        );

        out
    }

    fn estimate_swap(e: Env, in_idx: u32, out_idx: u32, in_amount: u128) -> u128 {
        if in_idx == out_idx {
            panic_with_error!(&e, LiquidityPoolValidationError::CannotSwapSameToken);
        }

        if in_idx > 1 {
            panic_with_error!(&e, LiquidityPoolValidationError::InTokenOutOfBounds);
        }

        if out_idx > 1 {
            panic_with_error!(&e, LiquidityPoolValidationError::OutTokenOutOfBounds);
        }

        let reserve_a = get_reserve_a(&e);
        let reserve_b = get_reserve_b(&e);
        let reserves = Vec::from_array(&e, [reserve_a, reserve_b]);
        let reserve_sell = reserves.get(in_idx).unwrap();
        let reserve_buy = reserves.get(out_idx).unwrap();

        get_amount_out(&e, in_amount, reserve_sell, reserve_buy).0
    }

    fn withdraw(e: Env, user: Address, share_amount: u128, min_amounts: Vec<u128>) -> Vec<u128> {
        user.require_auth();

        if min_amounts.len() != 2 {
            panic_with_error!(&e, LiquidityPoolValidationError::WrongInputVecSize);
        }

        // Before actual changes were made to the pool, update total rewards data and refresh user reward
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        let pool_data = rewards.manager().update_rewards_data(total_shares);
        rewards
            .manager()
            .update_user_reward(&pool_data, &user, user_shares);
        rewards.storage().bump_user_reward_data(&user);

        // First transfer the pool shares that need to be redeemed
        let share_token_client = SorobanTokenClient::new(&e, &get_token_share(&e));
        share_token_client.transfer(
            &user,
            &e.current_contract_address(),
            &(share_amount as i128),
        );

        let (balance_a, balance_b) = (get_balance_a(&e), get_balance_b(&e));
        let balance_shares = get_balance_shares(&e);
        let total_shares = get_total_shares(&e);

        // Now calculate the withdraw amounts
        let out_a = balance_a.fixed_mul_floor(&e, balance_shares, total_shares);
        let out_b = balance_b.fixed_mul_floor(&e, balance_shares, total_shares);

        let min_a = min_amounts.get(0).unwrap();
        let min_b = min_amounts.get(1).unwrap();

        if out_a < min_a || out_b < min_b {
            panic_with_error!(&e, LiquidityPoolValidationError::OutMinNotSatisfied);
        }

        burn_shares(&e, balance_shares as i128);
        transfer_a(&e, user.clone(), out_a);
        transfer_b(&e, user, out_b);
        put_reserve_a(&e, balance_a - out_a);
        put_reserve_b(&e, balance_b - out_b);

        // update plane data for every pool update
        update_plane(&e);

        let withdraw_amounts = Vec::from_array(&e, [out_a, out_b]);
        PoolEvents::new(&e).withdraw_liquidity(
            Self::get_tokens(e.clone()),
            withdraw_amounts.clone(),
            share_amount,
        );

        withdraw_amounts
    }

    fn get_reserves(e: Env) -> Vec<u128> {
        Vec::from_array(&e, [get_reserve_a(&e), get_reserve_b(&e)])
    }

    fn get_fee_fraction(e: Env) -> u32 {
        // returns fee fraction. 0.01% = 1; 1% = 100; 0.3% = 30
        get_fee_fraction(&e)
    }

    fn get_info(e: Env) -> Map<Symbol, Val> {
        let fee = get_fee_fraction(&e);
        let pool_type = Self::pool_type(e.clone());
        let mut result = Map::new(&e);
        result.set(symbol_short!("pool_type"), pool_type.into_val(&e));
        result.set(symbol_short!("fee"), fee.into_val(&e));
        result
    }
}

impl UpgradeableContractTrait for LiquidityPool {
    fn version() -> u32 {
        100
    }

    fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        let access_control = AccessControl::new(&e);
        access_control.require_admin();
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

#[contractimpl]
impl RewardsTrait for LiquidityPool {
    fn initialize_rewards_config(e: Env, reward_token: Address) {
        let rewards = get_rewards_manager(&e);
        if rewards.storage().has_reward_token() {
            panic_with_error!(&e, LiquidityPoolError::RewardsAlreadyInitialized);
        }

        rewards.storage().put_reward_token(reward_token);
    }

    fn set_rewards_config(
        e: Env,
        admin: Address,
        expired_at: u64, // timestamp
        tps: u128,       // value with 7 decimal places. example: 600_0000000
    ) {
        admin.require_auth();

        // either admin or router can set the rewards config
        if admin != get_router(&e) {
            AccessControl::new(&e).check_admin(&admin);
        }

        if expired_at < e.ledger().timestamp() {
            panic_with_error!(&e, LiquidityPoolValidationError::PastTimeNotAllowed);
        }

        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        rewards.manager().update_rewards_data(total_shares);

        let config = PoolRewardConfig { tps, expired_at };
        bump_instance(&e);
        rewards.storage().set_pool_reward_config(&config);
    }

    fn get_rewards_info(e: Env, user: Address) -> Map<Symbol, i128> {
        let rewards = get_rewards_manager(&e);
        let config = rewards.storage().get_pool_reward_config();
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        let pool_data = rewards.manager().update_rewards_data(total_shares);
        let user_data = rewards
            .manager()
            .update_user_reward(&pool_data, &user, user_shares);
        let mut result = Map::new(&e);
        result.set(symbol_short!("tps"), config.tps as i128);
        result.set(symbol_short!("exp_at"), config.expired_at as i128);
        result.set(symbol_short!("acc"), pool_data.accumulated as i128);
        result.set(symbol_short!("last_time"), pool_data.last_time as i128);
        result.set(
            symbol_short!("pool_acc"),
            user_data.pool_accumulated as i128,
        );
        result.set(symbol_short!("block"), pool_data.block as i128);
        result.set(symbol_short!("usr_block"), user_data.last_block as i128);
        result.set(symbol_short!("to_claim"), user_data.to_claim as i128);
        result
    }

    fn get_user_reward(e: Env, user: Address) -> u128 {
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        rewards
            .manager()
            .get_amount_to_claim(&user, total_shares, user_shares)
    }

    fn claim(e: Env, user: Address) -> u128 {
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        let reward = rewards
            .manager()
            .claim_reward(&user, total_shares, user_shares);
        rewards.storage().bump_user_reward_data(&user);
        reward
    }
}

#[contractimpl]
impl Plane for LiquidityPool {
    fn set_pools_plane(e: Env, plane: Address) {
        if has_plane(&e) {
            panic_with_error!(&e, LiquidityPoolError::PlaneAlreadyInitialized);
        }

        set_plane(&e, &plane);
    }
    fn get_pools_plane(e: Env) -> Address {
        get_plane(&e)
    }
}
