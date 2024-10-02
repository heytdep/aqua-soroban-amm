use crate::constants::FEE_MULTIPLIER;
use crate::errors::LiquidityPoolError;
use crate::plane::update_plane;
use crate::plane_interface::Plane;
use crate::pool;
use crate::pool::get_amount_out;
use crate::pool_interface::{
    AdminInterfaceTrait, LiquidityPoolCrunch, LiquidityPoolTrait, RewardsTrait,
    UpgradeableContractTrait,
};
use crate::rewards::get_rewards_manager;
use crate::storage::{
    get_fee_fraction, get_is_killed_claim, get_is_killed_deposit, get_is_killed_swap, get_plane,
    get_reserve_a, get_reserve_b, get_router, get_token_a, get_token_b, has_plane,
    put_fee_fraction, put_reserve_a, put_reserve_b, put_token_a, put_token_b, set_is_killed_claim,
    set_is_killed_deposit, set_is_killed_swap, set_plane, set_router,
};
use crate::token::{create_contract, transfer_a, transfer_b};
use access_control::access::{AccessControl, AccessControlTrait};
use liquidity_pool_events::Events as PoolEvents;
use liquidity_pool_events::LiquidityPoolEvents;
use liquidity_pool_validation_errors::LiquidityPoolValidationError;
use rewards::storage::RewardsStorageTrait;
use soroban_fixed_point_math::SorobanFixedPoint;
use soroban_sdk::token::TokenClient as SorobanTokenClient;
use soroban_sdk::{
    contract, contractimpl, contractmeta, contracttype, panic_with_error, symbol_short, Address,
    BytesN, Env, IntoVal, Map, String, Symbol, Val, Vec, U256,
};
use token_share::{
    burn_shares, get_balance_shares, get_token_share, get_total_shares, get_user_balance_shares,
    mint_shares, put_token_share, Client as LPTokenClient,
};
use utils::u256_math::ExtraMath;

mod reflector_oracle {
    use soroban_sdk::{
        contracttype, symbol_short, token::TokenClient, Address, IntoVal, String, Symbol, Val,
    };

    // CCYOZJCOPG34LLQQ7N24YXBM7LL62R7ONMZ3G6WZAAYPB5OYKOMJRN63 on testnet
    const REFLECTOR_ORACLE_OFFCHAIN_PRICES: &'static str = env!("REFLECTOR_ORACLE_OFFCHAIN_PRICES");

    // CAVLP5DH2GJPZMVO7IJY4CVOD5MWEFTJFVPD2YY2FQXOQHRGHK4D6HLP on testnet
    const REFLECTOR_ORACLE_PUBNET_PRICES: &'static str = env!("REFLECTOR_ORACLE_PUBNET_PRICES");

    #[contracttype]
    pub struct PriceData {
        price: i128,    //asset price at given point in time
        timestamp: u64, //recording timestamp
    }

    #[contracttype]
    enum Asset {
        Stellar(Address), //for Stellar Classic and Soroban assets
        Other(Symbol),    //for any external tokens/assets/symbols
    }

    pub fn get_token_amount_in_usdc_value(
        e: &Env,
        token_client: &TokenClient,
        amount: u128,
    ) -> u128 {
        let token_symbol = token_client.symbol();

        let asset = if token_symbol == String::from_str(&e, "BTC") {
            Some(Asset::Other(symbol_short!("BTC")))
        } else if token_symbol == String::from_str(&e, "ETH") {
            Some(Asset::Other(symbol_short!("ETH")))
        } else if token_symbol == String::from_str(&e, "USDT") {
            Some(Asset::Other(symbol_short!("USDT")))
        } else if token_symbol == String::from_str(&e, "XRP") {
            Some(Asset::Other(symbol_short!("XRP")))
        } else if token_symbol == String::from_str(&e, "SOL") {
            Some(Asset::Other(symbol_short!("SOL")))
        } else if token_symbol == String::from_str(&e, "USDC") {
            Some(Asset::Other(symbol_short!("USDC")))
        } else if token_symbol == String::from_str(&e, "ADA") {
            Some(Asset::Other(symbol_short!("ADA")))
        } else if token_symbol == String::from_str(&e, "AVAX") {
            Some(Asset::Other(symbol_short!("AVAX")))
        } else if token_symbol == String::from_str(&e, "DOT") {
            Some(Asset::Other(symbol_short!("DOT")))
        } else if token_symbol == String::from_str(&e, "MATIC") {
            Some(Asset::Other(symbol_short!("MATIC")))
        } else if token_symbol == String::from_str(&e, "LINK") {
            Some(Asset::Other(symbol_short!("LINK")))
        } else if token_symbol == String::from_str(&e, "DAI") {
            Some(Asset::Other(symbol_short!("DAI")))
        } else if token_symbol == String::from_str(&e, "ATOM") {
            Some(Asset::Other(symbol_short!("ATOM")))
        } else if token_symbol == String::from_str(&e, "native") {
            Some(Asset::Other(symbol_short!("XLM")))
        } else if token_symbol == String::from_str(&e, "UNI") {
            Some(Asset::Other(symbol_short!("UNI")))
        } else if token_symbol == String::from_str(&e, "EURC") {
            Some(Asset::Other(symbol_short!("EURC")))
        } else {
            None
        };

        // This should only be for testnet
        let token_address = if token_client.address
            == Address::from_string(&String::from_str(
                &e,
                "CDNVQW44C3HALYNVQ4SOBXY5EWYTGVYXX6JPESOLQDABJI5FC5LTRRUE",
            )) {
            Address::from_string(&String::from_str(
                &e,
                "CDJF2JQINO7WRFXB2AAHLONFDPPI4M3W2UM5THGQQ7JMJDIEJYC4CMPG",
            ))
        } else {
            token_client.address.clone()
        };

        let result = if let Some(asset) = asset {
            let last_timestamp = e.try_invoke_contract::<u64, Val>(
                &Address::from_string(&String::from_str(&e, REFLECTOR_ORACLE_OFFCHAIN_PRICES)),
                &Symbol::new(&e, "last_timestamp"),
                ().into_val(e),
            );

            e.try_invoke_contract::<Option<PriceData>, Val>(
                &Address::from_string(&String::from_str(&e, REFLECTOR_ORACLE_OFFCHAIN_PRICES)),
                &symbol_short!("price"),
                (asset, last_timestamp.unwrap().unwrap()).into_val(e),
            )
        } else {
            let last_timestamp = e.try_invoke_contract::<u64, Val>(
                &Address::from_string(&String::from_str(&e, REFLECTOR_ORACLE_PUBNET_PRICES)),
                &Symbol::new(&e, "last_timestamp"),
                ().into_val(e),
            );

            e.try_invoke_contract::<Option<PriceData>, Val>(
                &Address::from_string(&String::from_str(&e, REFLECTOR_ORACLE_PUBNET_PRICES)),
                &symbol_short!("price"),
                (
                    Asset::Stellar(token_address),
                    last_timestamp.unwrap().unwrap(),
                )
                    .into_val(e),
            )
        };

        let in_amount_usd_stellar_oracle = if let Ok(Ok(Some(price))) = result {
            price.price
        } else if let Ok(Ok(None)) = result {
            0
        } else {
            0
        };

        let in_amount_usd_stellar_oracle =
            (in_amount_usd_stellar_oracle as u128).fixed_mul_ceil(&e, &amount, &100000000000000);

        in_amount_usd_stellar_oracle
    }
}

#[cfg(feature = "mercury")]
mod retroshades {
    use retroshade_sdk::Retroshade;
    use soroban_sdk::{contracttype, Address, Symbol, Vec, U256};

    #[derive(Retroshade)]
    #[contracttype]
    pub struct TvlEvent {
        pub pool_address: Address,
        pub user_address: Address,
        pub token_a: Address,
        pub token_b: Address,
        pub reserve_a: u128,
        pub reserve_b: u128,
        pub total_shares: u128,
        pub tvl_ratio: U256,
        pub fee_fraction: u32,
        pub pool_type: Symbol,
        pub action: Symbol,       // "deposit", "withdraw", or "update"
        pub amount_a: u128,       // amount deposited or withdrawn (if applicable)
        pub amount_b: u128,       // amount deposited or withdrawn (if applicable)
        pub shares_changed: u128, // shares minted or burned (if applicable)
        pub ledger: u32,
        pub timestamp: u64,

        pub usdc_reserve_a: u128,
        pub usdc_reserve_b: u128,
        pub usdc_volume: u128,
        pub usdc_tvl_after: u128,
    }

    #[derive(Retroshade)]
    #[contracttype]
    pub struct SwapEvent {
        pub pool_address: Address,
        pub user: Address,
        pub sell_token: Address,
        pub buy_token: Address,
        pub sell_amount: u128,
        pub buy_amount: u128,
        pub ledger: u32,
        pub timestamp: u64,

        pub admin_fee: u128,
        pub lp_fee: u128,
        pub usdc_admin_fee: u128,
        pub usdc_lp_fee: u128,

        pub total_shares: u128,
        pub accomulated: u128,
        pub accomulated_delta: u128,

        pub claimed: u128,
        pub usdc_accomulated: u128,
        pub usdc_claimed: u128,
        pub current_reward_block: u64,
        pub last_claimed_at: u64,
    }

    #[derive(Retroshade)]
    #[contracttype]
    pub struct YieldEvent {
        pub pool_address: Address,
        pub action: Symbol, // "config", "claim", or "update"
        pub user: Address,
        pub reward_token: Address,
        pub amount: u128,
        pub usdc_amount: u128,
        pub tps: u128,
        pub expired_at: u64,
        pub total_shares: u128,
        pub user_shares: u128,
        pub total_accumulated_reward: u128,
        pub total_configured_reward: u128,
        pub total_claimed_reward: u128,
        pub ledger: u32,
        pub timestamp: u64,
    }
}

// Metadata that is added on to the WASM custom section
contractmeta!(
    key = "Description",
    val = "Constant product AMM with configurable swap fee"
);

#[contract]
pub struct LiquidityPool;

#[contractimpl]
impl LiquidityPoolCrunch for LiquidityPool {
    // Initializes all the components of the liquidity pool.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin user.
    // * `router` - The address of the router.
    // * `lp_token_wasm_hash` - The hash of the liquidity pool token contract.
    // * `tokens` - A vector of token addresses.
    // * `fee_fraction` - The fee fraction for the pool.
    // * `reward_token` - The address of the reward token.
    // * `plane` - The address of the plane.
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
        Self::init_pools_plane(e.clone(), plane);
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
    // Returns the type of the pool.
    //
    // # Returns
    //
    // The type of the pool as a Symbol.
    fn pool_type(e: Env) -> Symbol {
        Symbol::new(&e, "constant_product")
    }

    // Initializes the liquidity pool.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin user.
    // * `router` - The address of the router.
    // * `lp_token_wasm_hash` - The hash of the liquidity pool token contract.
    // * `tokens` - A vector of token addresses.
    // * `fee_fraction` - The fee fraction for the pool.
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

        // update plane data for every pool update
        update_plane(&e);
    }

    // Returns the pool's share token address.
    //
    // # Returns
    //
    // The pool's share token as an Address.
    fn share_id(e: Env) -> Address {
        get_token_share(&e)
    }

    // Returns the total shares of the pool.
    //
    // # Returns
    //
    // The total shares of the pool as a u128.
    fn get_total_shares(e: Env) -> u128 {
        get_total_shares(&e)
    }

    // Returns the pool's tokens.
    //
    // # Returns
    //
    // A vector of token addresses.
    fn get_tokens(e: Env) -> Vec<Address> {
        Vec::from_array(&e, [get_token_a(&e), get_token_b(&e)])
    }

    // Deposits tokens into the pool.
    //
    // # Arguments
    //
    // * `user` - The address of the user depositing the tokens.
    // * `desired_amounts` - A vector of desired amounts of each token to deposit.
    // * `min_shares` - The minimum amount of pool tokens to mint.
    //
    // # Returns
    //
    // A tuple containing a vector of actual amounts of each token deposited and a u128 representing the amount of pool tokens minted.
    fn deposit(
        e: Env,
        user: Address,
        desired_amounts: Vec<u128>,
        min_shares: u128,
    ) -> (Vec<u128>, u128) {
        // Depositor needs to authorize the deposit
        user.require_auth();

        if get_is_killed_deposit(&e) {
            panic_with_error!(e, LiquidityPoolError::PoolDepositKilled);
        }

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

        // Increase reserves
        put_reserve_a(&e, reserve_a + amounts.0);
        put_reserve_b(&e, reserve_b + amounts.1);

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
        let (new_reserve_a, new_reserve_b) = (get_reserve_a(&e), get_reserve_b(&e));
        let total_shares = get_total_shares(&e);

        let zero = 0;
        let new_total_shares = if reserve_a > zero && reserve_b > zero {
            let shares_a = new_reserve_a.fixed_mul_floor(&e, &total_shares, &reserve_a);
            let shares_b = new_reserve_b.fixed_mul_floor(&e, &total_shares, &reserve_b);
            shares_a.min(shares_b)
        } else {
            // if .mul doesn't fail, sqrt also won't -> safe to unwrap
            U256::from_u128(&e, new_reserve_a)
                .mul(&U256::from_u128(&e, new_reserve_b))
                .sqrt()
                .to_u128()
                .unwrap()
        };

        let shares_to_mint = new_total_shares - total_shares;
        if shares_to_mint < min_shares {
            panic_with_error!(&e, LiquidityPoolValidationError::OutMinNotSatisfied);
        }
        mint_shares(&e, user.clone(), shares_to_mint as i128);
        put_reserve_a(&e, new_reserve_a);
        put_reserve_b(&e, new_reserve_b);

        // update plane data for every pool update
        update_plane(&e);

        let amounts_vec = Vec::from_array(&e, [amounts.0, amounts.1]);
        PoolEvents::new(&e).deposit_liquidity(
            Self::get_tokens(e.clone()),
            amounts_vec.clone(),
            shares_to_mint,
        );

        #[cfg(feature = "mercury")]
        let usdc_volume =
            reflector_oracle::get_token_amount_in_usdc_value(&e, &token_a_client, amounts.0)
                + reflector_oracle::get_token_amount_in_usdc_value(&e, &token_b_client, amounts.1);
        {
            retroshades::TvlEvent {
                pool_address: e.current_contract_address(),
                user_address: user,
                token_a: get_token_a(&e),
                token_b: get_token_b(&e),
                reserve_a: new_reserve_a,
                reserve_b: new_reserve_b,
                total_shares: new_total_shares,
                tvl_ratio: U256::from_u128(&e, get_reserve_a(&e))
                    .div(&U256::from_u128(&e, get_reserve_b(&e))),
                fee_fraction: get_fee_fraction(&e),
                pool_type: Self::pool_type(e.clone()),
                action: Symbol::new(&e, "deposit"),
                amount_a: amounts.0,
                amount_b: amounts.1,
                shares_changed: shares_to_mint,
                ledger: e.ledger().sequence(),
                timestamp: e.ledger().timestamp(),

                usdc_volume,
                usdc_tvl_after: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_a_client,
                    new_reserve_a,
                ) + reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_b_client,
                    new_reserve_b,
                ),
                usdc_reserve_a: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_a_client,
                    new_reserve_a,
                ),
                usdc_reserve_b: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_b_client,
                    new_reserve_b,
                ),
            }
            .emit(&e);
        }

        (amounts_vec, shares_to_mint)
    }

    // Swaps tokens in the pool.
    //
    // # Arguments
    //
    // * `user` - The address of the user swapping the tokens.
    // * `in_idx` - The index of the input token to be swapped.
    // * `out_idx` - The index of the output token to be received.
    // * `in_amount` - The amount of the input token to be swapped.
    // * `out_min` - The minimum amount of the output token to be received.
    //
    // # Returns
    //
    // The amount of the output token received.
    fn swap(
        e: Env,
        user: Address,
        in_idx: u32,
        out_idx: u32,
        in_amount: u128,
        out_min: u128,
    ) -> u128 {
        user.require_auth();

        if get_is_killed_swap(&e) {
            panic_with_error!(e, LiquidityPoolError::PoolSwapKilled);
        }

        if in_idx == out_idx {
            panic_with_error!(&e, LiquidityPoolValidationError::CannotSwapSameToken);
        }

        if in_idx > 1 {
            panic_with_error!(&e, LiquidityPoolValidationError::InTokenOutOfBounds);
        }

        if out_idx > 1 {
            panic_with_error!(&e, LiquidityPoolValidationError::OutTokenOutOfBounds);
        }

        if in_amount == 0 {
            panic_with_error!(e, LiquidityPoolValidationError::ZeroAmount);
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

        if in_idx == 0 {
            put_reserve_a(&e, reserve_a + in_amount);
        } else {
            put_reserve_b(&e, reserve_b + in_amount);
        }

        let (new_reserve_a, new_reserve_b) = (get_reserve_a(&e), get_reserve_b(&e));

        // residue_numerator and residue_denominator are the amount that the invariant considers after
        // deducting the fee, scaled up by FEE_MULTIPLIER to avoid fractions
        let residue_numerator = FEE_MULTIPLIER - (get_fee_fraction(&e) as u128);
        let residue_denominator = U256::from_u128(&e, FEE_MULTIPLIER);

        let new_invariant_factor = |reserve: u128, old_reserve: u128, out: u128| {
            if reserve - old_reserve > out {
                residue_denominator
                    .mul(&U256::from_u128(&e, old_reserve))
                    .add(
                        &(U256::from_u128(&e, residue_numerator)
                            .mul(&U256::from_u128(&e, reserve - old_reserve - out))),
                    )
            } else {
                residue_denominator
                    .mul(&U256::from_u128(&e, old_reserve))
                    .add(&residue_denominator.mul(&U256::from_u128(&e, reserve)))
                    .sub(&(residue_denominator.mul(&U256::from_u128(&e, old_reserve + out))))
            }
        };

        let (out_a, out_b) = if out_idx == 0 { (out, 0) } else { (0, out) };

        let new_inv_a = new_invariant_factor(new_reserve_a, reserve_a, out_a);
        let new_inv_b = new_invariant_factor(new_reserve_b, reserve_b, out_b);
        let old_inv_a = residue_denominator.mul(&U256::from_u128(&e, reserve_a));
        let old_inv_b = residue_denominator.mul(&U256::from_u128(&e, reserve_b));

        if new_inv_a.mul(&new_inv_b) < old_inv_a.mul(&old_inv_b) {
            panic_with_error!(&e, LiquidityPoolError::InvariantDoesNotHold);
        }

        if out_idx == 0 {
            transfer_a(&e, user.clone(), out_a);
            put_reserve_a(&e, reserve_a - out);
        } else {
            transfer_b(&e, user.clone(), out_b);
            put_reserve_b(&e, reserve_b - out);
        }

        // update plane data for every pool update
        update_plane(&e);

        PoolEvents::new(&e).trade(
            user.clone(),
            sell_token.clone(),
            tokens.get(out_idx).unwrap(),
            in_amount,
            out,
            fee,
        );

        #[cfg(feature = "mercury")]
        // Fee parameters and info
        let rewards = get_rewards_manager(&e);
        let older_pool_data = rewards.storage().get_pool_reward_data();

        let total_shares = get_total_shares(&e);
        // note: we update the rewards first to reflect how the swap affects the pool's
        // rewards. This will help us indentifying the best yield opportunities.
        rewards.manager().update_rewards_data(total_shares);

        let reward_token = rewards.storage().get_reward_token();
        let reward_token_client = SorobanTokenClient::new(&e, &reward_token);

        let pool_data = rewards.storage().get_pool_reward_data();

        let total_accomulated = pool_data.accumulated;
        let accomulated_block_delta = total_accomulated - older_pool_data.accumulated;
        let total_claimed = pool_data.claimed;
        let usdc_total_accomulated = reflector_oracle::get_token_amount_in_usdc_value(
            &e,
            &reward_token_client,
            total_accomulated,
        );

        let usdc_total_claimed = reflector_oracle::get_token_amount_in_usdc_value(
            &e,
            &reward_token_client,
            total_claimed,
        );
        let current_rewards_block = pool_data.block;
        let last_claimed_at = pool_data.last_time;

        let token_a_client = SorobanTokenClient::new(&e, &get_token_a(&e));
        let token_b_client = SorobanTokenClient::new(&e, &get_token_b(&e));
        let usdc_volume =
            reflector_oracle::get_token_amount_in_usdc_value(&e, &token_a_client, out_a)
                + reflector_oracle::get_token_amount_in_usdc_value(&e, &token_b_client, out_b);
        {
            retroshades::SwapEvent {
                pool_address: e.current_contract_address(),
                user: user.clone(),
                sell_token,
                buy_token: tokens.get(out_idx).unwrap(),
                sell_amount: in_amount,
                buy_amount: out,
                ledger: e.ledger().sequence(),
                timestamp: e.ledger().timestamp(),

                admin_fee: 0,
                lp_fee: fee,
                usdc_admin_fee: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &reward_token_client,
                    0,
                ),
                usdc_lp_fee: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &reward_token_client,
                    fee,
                ),

                total_shares,
                accomulated: total_accomulated,
                accomulated_delta: accomulated_block_delta,
                claimed: total_claimed,
                usdc_accomulated: usdc_total_accomulated,
                usdc_claimed: usdc_total_claimed,
                current_reward_block: current_rewards_block,
                last_claimed_at,
            }
            .emit(&e);

            retroshades::TvlEvent {
                pool_address: e.current_contract_address(),
                user_address: user.clone(),
                token_a: get_token_a(&e),
                token_b: get_token_b(&e),
                reserve_a: get_reserve_a(&e),
                reserve_b: get_reserve_b(&e),
                total_shares: get_total_shares(&e),
                tvl_ratio: U256::from_u128(&e, get_reserve_a(&e))
                    .div(&U256::from_u128(&e, get_reserve_b(&e))),
                fee_fraction: get_fee_fraction(&e),
                pool_type: Self::pool_type(e.clone()),
                action: Symbol::new(&e, "swap"),
                amount_a: if in_idx == 0 { in_amount } else { out },
                amount_b: if in_idx == 1 { in_amount } else { out },
                shares_changed: 0,
                ledger: e.ledger().sequence(),
                timestamp: e.ledger().timestamp(),

                usdc_volume,
                usdc_tvl_after: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_a_client,
                    new_reserve_a,
                ) + reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_b_client,
                    new_reserve_b,
                ),
                usdc_reserve_a: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_a_client,
                    new_reserve_a,
                ),
                usdc_reserve_b: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_b_client,
                    new_reserve_b,
                ),
            }
            .emit(&e);
        }

        out
    }

    // Estimates the result of a swap operation.
    //
    // # Arguments
    //
    // * `in_idx` - The index of the input token to be swapped.
    // * `out_idx` - The index of the output token to be received.
    // * `in_amount` - The amount of the input token to be swapped.
    //
    // # Returns
    //
    // The estimated amount of the output token that would be received.
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

    // Withdraws tokens from the pool.
    //
    // # Arguments
    //
    // * `user` - The address of the user withdrawing the tokens.
    // * `share_amount` - The amount of pool tokens to burn.
    // * `min_amounts` - A vector of minimum amounts of each token to be received.
    //
    // # Returns
    //
    // A vector of actual amounts of each token withdrawn.
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

        let (reserve_a, reserve_b) = (get_reserve_a(&e), get_reserve_b(&e));
        let balance_shares = get_balance_shares(&e);
        let total_shares = get_total_shares(&e);

        // Now calculate the withdraw amounts
        let out_a = reserve_a.fixed_mul_floor(&e, &balance_shares, &total_shares);
        let out_b = reserve_b.fixed_mul_floor(&e, &balance_shares, &total_shares);

        let min_a = min_amounts.get(0).unwrap();
        let min_b = min_amounts.get(1).unwrap();

        if out_a < min_a || out_b < min_b {
            panic_with_error!(&e, LiquidityPoolValidationError::OutMinNotSatisfied);
        }

        burn_shares(&e, balance_shares as i128);
        transfer_a(&e, user.clone(), out_a);
        transfer_b(&e, user.clone(), out_b);
        put_reserve_a(&e, reserve_a - out_a);
        put_reserve_b(&e, reserve_b - out_b);

        // update plane data for every pool update
        update_plane(&e);

        let withdraw_amounts = Vec::from_array(&e, [out_a, out_b]);
        PoolEvents::new(&e).withdraw_liquidity(
            Self::get_tokens(e.clone()),
            withdraw_amounts.clone(),
            share_amount,
        );

        #[cfg(feature = "mercury")]
        let token_a_client = SorobanTokenClient::new(&e, &get_token_a(&e));
        let token_b_client = SorobanTokenClient::new(&e, &get_token_b(&e));
        let usdc_volume =
            reflector_oracle::get_token_amount_in_usdc_value(&e, &token_a_client, out_a)
                + reflector_oracle::get_token_amount_in_usdc_value(&e, &token_b_client, out_b);
        {
            retroshades::TvlEvent {
                pool_address: e.current_contract_address(),
                user_address: user,
                token_a: get_token_a(&e),
                token_b: get_token_b(&e),
                reserve_a: get_reserve_a(&e),
                reserve_b: get_reserve_b(&e),
                total_shares: get_total_shares(&e),
                tvl_ratio: U256::from_u128(&e, get_reserve_a(&e))
                    .div(&U256::from_u128(&e, get_reserve_b(&e))),
                fee_fraction: get_fee_fraction(&e),
                pool_type: Self::pool_type(e.clone()),
                action: Symbol::new(&e, "withdraw"),
                amount_a: out_a,
                amount_b: out_b,
                shares_changed: share_amount,
                ledger: e.ledger().sequence(),
                timestamp: e.ledger().timestamp(),

                usdc_volume,
                usdc_tvl_after: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_a_client,
                    reserve_a - out_a,
                ) + reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_b_client,
                    reserve_b - out_b,
                ),
                usdc_reserve_a: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_a_client,
                    reserve_a - out_a,
                ),
                usdc_reserve_b: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &token_b_client,
                    reserve_b - out_b,
                ),
            }
            .emit(&e);
        }

        withdraw_amounts
    }

    // Returns the pool's reserves.
    //
    // # Returns
    //
    // A vector of the pool's reserves.
    fn get_reserves(e: Env) -> Vec<u128> {
        Vec::from_array(&e, [get_reserve_a(&e), get_reserve_b(&e)])
    }

    // Returns the pool's fee fraction.
    //
    // # Returns
    //
    // The pool's fee fraction as a u32.
    fn get_fee_fraction(e: Env) -> u32 {
        // returns fee fraction. 0.01% = 1; 1% = 100; 0.3% = 30
        get_fee_fraction(&e)
    }

    // Returns information about the pool.
    //
    // # Returns
    //
    // A map of Symbols to Vals representing the pool's information.
    fn get_info(e: Env) -> Map<Symbol, Val> {
        let fee = get_fee_fraction(&e);
        let pool_type = Self::pool_type(e.clone());
        let mut result = Map::new(&e);
        result.set(symbol_short!("pool_type"), pool_type.into_val(&e));
        result.set(symbol_short!("fee"), fee.into_val(&e));
        result
    }
}

#[contractimpl]
impl AdminInterfaceTrait for LiquidityPool {
    // Stops the pool deposits instantly.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin.
    fn kill_deposit(e: Env, admin: Address) {
        admin.require_auth();
        let access_control = AccessControl::new(&e);
        access_control.check_admin(&admin);

        set_is_killed_deposit(&e, &true);
        PoolEvents::new(&e).kill_deposit();
    }

    // Stops the pool swaps instantly.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin.
    fn kill_swap(e: Env, admin: Address) {
        admin.require_auth();
        let access_control = AccessControl::new(&e);
        access_control.check_admin(&admin);

        set_is_killed_swap(&e, &true);
        PoolEvents::new(&e).kill_swap();
    }

    // Stops the pool claims instantly.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin.
    fn kill_claim(e: Env, admin: Address) {
        admin.require_auth();
        let access_control = AccessControl::new(&e);
        access_control.check_admin(&admin);

        set_is_killed_claim(&e, &true);
        PoolEvents::new(&e).kill_claim();
    }

    // Resumes the pool deposits.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin.
    fn unkill_deposit(e: Env, admin: Address) {
        admin.require_auth();
        let access_control = AccessControl::new(&e);
        access_control.check_admin(&admin);

        set_is_killed_deposit(&e, &false);
        PoolEvents::new(&e).unkill_deposit();
    }

    // Resumes the pool swaps.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin.
    fn unkill_swap(e: Env, admin: Address) {
        admin.require_auth();
        let access_control = AccessControl::new(&e);
        access_control.check_admin(&admin);

        set_is_killed_swap(&e, &false);
        PoolEvents::new(&e).unkill_swap();
    }

    // Resumes the pool claims.
    //
    // # Arguments
    //
    // * `admin` - The address of the admin.
    fn unkill_claim(e: Env, admin: Address) {
        admin.require_auth();
        let access_control = AccessControl::new(&e);
        access_control.check_admin(&admin);

        set_is_killed_claim(&e, &false);
        PoolEvents::new(&e).unkill_claim();
    }

    // Get deposit killswitch status.
    fn get_is_killed_deposit(e: Env) -> bool {
        get_is_killed_deposit(&e)
    }

    // Get swap killswitch status.
    fn get_is_killed_swap(e: Env) -> bool {
        get_is_killed_swap(&e)
    }

    // Get claim killswitch status.
    fn get_is_killed_claim(e: Env) -> bool {
        get_is_killed_claim(&e)
    }
}

#[contractimpl]
impl UpgradeableContractTrait for LiquidityPool {
    // Returns the version of the contract.
    //
    // # Returns
    //
    // The version of the contract as a u32.
    fn version() -> u32 {
        105
    }

    // Upgrades the contract to a new version.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `new_wasm_hash` - The hash of the new contract version.
    fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        let access_control = AccessControl::new(&e);
        access_control.require_admin();
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
#[contractimpl]
impl RewardsTrait for LiquidityPool {
    // Initializes the rewards configuration.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `reward_token` - The address of the reward token.
    fn initialize_rewards_config(e: Env, reward_token: Address) {
        let rewards = get_rewards_manager(&e);
        if rewards.storage().has_reward_token() {
            panic_with_error!(&e, LiquidityPoolError::RewardsAlreadyInitialized);
        }

        rewards.storage().put_reward_token(reward_token);
    }

    // Sets the rewards configuration.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `admin` - The address of the admin user.
    // * `expired_at` - The timestamp when the rewards expire.
    // * `tps` - The value with 7 decimal places. Example: 600_0000000
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

        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        rewards
            .manager()
            .set_reward_config(total_shares, expired_at, tps);
    }

    // Returns the rewards information:
    //     tps, total accumulated amount for user, expiration, amount available to claim, debug info.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `user` - The address of the user.
    //
    // # Returns
    //
    // A map of Symbols to i128 representing the rewards information.
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

    // Returns the amount of reward tokens available for the user to claim.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `user` - The address of the user.
    //
    // # Returns
    //
    // The amount of reward tokens available for the user to claim as a u128.
    fn get_user_reward(e: Env, user: Address) -> u128 {
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        rewards
            .manager()
            .get_amount_to_claim(&user, total_shares, user_shares)
    }

    // Returns the total amount of accumulated reward for the pool.
    //
    // # Arguments
    //
    // * `e` - The environment.
    //
    // # Returns
    //
    // The total amount of accumulated reward for the pool as a u128.
    fn get_total_accumulated_reward(e: Env) -> u128 {
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        rewards.manager().get_total_accumulated_reward(total_shares)
    }

    // Returns the total amount of configured reward for the pool.
    //
    // # Arguments
    //
    // * `e` - The environment.
    //
    // # Returns
    //
    // The total amount of configured reward for the pool as a u128.
    fn get_total_configured_reward(e: Env) -> u128 {
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        rewards.manager().get_total_configured_reward(total_shares)
    }

    // Returns the total amount of claimed reward for the pool.
    //
    // # Arguments
    //
    // * `e` - The environment.
    //
    // # Returns
    //
    // The total amount of claimed reward for the pool as a u128.
    fn get_total_claimed_reward(e: Env) -> u128 {
        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        rewards.manager().get_total_claimed_reward(total_shares)
    }

    // Claims the reward as a user.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `user` - The address of the user.
    //
    // # Returns
    //
    // The amount of tokens rewarded to the user as a u128.
    fn claim(e: Env, user: Address) -> u128 {
        if get_is_killed_claim(&e) {
            panic_with_error!(e, LiquidityPoolError::PoolClaimKilled);
        }

        let rewards = get_rewards_manager(&e);
        let total_shares = get_total_shares(&e);
        let user_shares = get_user_balance_shares(&e, &user);
        let reward = rewards
            .manager()
            .claim_reward(&user, total_shares, user_shares);
        rewards.storage().bump_user_reward_data(&user);

        #[cfg(feature = "mercury")]
        let reward_token = rewards.storage().get_reward_token();
        let reward_token_client = SorobanTokenClient::new(&e, &reward_token);
        {
            retroshades::YieldEvent {
                pool_address: e.current_contract_address(),
                action: Symbol::new(&e, "claim"),
                user: user.clone(),
                reward_token: rewards.storage().get_reward_token(),
                amount: reward,
                usdc_amount: reflector_oracle::get_token_amount_in_usdc_value(
                    &e,
                    &reward_token_client,
                    reward,
                ),
                tps: rewards.storage().get_pool_reward_config().tps,
                expired_at: rewards.storage().get_pool_reward_config().expired_at,
                total_shares,
                user_shares,
                total_accumulated_reward: Self::get_total_accumulated_reward(e.clone()),
                total_configured_reward: Self::get_total_configured_reward(e.clone()),
                total_claimed_reward: Self::get_total_claimed_reward(e.clone()),
                ledger: e.ledger().sequence(),
                timestamp: e.ledger().timestamp(),
            }
            .emit(&e);
        }

        reward
    }
}

#[contractimpl]
impl Plane for LiquidityPool {
    // Sets the plane for the pool.
    //
    // # Arguments
    //
    // * `e` - The environment.
    // * `plane` - The address of the plane.
    //
    // # Panics
    //
    // If the plane has already been initialized.
    fn init_pools_plane(e: Env, plane: Address) {
        if has_plane(&e) {
            panic_with_error!(&e, LiquidityPoolError::PlaneAlreadyInitialized);
        }

        set_plane(&e, &plane);
    }

    fn set_pools_plane(e: Env, admin: Address, plane: Address) {
        let access_control = AccessControl::new(&e);
        admin.require_auth();
        access_control.check_admin(&admin);

        set_plane(&e, &plane);
    }

    // Returns the plane of the pool.
    //
    // # Arguments
    //
    // * `e` - The environment.
    //
    // # Returns
    //
    // The address of the plane.
    fn get_pools_plane(e: Env) -> Address {
        get_plane(&e)
    }

    // Updates the plane data in case the plane contract was updated.
    fn backfill_plane_data(e: Env) {
        update_plane(&e);
    }
}
