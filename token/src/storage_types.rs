use soroban_sdk::{contracttype, Address};

pub(crate) const INSTANCE_BUMP_AMOUNT: u32 = 6_312_000; // one year
pub(crate) const BALANCE_BUMP_AMOUNT: u32 = 6_312_000; // one year

#[derive(Clone)]
#[contracttype]
pub struct AllowanceDataKey {
    pub from: Address,
    pub spender: Address,
}

#[contracttype]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Allowance(AllowanceDataKey),
    Balance(Address),
    Nonce(Address),
    State(Address),
    Admin,
}
