use soroban_sdk::{Address, Env};

use crate::LibKey;

/// Debits `token`'s balance: callers must authorize it.
pub fn on_hook(e: &Env, token: &Address, amount: i128) {
    if amount < 0 {
        panic!("negative");
    }
    let key = LibKey::Balance(token.clone());
    let b: i128 = e.storage().persistent().get(&key).unwrap_or(0);
    e.storage().persistent().set(&key, &(b - amount));
}
