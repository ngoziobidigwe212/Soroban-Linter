use soroban_sdk::{Address, Env};

use crate::LibKey;

/// Same file and function name as `a/storage.rs`, but read-only.
pub fn on_hook(e: &Env, token: &Address, _amount: i128) {
    let _: Option<i128> = e.storage().persistent().get(&LibKey::Balance(token.clone()));
}
