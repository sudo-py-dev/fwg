//! nftables backend for fwg: builds the ruleset as nftables JSON and applies it with `nft`.

mod build;
mod schema;

pub use build::{TABLE, build, teardown};
pub use schema::Batch;
