//! nftables backend for fwg: builds the ruleset as nftables JSON and applies it with `nft`.

mod backend;
mod build;
mod schema;

pub use backend::{Backend, NFT_PATHS, Nft, NftError, TableRef};
pub use build::{TABLE, build, teardown};
pub use schema::Batch;
