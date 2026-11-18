//! nftables backend for fwg: builds the ruleset as nftables JSON and applies it with `nft`.

mod backend;
mod ban;
mod build;
mod schema;

pub use backend::{ActiveBan, Backend, NFT_PATHS, Nft, NftError, TableRef};
pub use ban::{
    BAN_TABLE, BanTime, BanTimeError, MAX_BAN, MAX_BANS_PER_FAMILY, MIN_BAN, ban, ensure_ban_table,
    unban,
};
pub use build::{TABLE, build, teardown};
pub use schema::Batch;
