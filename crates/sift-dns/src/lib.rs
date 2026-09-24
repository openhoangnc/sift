//! The DNS server: wire handling, caching, upstream resolution.

pub mod addr;
pub mod blocked;
pub mod cache;
pub mod client;
pub mod clients;
pub mod conn;
pub mod ddr;
pub mod dns64;
pub mod doq;
pub mod edns;
pub mod msg;
mod packed;
pub mod pending;
pub mod pool;
pub mod probe;
pub mod ratelimit;
pub mod refresh;
pub mod resolver;
pub mod rewrite;
pub mod server;
pub mod tls;
