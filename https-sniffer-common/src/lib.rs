// #![no_std]
#![cfg_attr(not(feature = "user"), no_std)]
pub mod data;

pub use data::{Data, Kind, MAX_BUF_SIZE};
