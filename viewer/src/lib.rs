//! The viewer's simulated network, shared by the two ways of driving it.
//!
//! The [`sim`] module holds the network itself. The binary in this crate serves
//! it over HTTP for local use; the `blackwood-wasm` crate compiles it to
//! WebAssembly so the same simulator can run inside a static page.

pub mod sim;
