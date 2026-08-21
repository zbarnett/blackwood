//! The viewer's simulator, compiled to WebAssembly.
//!
//! This is what lets the hosted demo run with no server behind it: the same
//! Rust that the local viewer serves over HTTP is instead called directly by
//! the page. Every export mirrors one HTTP command and leaves the same JSON
//! behind, so the UI cannot tell the two apart.
//!
//! The boundary is written by hand rather than generated, which keeps the
//! dependency count at zero. Its whole contract is: call a command, then read
//! the bytes at [`out_ptr`] for [`out_len`] and parse them as JSON. Nothing is
//! passed in but numbers, so there is no need to hand strings the other way.

use std::cell::RefCell;

use blackwood_viewer::sim::{Delivery, Id, Sim, json_string};

thread_local! {
    static SIM: RefCell<Sim> = RefCell::new(Sim::new());
    static OUT: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Where the last command left its JSON.
///
/// Valid until the next command runs, which is long enough for the caller to
/// copy it out.
#[unsafe(no_mangle)]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|out| out.borrow().as_ptr())
}

/// How many bytes of JSON the last command left.
#[unsafe(no_mangle)]
pub extern "C" fn out_len() -> usize {
    OUT.with(|out| out.borrow().len())
}

/// Reports the network without changing it.
#[unsafe(no_mangle)]
pub extern "C" fn state() {
    respond(Ok(None));
}

/// Adds an isolated node.
#[unsafe(no_mangle)]
pub extern "C" fn node_add() {
    respond(with_sim(|sim| sim.add_node().map(|_| None)));
}

/// Removes a node and its links.
#[unsafe(no_mangle)]
pub extern "C" fn node_remove(id: u32) {
    respond(with_sim(|sim| sim.remove_node(id as Id).map(|()| None)));
}

/// Brings up a link.
#[unsafe(no_mangle)]
pub extern "C" fn link_add(a: u32, b: u32) {
    respond(with_sim(|sim| {
        sim.add_link(a as Id, b as Id).map(|()| None)
    }));
}

/// Tears down a link.
#[unsafe(no_mangle)]
pub extern "C" fn link_remove(a: u32, b: u32) {
    respond(with_sim(|sim| {
        sim.remove_link(a as Id, b as Id).map(|()| None)
    }));
}

/// Sends one packet, reporting the route it took.
#[unsafe(no_mangle)]
pub extern "C" fn send(from: u32, to: u32) {
    respond(with_sim(|sim| {
        sim.send(from as Id, to as Id)
            .map(|delivery: Delivery| Some(delivery.json_fields()))
    }));
}

/// Rebuilds the starting network.
#[unsafe(no_mangle)]
pub extern "C" fn reset() {
    respond(with_sim(|sim| {
        *sim = Sim::new();
        Ok(None)
    }));
}

fn with_sim<T>(command: impl FnOnce(&mut Sim) -> Result<T, String>) -> Result<T, String> {
    SIM.with(|sim| command(&mut sim.borrow_mut()))
}

/// Writes the outcome of a command, in the shape the HTTP server uses.
fn respond(outcome: Result<Option<String>, String>) {
    let state = SIM.with(|sim| sim.borrow().snapshot());
    let body = match outcome {
        Ok(Some(extra)) => format!(r#"{{"ok":true,{extra},"state":{state}}}"#),
        Ok(None) => format!(r#"{{"ok":true,"state":{state}}}"#),
        Err(message) => format!(
            r#"{{"ok":false,"error":{},"state":{state}}}"#,
            json_string(&message)
        ),
    };
    OUT.with(|out| *out.borrow_mut() = body);
}
