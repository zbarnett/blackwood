# blackwood

A minimal reimplementation of the [ironwood](https://github.com/Arceliar/ironwood)
routing protocol's core, in dependency-free Rust.

Nodes address one another by public key rather than by location, and reach each
other across a network where no node is guaranteed a direct link to any other.
Routing works by embedding the network in a spanning tree and greedily
forwarding towards the destination in the metric that embedding induces.

**[Try the demo →](https://zbarnett.github.io/blackwood/)** — a whole network in
one page: add and remove nodes and links, move the clock forward, and watch a
packet find its way.

[![The viewer showing a five-node network](docs/viewer.png)](https://zbarnett.github.io/blackwood/)

## The core

The node holding the smallest key in a connected component becomes the root.
Every node announces the path of keys running from that root down to itself and
gossips what it hears onward. Announcements are only ever authored by the node
they describe, so the set of them is a conflict-free replicated map whose join
is simply the greater of two announcements: no coordination, no ordering
requirements, and no divergence between nodes.

The distance between two nodes is the walk up to their lowest common ancestor
and back down. A node forwards a packet to whichever peer stands strictly closer
to the destination. Three properties follow, each from a local rule:

- **Loop-free forwarding.** Distance strictly decreases at every hop and is
  bounded below by zero, so a packet cannot revisit a node.
- **Loop-free tree.** An announcement carries its whole path, and a node refuses
  to sit below a path that already runs through it. Staleness can cost a node
  its route, never its acyclicity.
- **Delivery on a settled tree.** A node's tree neighbour towards the
  destination is always exactly one hop closer, so there is always a next hop.

Announcements are soft state. A node reissues its own on a schedule and forgets
any it has not heard reissued, so a view repairs itself rather than only
accumulating: a node that vanishes is eventually forgotten instead of lingering
as a route to nowhere, and one that comes back with its sequence numbers reset
is not mistaken for a stale copy of itself.

Nothing in the core performs I/O, reads a clock, allocates a thread, or calls
into the operating system. It has no dependencies beyond `std`, no `unsafe`, and
no panics: a node is a state machine whose every effect is the messages it hands
back and whose every input — a message, a link coming or going, the passage of
time — is an argument to a method. Even expiry reads no clock; `Node::tick` is
handed the current instant by its caller, in whatever unit that caller counts
in. That is what makes a network of them deterministically simulatable, and what
should make the argument above tractable to check in a proof assistant.

Cryptography, bloom-filter lookups and link costs are deliberately absent;
[`src/lib.rs`](src/lib.rs) records what each one would add.

## Layout

| Path | What it is |
| --- | --- |
| [`src/`](src/) | The routing core. No dependencies, no I/O, no `unsafe` |
| [`tests/simulation.rs`](tests/simulation.rs) | Brings a network up and carries a packet across it |
| [`viewer/`](viewer/) | The visualiser: a simulator, a small server, and a Svelte page |
| [`viewer/wasm/`](viewer/wasm/) | The same simulator compiled to WebAssembly, for the hosted demo |

## Running it

```sh
cargo test --workspace          # the core and its simulation

cd viewer/ui && npm install && npm run build
cargo run -p blackwood-viewer   # then open http://127.0.0.1:8080
```

The demo above is the same page with the simulator compiled to WebAssembly
instead of served, so it needs nothing running behind it. To build that locally:

```sh
rustup target add wasm32-unknown-unknown
cd viewer/ui && npm run build:static
```

See [`viewer/README.md`](viewer/README.md) for the controls.
