//! A simulated network of [`Node`]s, driven by the viewer.
//!
//! This is the same shape as the simulator in the core's integration tests: a
//! queue of messages in flight and a map of nodes to hand them to. Nothing here
//! reaches the operating system; the only socket in this crate belongs to the
//! HTTP server that shows the result.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use blackwood::{Envelope, KEY_LEN, Message, Node, PublicKey};

/// A short label for a node, used as its identity throughout the UI.
pub type Id = u8;

/// A node's key is its label repeated, so the two convert freely.
fn key_of(id: Id) -> PublicKey {
    PublicKey::new([id; KEY_LEN])
}

fn id_of(key: PublicKey) -> Id {
    key.as_bytes()[0]
}

/// A message on its way from one node to a linked peer.
struct InFlight {
    to: PublicKey,
    from: PublicKey,
    message: Message,
}

/// The outcome of pushing one packet through the network.
pub struct Delivery {
    /// The nodes the packet passed through, in order, starting at the sender.
    pub route: Vec<Id>,
    /// Whether it reached the node it was addressed to.
    pub delivered: bool,
}

/// Everything the viewer knows.
pub struct Sim {
    nodes: BTreeMap<Id, Node>,
    /// Links, each held once with the smaller label first.
    links: BTreeSet<(Id, Id)>,
    queue: VecDeque<InFlight>,
    /// Labels are never reused. A node added under an old label would restart
    /// its sequence numbers at zero, and its peers, which have no clock to
    /// expire the old announcement with, would dismiss it as stale.
    next_id: Id,
    log: Vec<String>,
    /// Bumped on every change, so the UI can tell whether it needs to redraw.
    version: u64,
}

impl Sim {
    /// Builds the network the core's integration test uses, so the viewer opens
    /// on something worth looking at.
    pub fn new() -> Self {
        let mut sim = Self {
            nodes: BTreeMap::new(),
            links: BTreeSet::new(),
            queue: VecDeque::new(),
            next_id: 1,
            log: Vec::new(),
            version: 0,
        };
        // These cannot fail: the labels are fresh and the links are between
        // distinct nodes that were just created.
        for _ in 0..5 {
            let _ = sim.add_node();
        }
        for (a, b) in [(1, 2), (2, 3), (3, 4), (2, 4), (4, 5)] {
            let _ = sim.add_link(a, b);
        }
        sim.log.clear();
        sim.note("network ready");
        sim
    }

    /// Adds an isolated node and returns its label.
    pub fn add_node(&mut self) -> Result<Id, String> {
        let id = self.next_id;
        if id == Id::MAX {
            return Err("out of labels".into());
        }
        self.next_id += 1;
        self.nodes.insert(id, Node::new(key_of(id)));
        self.note(&format!("added node {id}"));
        Ok(id)
    }

    /// Removes a node and every link it held.
    pub fn remove_node(&mut self, id: Id) -> Result<(), String> {
        if !self.nodes.contains_key(&id) {
            return Err(format!("no node {id}"));
        }
        for peer in self.peers_of(id) {
            self.unlink(id, peer);
        }
        self.nodes.remove(&id);
        self.run();
        self.note(&format!("removed node {id}"));
        Ok(())
    }

    /// Brings up a link between two nodes.
    pub fn add_link(&mut self, a: Id, b: Id) -> Result<(), String> {
        if a == b {
            return Err("a node cannot link to itself".into());
        }
        self.require(a)?;
        self.require(b)?;
        if !self.links.insert(ordered(a, b)) {
            return Err(format!("{a} and {b} are already linked"));
        }
        for (near, far) in [(a, b), (b, a)] {
            let outbound = self.node_mut(near)?.add_peer(key_of(far));
            self.enqueue(near, outbound);
        }
        self.run();
        self.note(&format!("linked {a} and {b}"));
        Ok(())
    }

    /// Tears down a link.
    pub fn remove_link(&mut self, a: Id, b: Id) -> Result<(), String> {
        if !self.links.contains(&ordered(a, b)) {
            return Err(format!("{a} and {b} are not linked"));
        }
        self.unlink(a, b);
        self.run();
        self.note(&format!("unlinked {a} and {b}"));
        Ok(())
    }

    /// Sends one packet and traces the path it took.
    pub fn send(&mut self, from: Id, to: Id) -> Result<Delivery, String> {
        self.require(from)?;
        self.require(to)?;

        let outbound = self
            .node_mut(from)?
            .send(key_of(to), b"hello".to_vec())
            .map_err(|error| format!("{from} to {to}: {error}"))?;

        // Forwarding a packet yields at most one packet, so following it is a
        // walk rather than a search. The sender of each hop is whichever node
        // is holding the packet, which is what the receiver checks it against.
        let mut route = vec![from];
        let mut carrier = from;
        let mut hop = outbound.into_iter().next();
        while let Some(envelope) = hop {
            let Message::Packet(_) = envelope.message else {
                break;
            };
            let next = id_of(envelope.to);
            route.push(next);
            let produced = self
                .node_mut(next)?
                .handle(key_of(carrier), envelope.message);
            carrier = next;
            hop = produced.into_iter().next();
        }

        let last = *route.last().unwrap_or(&from);
        let delivered = !self.node_mut(last)?.take_delivered().is_empty();
        self.note(&format!(
            "packet {from} to {to}: {} ({})",
            route
                .iter()
                .map(Id::to_string)
                .collect::<Vec<_>>()
                .join(" \u{2192} "),
            if delivered { "delivered" } else { "dropped" }
        ));
        Ok(Delivery { route, delivered })
    }

    /// The current state of the whole network, as JSON.
    pub fn snapshot(&self) -> String {
        let nodes = self
            .nodes
            .iter()
            .map(|(id, node)| {
                format!(
                    r#"{{"id":{id},"root":{},"parent":{},"path":{},"peers":{}}}"#,
                    id_of(node.root()),
                    match node.parent() {
                        Some(parent) => id_of(parent).to_string(),
                        None => "null".into(),
                    },
                    json_ids(node.path().iter().map(|key| id_of(*key))),
                    json_ids(node.peers().map(id_of)),
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let links = self
            .links
            .iter()
            .map(|(a, b)| {
                let tree = self.parent_of(*a) == Some(*b) || self.parent_of(*b) == Some(*a);
                format!(r#"{{"a":{a},"b":{b},"tree":{tree}}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");

        let log = self
            .log
            .iter()
            .rev()
            .take(40)
            .map(|line| json_string(line))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"{{"version":{},"nodes":[{nodes}],"links":[{links}],"log":[{log}]}}"#,
            self.version
        )
    }

    fn require(&self, id: Id) -> Result<(), String> {
        if self.nodes.contains_key(&id) {
            Ok(())
        } else {
            Err(format!("no node {id}"))
        }
    }

    fn node_mut(&mut self, id: Id) -> Result<&mut Node, String> {
        self.nodes.get_mut(&id).ok_or(format!("no node {id}"))
    }

    fn parent_of(&self, id: Id) -> Option<Id> {
        self.nodes.get(&id)?.parent().map(id_of)
    }

    fn peers_of(&self, id: Id) -> Vec<Id> {
        match self.nodes.get(&id) {
            Some(node) => node.peers().map(id_of).collect(),
            None => Vec::new(),
        }
    }

    /// Drops a link on both sides without logging or running the queue.
    fn unlink(&mut self, a: Id, b: Id) {
        self.links.remove(&ordered(a, b));
        for (near, far) in [(a, b), (b, a)] {
            if let Ok(node) = self.node_mut(near) {
                let outbound = node.remove_peer(key_of(far));
                self.enqueue(near, outbound);
            }
        }
    }

    fn enqueue(&mut self, from: Id, outbound: Vec<Envelope>) {
        for envelope in outbound {
            self.queue.push_back(InFlight {
                to: envelope.to,
                from: key_of(from),
                message: envelope.message,
            });
        }
    }

    /// Delivers gossip until the network falls quiet.
    fn run(&mut self) {
        const MAX_STEPS: usize = 100_000;
        for step in 0.. {
            if step >= MAX_STEPS {
                self.note("gossip did not settle; stopping");
                self.queue.clear();
                return;
            }
            let Some(in_flight) = self.queue.pop_front() else {
                return;
            };
            let Ok(node) = self.node_mut(id_of(in_flight.to)) else {
                continue;
            };
            let outbound = node.handle(in_flight.from, in_flight.message);
            self.enqueue(id_of(in_flight.to), outbound);
        }
    }

    fn note(&mut self, line: &str) {
        self.version += 1;
        self.log.push(line.to_string());
    }
}

fn ordered(a: Id, b: Id) -> (Id, Id) {
    if a <= b { (a, b) } else { (b, a) }
}

fn json_ids(ids: impl Iterator<Item = Id>) -> String {
    let inner = ids.map(|id| id.to_string()).collect::<Vec<_>>().join(",");
    format!("[{inner}]")
}

/// Quotes a string for JSON. Log lines are our own text, but escaping is cheap.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
