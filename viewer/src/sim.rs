//! A simulated network of [`Node`]s, driven by the viewer.
//!
//! This is the same shape as the simulator in the core's integration tests: a
//! queue of messages in flight, a map of nodes to hand them to, and a clock
//! that moves only when somebody asks it to. Nothing here reaches the operating
//! system; the only socket in this crate belongs to the HTTP server that shows
//! the result.

use std::collections::{BTreeMap, VecDeque};

use blackwood::{Cost, Envelope, KEY_LEN, Message, Node, PublicKey, Timing};

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
    /// What the links it crossed cost, added up.
    pub cost: u64,
}

impl Delivery {
    /// The JSON fields a caller adds to its response, without the braces.
    pub fn json_fields(&self) -> String {
        format!(
            r#""route":{},"delivered":{},"cost":{}"#,
            json_ids(self.route.iter().copied()),
            self.delivered,
            self.cost
        )
    }
}

/// Everything the viewer knows.
pub struct Sim {
    nodes: BTreeMap<Id, Node>,
    /// Links and what each costs to cross, each held once with the smaller
    /// label first. Both ends of a link agree on its cost here; a node itself
    /// makes no such assumption, since each end measures for itself.
    links: BTreeMap<(Id, Id), Cost>,
    queue: VecDeque<InFlight>,
    /// The clock every node shares. Only [`Sim::advance`] moves it, so nothing
    /// expires or is reissued except when the viewer asks for it.
    now: u64,
    /// Labels are never reused. Reusing one is only safe once the network has
    /// forgotten the node that held it, and the viewer cannot promise that at
    /// the moment somebody presses the button.
    next_id: Id,
    log: Vec<String>,
    /// Bumped on every change, so the UI can tell whether it needs to redraw.
    version: u64,
}

impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

impl Sim {
    /// Builds the network the core's integration test uses, so the viewer opens
    /// on something worth looking at.
    pub fn new() -> Self {
        let mut sim = Self {
            nodes: BTreeMap::new(),
            links: BTreeMap::new(),
            queue: VecDeque::new(),
            now: 0,
            next_id: 1,
            log: Vec::new(),
            version: 0,
        };
        // These cannot fail: the labels are fresh, the links are between
        // distinct nodes that were just created, and no cost is zero.
        for _ in 0..5 {
            let _ = sim.add_node();
        }
        // The 2-4 link is the short way round and the dear one, so the tree
        // that forms is the cheapest one rather than the shallowest.
        for (a, b, cost) in [(1, 2, 1), (2, 3, 1), (3, 4, 1), (2, 4, 5), (4, 5, 1)] {
            let _ = sim.add_link(a, b, cost);
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
        self.nodes.insert(id, Node::new(self.now, key_of(id)));
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

    /// Brings up a link between two nodes, costing `cost` to cross.
    pub fn add_link(&mut self, a: Id, b: Id, cost: u64) -> Result<(), String> {
        if a == b {
            return Err("a node cannot link to itself".into());
        }
        self.require(a)?;
        self.require(b)?;
        let cost = price(cost)?;
        if self.links.contains_key(&ordered(a, b)) {
            return Err(format!("{a} and {b} are already linked"));
        }
        self.connect(a, b, cost);
        self.note(&format!("linked {a} and {b} at cost {cost}"));
        Ok(())
    }

    /// Re-prices a link that is already up.
    ///
    /// This is what a real caller does when it measures a peering again, and
    /// it is the whole of what link cost changes: no message crosses the
    /// network, but every node that was routing over this link reconsiders.
    pub fn set_link_cost(&mut self, a: Id, b: Id, cost: u64) -> Result<(), String> {
        let cost = price(cost)?;
        let Some(&current) = self.links.get(&ordered(a, b)) else {
            return Err(format!("{a} and {b} are not linked"));
        };
        if current == cost {
            return Err(format!("{a} and {b} already cost {cost}"));
        }
        self.connect(a, b, cost);
        self.note(&format!("{a} and {b} now cost {cost}, was {current}"));
        Ok(())
    }

    /// Tears down a link.
    pub fn remove_link(&mut self, a: Id, b: Id) -> Result<(), String> {
        if !self.links.contains_key(&ordered(a, b)) {
            return Err(format!("{a} and {b} are not linked"));
        }
        self.unlink(a, b);
        self.run();
        self.note(&format!("unlinked {a} and {b}"));
        Ok(())
    }

    /// Moves the clock forward, letting nodes reissue and expire announcements.
    ///
    /// Time is stepped in refresh-sized increments rather than jumped in one
    /// go, because a jump would look to every node as though the whole network
    /// had fallen silent for the entire interval.
    pub fn advance(&mut self, by: u64) {
        let step = Timing::DEFAULT.refresh.max(1);
        let before = self.total_known();
        let target = self.now.saturating_add(by);
        while self.now < target {
            self.now = self.now.saturating_add(step).min(target);
            let now = self.now;
            for id in self.nodes.keys().copied().collect::<Vec<_>>() {
                if let Ok(node) = self.node_mut(id) {
                    let outbound = node.tick(now);
                    self.enqueue(id, outbound);
                }
            }
            self.run();
        }
        let forgotten = before.saturating_sub(self.total_known());
        let seconds = self.now as f64 / 1000.0;
        match forgotten {
            0 => self.note(&format!("clock at {seconds:.1}s")),
            1 => self.note(&format!("clock at {seconds:.1}s, 1 announcement expired")),
            n => self.note(&format!(
                "clock at {seconds:.1}s, {n} announcements expired"
            )),
        }
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
        let now = self.now;
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
                .handle(now, key_of(carrier), envelope.message);
            carrier = next;
            hop = produced.into_iter().next();
        }

        let last = *route.last().unwrap_or(&from);
        let delivered = !self.node_mut(last)?.take_delivered().is_empty();
        let cost = self.cost_of(&route);
        self.note(&format!(
            "packet {from} to {to}: {} ({delivered_or_not}, cost {cost})",
            route
                .iter()
                .map(Id::to_string)
                .collect::<Vec<_>>()
                .join(" \u{2192} "),
            delivered_or_not = if delivered { "delivered" } else { "dropped" }
        ));
        Ok(Delivery {
            route,
            delivered,
            cost,
        })
    }

    /// The current state of the whole network, as JSON.
    pub fn snapshot(&self) -> String {
        let nodes = self
            .nodes
            .iter()
            .map(|(id, node)| {
                format!(
                    r#"{{"id":{id},"root":{},"parent":{},"path":{},"cost":{},"peers":{},"knows":{}}}"#,
                    id_of(node.root()),
                    match node.parent() {
                        Some(parent) => id_of(parent).to_string(),
                        None => "null".into(),
                    },
                    json_ids(node.path().iter().map(|hop| id_of(hop.key))),
                    node.cost_to_root(),
                    json_ids(node.peers().map(|(peer, _)| id_of(peer))),
                    node.known().count(),
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let links = self
            .links
            .iter()
            .map(|((a, b), cost)| {
                let tree = self.parent_of(*a) == Some(*b) || self.parent_of(*b) == Some(*a);
                format!(r#"{{"a":{a},"b":{b},"cost":{cost},"tree":{tree}}}"#)
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
            r#"{{"version":{},"now":{},"nodes":[{nodes}],"links":[{links}],"log":[{log}]}}"#,
            self.version, self.now
        )
    }

    /// How many announcements the network holds in total, which is what
    /// expiry shrinks.
    fn total_known(&self) -> usize {
        self.nodes.values().map(|node| node.known().count()).sum()
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
            Some(node) => node.peers().map(|(peer, _)| id_of(peer)).collect(),
            None => Vec::new(),
        }
    }

    /// What crossing every link along `route` costs.
    fn cost_of(&self, route: &[Id]) -> u64 {
        route
            .windows(2)
            .filter_map(|pair| self.links.get(&ordered(pair[0], pair[1])))
            .fold(0, |total, cost| total.saturating_add(cost.get()))
    }

    /// Prices a link on both sides and lets the network settle.
    ///
    /// Each node is told separately what its own end costs, because that is
    /// all a node ever knows: nothing in the core assumes the two ends of a
    /// link agree, and it is only this simulator that makes them.
    fn connect(&mut self, a: Id, b: Id, cost: Cost) {
        self.links.insert(ordered(a, b), cost);
        let now = self.now;
        for (near, far) in [(a, b), (b, a)] {
            if let Ok(node) = self.node_mut(near) {
                let outbound = node.add_peer(now, key_of(far), cost);
                self.enqueue(near, outbound);
            }
        }
        self.run();
    }

    /// Drops a link on both sides without logging or running the queue.
    fn unlink(&mut self, a: Id, b: Id) {
        self.links.remove(&ordered(a, b));
        let now = self.now;
        for (near, far) in [(a, b), (b, a)] {
            if let Ok(node) = self.node_mut(near) {
                let outbound = node.remove_peer(now, key_of(far));
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
            let now = self.now;
            let Ok(node) = self.node_mut(id_of(in_flight.to)) else {
                continue;
            };
            let outbound = node.handle(now, in_flight.from, in_flight.message);
            self.enqueue(id_of(in_flight.to), outbound);
        }
    }

    fn note(&mut self, line: &str) {
        self.version += 1;
        self.log.push(line.to_string());
    }
}

/// Reads a cost off the wire, where a link that costs nothing is not a link.
fn price(cost: u64) -> Result<Cost, String> {
    Cost::new(cost).ok_or_else(|| "a link costs at least 1".to_string())
}

fn ordered(a: Id, b: Id) -> (Id, Id) {
    if a <= b { (a, b) } else { (b, a) }
}

fn json_ids(ids: impl Iterator<Item = Id>) -> String {
    let inner = ids.map(|id| id.to_string()).collect::<Vec<_>>().join(",");
    format!("[{inner}]")
}

/// Quotes a string for JSON. Log lines are our own text, but escaping is cheap.
pub fn json_string(value: &str) -> String {
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
