//! A simulated network of [`Node`]s, driven by the viewer.
//!
//! This is the same shape as the simulator in the core's integration tests: a
//! queue of messages in flight, a map of nodes to hand them to, and a clock
//! that moves only when somebody asks it to. Nothing here reaches the operating
//! system; the only socket in this crate belongs to the HTTP server that shows
//! the result.

use std::collections::{BTreeMap, VecDeque};

use blackwood::{Announcement, Cost, Envelope, Message, Node, PublicKey, Timing};
use blackwood_ed25519::Ed25519;

/// A short label for a node, shown throughout the UI in place of its key.
///
/// It is only a name. A node's address is an ed25519 public key it cannot
/// choose, and nothing in the protocol has ever heard of these.
pub type Id = u8;

/// The node type this simulation runs: a routing node signing with ed25519.
type Signed = Node<Ed25519>;

/// The secret a label's node is built from.
///
/// Written down rather than drawn from anywhere, so that the same network comes
/// up the same way every time. A real node wants 32 bytes it did not choose.
fn seed_for(id: Id) -> [u8; 32] {
    [id; 32]
}

/// A key abbreviated for display, since the whole of one is 64 hex digits and
/// the point of showing it at all is that the ordering can be seen.
fn short_key(key: PublicKey) -> String {
    key.as_bytes()[..3]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
    /// The nodes a search passed through first, if the sender had to ask where
    /// the destination was. Empty when it already knew.
    pub searched: Vec<Id>,
}

impl Delivery {
    /// The JSON fields a caller adds to its response, without the braces.
    pub fn json_fields(&self) -> String {
        format!(
            r#""route":{},"delivered":{},"cost":{},"searched":{}"#,
            json_ids(self.route.iter().copied()),
            self.delivered,
            self.cost,
            json_ids(self.searched.iter().copied()),
        )
    }
}

/// What became of an attempt to pass off an altered position as genuine.
pub struct Forgery {
    /// Whether the node's real position still checks out, which it always
    /// does — reported so that a refusal below cannot be mistaken for a check
    /// that simply says no to everything.
    pub genuine: bool,
    /// Why the altered one was refused, or `None` if it got through, which
    /// would mean the signatures were doing nothing.
    pub refused: Option<String>,
}

impl Forgery {
    /// The JSON fields a caller adds to its response, without the braces.
    pub fn json_fields(&self) -> String {
        format!(
            r#""genuine":{},"refused":{}"#,
            self.genuine,
            match &self.refused {
                Some(why) => json_string(why),
                None => "null".into(),
            }
        )
    }
}

/// The outcome of one search.
pub struct Search {
    /// The nodes it passed through, in the order they saw it.
    pub visited: Vec<Id>,
    /// Whether the asker came away holding the target's position.
    pub found: bool,
}

impl Search {
    /// The JSON fields a caller adds to its response, without the braces.
    pub fn json_fields(&self) -> String {
        format!(
            r#""searched":{},"found":{}"#,
            json_ids(self.visited.iter().copied()),
            self.found
        )
    }
}

/// Everything the viewer knows.
pub struct Sim {
    nodes: BTreeMap<Id, Signed>,
    /// What each label's key is, and which label a key belongs to. Keys are
    /// derived from a secret and so arrive in no particular order; these two
    /// maps are the whole of the UI's right to call one of them "node 3".
    keys: BTreeMap<Id, PublicKey>,
    ids: BTreeMap<PublicKey, Id>,
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
    /// The nodes the search now running has passed through. Only [`Sim::run`]
    /// appends to it, and only [`Sim::look_up`] reads it back.
    searched: Vec<Id>,
    /// Bumped on every change, so the UI can tell whether it needs to redraw.
    version: u64,
}

impl Default for Sim {
    fn default() -> Self {
        Self::new()
    }
}

impl Sim {
    /// Builds a network worth opening on: a cycle, one link priced so that the
    /// cheapest tree is not the shallowest, and a branch for a search to
    /// decline to go down.
    pub fn new() -> Self {
        let mut sim = Self {
            nodes: BTreeMap::new(),
            keys: BTreeMap::new(),
            ids: BTreeMap::new(),
            links: BTreeMap::new(),
            queue: VecDeque::new(),
            now: 0,
            next_id: 1,
            log: Vec::new(),
            searched: Vec::new(),
            version: 0,
        };
        // Labels are handed out in key order for the network the viewer opens
        // on, so that node 1 holds the smallest key, is therefore the root, and
        // the demo reads the same way every time. Nothing in the protocol knows
        // about this: a node added later takes the next label and whatever key
        // its seed gives it, which may well sort below everything already here.
        let mut signers: Vec<Ed25519> =
            (1..=6).map(|seed| Ed25519::from_seed([seed; 32])).collect();
        signers.sort_by_key(Ed25519::key);
        for signer in signers {
            let id = sim.next_id;
            sim.next_id += 1;
            sim.adopt(id, signer);
        }

        // These cannot fail: the links are between distinct nodes that were
        // just created, and no cost is zero.
        // The 2-4 link is the short way round and the dear one, so the tree
        // that forms is the cheapest one rather than the shallowest. 6 hangs
        // off 2 on a branch of its own, which is what gives a search somewhere
        // it can decline to go.
        for (a, b, cost) in [
            (1, 2, 1),
            (2, 3, 1),
            (3, 4, 1),
            (2, 4, 5),
            (4, 5, 1),
            (2, 6, 1),
        ] {
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
        self.adopt(id, Ed25519::from_seed(seed_for(id)));
        self.note(&format!("added node {id}"));
        Ok(id)
    }

    /// Puts a node into the network under a label, and records which key that
    /// label stands for.
    fn adopt(&mut self, id: Id, signer: Ed25519) {
        let key = signer.key();
        self.keys.insert(id, key);
        self.ids.insert(key, id);
        self.nodes.insert(id, Node::new(self.now, signer));
    }

    /// Removes a node and every link it held.
    pub fn remove_node(&mut self, id: Id) -> Result<(), String> {
        let key = self.require(id)?;
        for peer in self.peers_of(id) {
            self.unlink(id, peer);
        }
        self.nodes.remove(&id);
        self.keys.remove(&id);
        self.ids.remove(&key);
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

    /// Asks the network where a node sits, and traces where the search went.
    ///
    /// It is handed on only to the tree neighbours whose summary admits the
    /// target might lie beyond them, so the nodes it visits are the branches
    /// that could have held it — and never the whole network, unless every
    /// summary has filled up enough to stop ruling anything out.
    pub fn look_up(&mut self, from: Id, to: Id) -> Result<Search, String> {
        self.require(from)?;

        let target = self.require(to)?;
        let outbound = self.node(from)?.lookup(target);
        self.searched.clear();
        self.enqueue(from, outbound);
        self.run();

        let visited = std::mem::take(&mut self.searched);
        let found = self.knows(from, to);
        self.note(&format!(
            "lookup {from} for {to}: {} ({})",
            if visited.is_empty() {
                "nobody could hold it".to_string()
            } else {
                format!("reached {}", join_ids(&visited))
            },
            if found { "found" } else { "no answer" }
        ));
        Ok(Search { visited, found })
    }

    /// Alters a node's real position and offers the result to the same check
    /// every node runs on everything it is told.
    ///
    /// The lie is a forged reissue: the sequence number moved on by one, and
    /// nothing else touched. That is the one alteration that would matter most
    /// — it would let anybody keep a node that had vanished looking alive,
    /// which is exactly what expiry exists to prevent.
    ///
    /// Nothing is injected into the running network. `Announcement::new` is the
    /// door every announcement arriving from a link comes through, and this
    /// shows what happens at it.
    pub fn forge(&mut self, id: Id) -> Result<Forgery, String> {
        self.require(id)?;
        let mut path = self.node(id)?.path().to_vec();
        let genuine = Announcement::new::<Ed25519>(path.clone()).is_ok();

        // The path is never empty, so there is always a last hop.
        let last = path.len() - 1;
        path[last].seq = path[last].seq.saturating_add(1);
        let refused = match Announcement::new::<Ed25519>(path) {
            Ok(_) => None,
            Err(why) => Some(why.to_string()),
        };

        self.note(&match (&refused, genuine) {
            (Some(why), true) => format!("forged a reissue of {id}: refused, {why}"),
            (Some(why), false) => format!(
                "forged a reissue of {id}: refused, {why} (and so was the real one, which is a bug)"
            ),
            (None, _) => format!("forged a reissue of {id}: accepted, which is a bug"),
        });
        Ok(Forgery { genuine, refused })
    }

    /// Sends one packet and traces the path it took, looking the destination
    /// up first if this node does not already hold its position.
    pub fn send(&mut self, from: Id, to: Id) -> Result<Delivery, String> {
        self.require(from)?;
        let target = self.require(to)?;

        // A node holds the position of its peers and of whoever it has looked
        // up lately. Anything else has to be found before it can be addressed.
        let searched = if self.knows(from, to) {
            Vec::new()
        } else {
            self.look_up(from, to)?.visited
        };

        let outbound = self
            .node_mut(from)?
            .send(target, b"hello".to_vec())
            .map_err(|error| format!("{from} to {to}: {error}"))?;

        // Forwarding a packet yields at most one packet, so following it is a
        // walk rather than a search. The sender of each hop is whichever node
        // is holding the packet, which is what the receiver checks it against.
        let now = self.now;
        let mut route = vec![from];
        let mut carrier = from;
        let mut hop = outbound.into_iter().next();
        while let Some(envelope) = hop {
            let Message::Traffic(_) = envelope.message else {
                break;
            };
            let next = self.id_of(envelope.to);
            route.push(next);
            let from_key = self.require(carrier)?;
            let produced = self.node_mut(next)?.handle(now, from_key, envelope.message);
            carrier = next;
            hop = produced.into_iter().next();
        }

        let last = *route.last().unwrap_or(&from);
        let delivered = !self.node_mut(last)?.take_delivered().is_empty();
        let cost = self.cost_of(&route);
        self.note(&format!(
            "packet {from} to {to}: {} ({delivered_or_not}, cost {cost})",
            join_ids(&route),
            delivered_or_not = if delivered { "delivered" } else { "dropped" }
        ));
        Ok(Delivery {
            route,
            delivered,
            cost,
            searched,
        })
    }

    /// The current state of the whole network, as JSON.
    pub fn snapshot(&self) -> String {
        let nodes = self
            .nodes
            .iter()
            .map(|(id, node)| {
                format!(
                    r#"{{"id":{id},"key":{},"root":{},"parent":{},"path":{},"cost":{},"peers":{},"knows":{}}}"#,
                    json_string(&short_key(node.key())),
                    self.id_of(node.root()),
                    match node.parent() {
                        Some(parent) => self.id_of(parent).to_string(),
                        None => "null".into(),
                    },
                    json_ids(node.path().iter().map(|hop| self.id_of(hop.key))),
                    node.cost_to_root(),
                    json_ids(node.peers().map(|(peer, _)| self.id_of(peer))),
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
                format!(
                    r#"{{"a":{a},"b":{b},"cost":{cost},"tree":{tree},"summary":[{},{}]}}"#,
                    self.summary_across(*a, *b),
                    self.summary_across(*b, *a)
                )
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

    /// How full the summary `from` sends `to` is, or `null` where the link is
    /// not part of the tree and so carries no summary at all.
    fn summary_across(&self, from: Id, to: Id) -> String {
        let Ok(peer) = self.require(to) else {
            return "null".into();
        };
        match self
            .nodes
            .get(&from)
            .and_then(|node| node.summary_for(peer))
        {
            Some(summary) => summary.filled().to_string(),
            None => "null".into(),
        }
    }

    /// Whether `from` holds a position for `to` and could address it now.
    fn knows(&self, from: Id, to: Id) -> bool {
        let Ok(target) = self.require(to) else {
            return false;
        };
        self.nodes
            .get(&from)
            .is_some_and(|node| node.known().any(|known| known == target))
    }

    /// The key a label stands for, or an error naming the label that has none.
    fn require(&self, id: Id) -> Result<PublicKey, String> {
        self.keys
            .get(&id)
            .copied()
            .ok_or_else(|| format!("no node {id}"))
    }

    /// The label a key goes by here.
    ///
    /// Every key the simulation handles belongs to one of its own nodes, so
    /// the fallback stands for a state this cannot reach; labels start at one,
    /// which leaves zero free to be visibly wrong if it ever did.
    fn id_of(&self, key: PublicKey) -> Id {
        self.ids.get(&key).copied().unwrap_or(0)
    }

    fn node(&self, id: Id) -> Result<&Signed, String> {
        self.nodes.get(&id).ok_or(format!("no node {id}"))
    }

    fn node_mut(&mut self, id: Id) -> Result<&mut Signed, String> {
        self.nodes.get_mut(&id).ok_or(format!("no node {id}"))
    }

    fn parent_of(&self, id: Id) -> Option<Id> {
        let parent = self.nodes.get(&id)?.parent()?;
        Some(self.id_of(parent))
    }

    fn peers_of(&self, id: Id) -> Vec<Id> {
        match self.nodes.get(&id) {
            Some(node) => node.peers().map(|(peer, _)| self.id_of(peer)).collect(),
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
            let (Ok(far_key), Some(node)) = (self.require(far), self.nodes.get_mut(&near)) else {
                continue;
            };
            let outbound = node.add_peer(now, far_key, cost);
            self.enqueue(near, outbound);
        }
        self.run();
    }

    /// Drops a link on both sides without logging or running the queue.
    fn unlink(&mut self, a: Id, b: Id) {
        self.links.remove(&ordered(a, b));
        let now = self.now;
        for (near, far) in [(a, b), (b, a)] {
            let (Ok(far_key), Some(node)) = (self.require(far), self.nodes.get_mut(&near)) else {
                continue;
            };
            let outbound = node.remove_peer(now, far_key);
            self.enqueue(near, outbound);
        }
    }

    fn enqueue(&mut self, from: Id, outbound: Vec<Envelope>) {
        let Ok(from_key) = self.require(from) else {
            return;
        };
        for envelope in outbound {
            self.queue.push_back(InFlight {
                to: envelope.to,
                from: from_key,
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
            let holder = self.id_of(in_flight.to);
            if matches!(in_flight.message, Message::Lookup(_)) {
                self.searched.push(holder);
            }
            let now = self.now;
            let Ok(node) = self.node_mut(holder) else {
                continue;
            };
            let outbound = node.handle(now, in_flight.from, in_flight.message);
            self.enqueue(holder, outbound);
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

/// Node labels as an arrow-separated trail, for the log.
fn join_ids(ids: &[Id]) -> String {
    ids.iter()
        .map(Id::to_string)
        .collect::<Vec<_>>()
        .join(" \u{2192} ")
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
