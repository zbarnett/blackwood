//! A deterministic simulation of a small network.
//!
//! The simulator is the whole of the "network" here: a queue of messages in
//! flight, a map of nodes to hand them to, and a clock that only moves when the
//! test moves it. Links never reorder or drop, and nothing runs concurrently,
//! so a run is reproducible down to the hop.

use std::collections::{BTreeMap, VecDeque};

use routing_core::{
    Cost, Hop, KEY_LEN, Message, NONCE_LEN, Node, Nonce, Packet, PublicKey, SIGNATURE_LEN,
    SendError, Signature, Signer, Timing,
};

fn key(n: u8) -> PublicKey {
    PublicKey::new([n; KEY_LEN])
}

/// A signer with the cryptography left out, which is what lets this simulation
/// use keys that read as `01`, `02`, `03` and still drive exactly the code a
/// real network runs — the core cannot tell one signer from another.
///
/// A signature is a hash of the key and the message, so it changes with what it
/// covers, and anybody can produce one for anybody. Nothing here forges
/// anything; that, and what real cryptography does instead, is exercised in the
/// `blackwood-ed25519` crate against a network built the same way.
struct StandIn(PublicKey);

impl Signer for StandIn {
    fn public_key(&self) -> PublicKey {
        self.0
    }

    fn sign(&self, message: &[u8]) -> Signature {
        stamp(self.0, message)
    }

    fn verify(key: PublicKey, message: &[u8], signature: &Signature) -> bool {
        &stamp(key, message) == signature
    }
}

/// FNV-1a over the key and the message, salted per eight-byte chunk so that one
/// input fills a whole signature.
fn stamp(key: PublicKey, message: &[u8]) -> Signature {
    let mut bytes = [0; SIGNATURE_LEN];
    for (round, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in std::iter::once(round as u8)
            .chain(key.as_bytes().iter().copied())
            .chain(message.iter().copied())
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        // Every chunk of a 64-byte array split eight ways is eight bytes long.
        chunk.copy_from_slice(&hash.to_be_bytes());
    }
    Signature::new(bytes)
}

fn signer(key: PublicKey) -> StandIn {
    StandIn(key)
}

fn cost(n: u64) -> Cost {
    Cost::new(n).expect("a test cost is never zero")
}

/// Where one node believes it sits: the root it answers to, its parent, and
/// the walk down to it.
type Position = (PublicKey, Option<PublicKey>, Vec<(PublicKey, u64)>);

/// The walk a path describes, with the stamps and signatures set aside.
///
/// Two nodes holding differently stamped copies of the same walk are in the
/// same place, and that is what these tests mean when they compare positions.
fn walk(path: &[Hop]) -> Vec<(PublicKey, u64)> {
    path.iter().map(|hop| (hop.key, hop.cost)).collect()
}

/// A message in flight, from one node to a linked peer.
struct InFlight {
    to: PublicKey,
    from: PublicKey,
    message: Message,
}

struct Network {
    nodes: BTreeMap<PublicKey, Node<StandIn>>,
    queue: VecDeque<InFlight>,
    /// How many times a packet has been handed to a node, i.e. hops taken.
    hops: usize,
    /// The nodes the last search passed through, in the order they saw it.
    searched: Vec<PublicKey>,
    /// The clock every node shares. Only [`Network::advance`] moves it.
    now: u64,
    /// Counts off the numbers searches go out with. A real caller would take
    /// these from the operating system; a simulation only needs them to
    /// differ from one another.
    nonces: u64,
}

impl Network {
    fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            nodes: keys
                .into_iter()
                .map(|k| (k, Node::new(0, signer(k), Timing::MILLISECONDS)))
                .collect(),
            queue: VecDeque::new(),
            hops: 0,
            searched: Vec::new(),
            now: 0,
            nonces: 0,
        }
    }

    fn node(&self, key: PublicKey) -> &Node<StandIn> {
        self.nodes.get(&key).expect("node is in the network")
    }

    fn node_mut(&mut self, key: PublicKey) -> &mut Node<StandIn> {
        self.nodes.get_mut(&key).expect("node is in the network")
    }

    /// Brings up a bidirectional link between two nodes, costing the same to
    /// cross from either end.
    ///
    /// Called for a link that is already up, it re-prices it instead — the
    /// caller of a real node does this whenever it measures a peering again.
    fn link(&mut self, a: PublicKey, b: PublicKey, cost: Cost) {
        let now = self.now;
        for (near, far) in [(a, b), (b, a)] {
            let outbound = self.node_mut(near).add_peer(now, far, cost);
            self.enqueue(near, outbound);
        }
    }

    /// Takes a bidirectional link back down.
    fn unlink(&mut self, a: PublicKey, b: PublicKey) {
        let now = self.now;
        for (near, far) in [(a, b), (b, a)] {
            let outbound = self.node_mut(near).remove_peer(now, far);
            self.enqueue(near, outbound);
        }
    }

    /// Moves the clock forward by `by`, letting every node reissue and expire.
    ///
    /// Time is stepped in refresh-sized increments rather than jumped in one
    /// go, because a jump would look to every node as though the whole network
    /// had fallen silent for the entire interval.
    fn advance(&mut self, by: u64) {
        let step = Timing::MILLISECONDS.refresh;
        let target = self.now + by;
        while self.now < target {
            self.now = (self.now + step).min(target);
            let now = self.now;
            for key in self.nodes.keys().copied().collect::<Vec<_>>() {
                let outbound = self.node_mut(key).tick(now);
                self.enqueue(key, outbound);
            }
            self.run();
        }
    }

    fn enqueue(&mut self, from: PublicKey, outbound: Vec<routing_core::Envelope>) {
        for envelope in outbound {
            self.queue.push_back(InFlight {
                to: envelope.to,
                from,
                message: envelope.message,
            });
        }
    }

    /// Delivers messages until the network falls quiet.
    ///
    /// The step limit is itself an assertion: gossip that failed to settle
    /// would otherwise spin here forever.
    fn run(&mut self) {
        const MAX_STEPS: usize = 10_000;

        for step in 0.. {
            assert!(step < MAX_STEPS, "network did not settle");
            let Some(in_flight) = self.queue.pop_front() else {
                return;
            };
            match in_flight.message {
                Message::Traffic(_) => self.hops += 1,
                Message::Lookup(_) => self.searched.push(in_flight.to),
                _ => {}
            }
            let now = self.now;
            let outbound =
                self.node_mut(in_flight.to)
                    .handle(now, in_flight.from, in_flight.message);
            self.enqueue(in_flight.to, outbound);
        }
    }

    /// Asks the network where `dst` sits on `src`'s behalf, and reports which
    /// nodes the search passed through.
    fn find(&mut self, src: PublicKey, dst: PublicKey) -> Vec<PublicKey> {
        self.nonces += 1;
        let mut bytes = [0; NONCE_LEN];
        bytes[..8].copy_from_slice(&self.nonces.to_be_bytes());
        let (now, nonce) = (self.now, Nonce::new(bytes));
        let outbound = self.node_mut(src).lookup(now, dst, nonce);
        self.searched.clear();
        self.enqueue(src, outbound);
        self.run();
        std::mem::take(&mut self.searched)
    }

    /// Looks up where `dst` sits and then sends one packet to it, which is the
    /// two steps every conversation between strangers begins with.
    fn send(&mut self, src: PublicKey, dst: PublicKey, payload: &[u8]) {
        self.find(src, dst);
        let outbound = self
            .node_mut(src)
            .send(dst, payload.to_vec())
            .unwrap_or_else(|error| panic!("{src:?} cannot reach {dst:?}: {error}"));
        self.enqueue(src, outbound);
        self.run();
    }

    /// Where every node believes it sits, for comparing one moment to another.
    ///
    /// The walk, not the announcement: a reissue restamps and re-signs without
    /// moving anybody, and a node that had gone nowhere would otherwise look
    /// like one that had.
    fn positions(&self, keys: &[PublicKey]) -> Vec<Position> {
        keys.iter()
            .map(|&key| {
                let node = self.node(key);
                (node.root(), node.parent(), walk(node.path()))
            })
            .collect()
    }

    /// Checks the invariant greedy forwarding rests on: every node's path is
    /// its parent's path with one hop more on the end, priced at what that
    /// node measured the link to its parent to cost.
    fn paths_agree_with_parents(&self, keys: &[PublicKey]) {
        for &key in keys {
            let node = self.node(key);
            let Some(parent) = node.parent() else {
                assert_eq!(walk(node.path()), [(key, 0)], "a root's path is itself");
                continue;
            };
            let (_, cost) = node
                .peers()
                .find(|(peer, _)| *peer == parent)
                .expect("a node's parent is one of its peers");
            let (head, tail) = node.path().split_at(node.path().len() - 1);
            assert_eq!(
                walk(head),
                walk(self.node(parent).path()),
                "path disagrees with parent"
            );
            assert_eq!(walk(tail), [(key, cost.get())]);
        }
    }

    /// Sends one packet between every ordered pair of nodes and checks that
    /// each one arrives where it was addressed.
    fn everyone_reaches_everyone(&mut self, keys: &[PublicKey]) {
        for &src in keys {
            for &dst in keys {
                if src == dst {
                    continue;
                }
                let payload = vec![src.as_bytes()[0], dst.as_bytes()[0]];
                self.send(src, dst, &payload);
                assert_eq!(
                    self.node_mut(dst).take_delivered(),
                    vec![Packet { src, dst, payload }]
                );
            }
        }
    }
}

/// The topology under test:
///
/// ```text
///     a --- b --- c
///           |     |
///           d --- +
///           |
///           e
/// ```
///
/// Every link costs the same, so distance here is counted in hops. The
/// `b - d` link gives `d` a shorter path to the root than going through `c`,
/// so the tree that forms is not simply the order the links came up in, and
/// the cycle `b - c - d` gives a wrong implementation somewhere to loop.
fn ring_with_a_tail() -> (Network, [PublicKey; 5]) {
    let keys = [key(1), key(2), key(3), key(4), key(5)];
    let [a, b, c, d, e] = keys;

    let mut net = Network::new(keys);
    for (near, far) in [(a, b), (b, c), (c, d), (b, d), (d, e)] {
        net.link(near, far, Cost::UNIT);
    }
    (net, keys)
}

/// The same topology, with the `b - d` link made expensive:
///
/// ```text
///     a -1- b -1- c
///           |     |
///           5     1
///           |     |
///           d --- +
///           |
///           1
///           |
///           e
/// ```
///
/// Every shortest path by hop count still runs over `b - d`, and every cheapest
/// one avoids it, so the two metrics disagree everywhere it matters.
fn ring_with_one_expensive_link() -> (Network, [PublicKey; 5]) {
    let keys = [key(1), key(2), key(3), key(4), key(5)];
    let [a, b, c, d, e] = keys;

    let mut net = Network::new(keys);
    for (near, far, price) in [(a, b, 1), (b, c, 1), (c, d, 1), (b, d, 5), (d, e, 1)] {
        net.link(near, far, cost(price));
    }
    (net, keys)
}

#[test]
fn brings_up_a_network_and_carries_a_packet_across_it() {
    let (mut net, [a, b, c, d, e]) = ring_with_a_tail();

    net.run();

    // Every node agrees on the smallest key as the root, and each sits below
    // the peer offering it the shortest path there.
    for node in [a, b, c, d, e] {
        assert_eq!(net.node(node).root(), a, "disagreement about the root");
    }
    assert_eq!(net.node(a).parent(), None);
    assert_eq!(net.node(b).parent(), Some(a));
    assert_eq!(net.node(c).parent(), Some(b));
    assert_eq!(
        net.node(d).parent(),
        Some(b),
        "the b-d link beats going via c"
    );
    assert_eq!(net.node(e).parent(), Some(d));

    net.paths_agree_with_parents(&[a, b, c, d, e]);

    // One packet, from the root down to the far end of the tail.
    net.send(a, e, b"hello ironwood");

    assert_eq!(
        net.node_mut(e).take_delivered(),
        vec![Packet {
            src: a,
            dst: e,
            payload: b"hello ironwood".to_vec(),
        }]
    );
    for node in [a, b, c, d] {
        assert!(
            net.node_mut(node).take_delivered().is_empty(),
            "the packet was delivered somewhere it was not addressed"
        );
    }
    assert_eq!(net.hops, 3, "expected a -> b -> d -> e");
}

#[test]
fn a_node_holds_a_position_for_its_peers_and_nobody_else() {
    let (mut net, keys) = ring_with_a_tail();
    net.run();

    for node in keys {
        let peers: Vec<_> = net.node(node).peers().map(|(peer, _)| peer).collect();
        let known: Vec<_> = net.node(node).known().collect();
        assert_eq!(known, peers, "{node:?} holds a position it never asked for");
    }

    // Ten positions held across the network, two per link, rather than the
    // twenty a flood would leave — and the gap widens with every node added.
    let held: usize = keys.iter().map(|&k| net.node(k).known().count()).sum();
    assert_eq!(held, 10);
}

#[test]
fn a_search_reaches_only_the_branches_that_might_hold_its_target() {
    let (mut net, [a, b, _c, d, e]) = ring_with_a_tail();
    net.run();

    // The tree runs a - b, b - c, b - d, d - e, so e lies beyond d and nowhere
    // near c. b passes the search to d alone: what c told it about its own side
    // of their link says e is not down there, and that is the whole point of a
    // summary.
    assert_eq!(net.find(a, e), vec![b, d, e]);
    assert!(
        net.node(a).known().any(|known| known == e),
        "the answer came back and a can now address e"
    );

    // Nothing anywhere claims a key that was never in the network, so a search
    // for one leaves the asker's own doorstep and stops.
    assert!(net.find(a, key(9)).is_empty());
    assert!(!net.node(a).known().any(|known| known == key(9)));
}

#[test]
fn a_search_finds_every_node_from_every_node() {
    let (mut net, keys) = ring_with_a_tail();
    net.run();

    for src in keys {
        for dst in keys {
            if src == dst {
                continue;
            }
            let searched = net.find(src, dst);
            assert!(
                searched.contains(&dst),
                "a search from {src:?} never reached {dst:?}, visiting {searched:?}"
            );
            assert!(
                net.node(src).known().any(|known| known == dst),
                "{src:?} asked where {dst:?} was and got no answer"
            );
        }
    }
}

#[test]
fn a_summary_names_everything_on_its_own_side_of_a_link_and_nothing_else() {
    let (mut net, [a, b, c, d, e]) = ring_with_a_tail();
    net.run();

    // Taking the tree link b - d out leaves a, b, c on one side and d, e on
    // the other, and each end's summary describes exactly its own side.
    let above = net.node(b).summary_for(d).expect("b - d is a tree link");
    let below = net.node(d).summary_for(b).expect("b - d is a tree link");

    for near in [a, b, c] {
        assert!(above.contains(near), "b's side is missing {near:?}");
        assert!(!below.contains(near), "d's side wrongly claims {near:?}");
    }
    for far in [d, e] {
        assert!(below.contains(far), "d's side is missing {far:?}");
        assert!(!above.contains(far), "b's side wrongly claims {far:?}");
    }

    // The c - d link closes the cycle and is not part of the tree, so no
    // summary crosses it. Folding them around a cycle would carry every key
    // back to where it came from until both ends claimed everything.
    assert_eq!(net.node(c).summary_for(d), None);
    assert_eq!(net.node(d).summary_for(c), None);
}

#[test]
fn every_node_can_reach_every_other() {
    let (mut net, keys) = ring_with_a_tail();
    net.run();
    net.everyone_reaches_everyone(&keys);
}

#[test]
fn every_node_can_reach_every_other_over_priced_links() {
    let (mut net, keys) = ring_with_one_expensive_link();
    net.run();
    net.everyone_reaches_everyone(&keys);
}

#[test]
fn the_cheapest_walk_wins_over_the_shortest_one() {
    let (mut net, [a, b, c, d, e]) = ring_with_one_expensive_link();

    net.run();

    for node in [a, b, c, d, e] {
        assert_eq!(net.node(node).root(), a, "disagreement about the root");
    }
    assert_eq!(
        net.node(d).parent(),
        Some(c),
        "one link costing 5 is worse than two costing 1 apiece"
    );
    assert_eq!(net.node(d).cost_to_root(), 3);
    assert_eq!(net.node(e).parent(), Some(d));
    assert_eq!(net.node(e).cost_to_root(), 4);
    net.paths_agree_with_parents(&[a, b, c, d, e]);

    // The same packet the unit-cost network carries in three hops. Here it
    // takes four, and pays 4 rather than the 7 the short way would have cost.
    net.send(a, e, b"the long way round");

    assert_eq!(
        net.node_mut(e).take_delivered(),
        vec![Packet {
            src: a,
            dst: e,
            payload: b"the long way round".to_vec(),
        }]
    );
    assert_eq!(net.hops, 4, "expected a -> b -> c -> d -> e");
}

#[test]
fn a_packet_refuses_an_expensive_shortcut() {
    let (mut net, [_a, b, c, d, e]) = ring_with_one_expensive_link();
    net.run();

    // b holds a link straight to d, which is one hop from the destination.
    // Crossing it costs 5, where walking the tree by way of c costs 3.
    assert!(net.node(b).peers().any(|(peer, _)| peer == d));

    net.send(b, e, b"not that way");

    assert!(!net.node_mut(e).take_delivered().is_empty());
    assert_eq!(net.hops, 3, "expected b -> c -> d -> e, not b -> d -> e");
    assert!(
        net.node_mut(c).take_delivered().is_empty(),
        "c carried the packet, it was not addressed to it"
    );
}

#[test]
fn re_pricing_a_link_reshapes_the_tree() {
    let (mut net, [a, b, c, d, e]) = ring_with_one_expensive_link();
    net.run();
    assert_eq!(net.node(d).parent(), Some(c));

    // The link is measured again and turns out to be as good as any other,
    // which is the same call that brought it up in the first place.
    net.link(b, d, Cost::UNIT);
    net.run();

    assert_eq!(
        net.node(d).parent(),
        Some(b),
        "the direct link is now cheapest"
    );
    assert_eq!(net.node(d).cost_to_root(), 2);
    assert_eq!(net.node(e).cost_to_root(), 3);
    net.paths_agree_with_parents(&[a, b, c, d, e]);

    // The tree moved, so the summaries moved with it: c - d has stopped being
    // a tree link and b - d has become one.
    assert_eq!(net.node(c).parent(), Some(b));
    assert_eq!(net.node(d).summary_for(c), None);
    assert!(net.node(d).summary_for(b).is_some());

    net.send(a, e, b"straight through");
    assert!(!net.node_mut(e).take_delivered().is_empty());
    assert_eq!(net.hops, 3, "expected a -> b -> d -> e");
}

#[test]
fn a_link_coming_up_late_is_absorbed() {
    let keys = [key(3), key(1), key(2)];
    let [c, a, b] = keys;

    // Bring up a single link. b holds the smaller of the two keys present, so
    // the pair roots on b.
    let mut net = Network::new(keys);
    net.link(c, b, Cost::UNIT);
    net.run();
    assert_eq!(net.node(c).root(), b);
    assert_eq!(net.node(c).parent(), Some(b));

    // a joins, holding a smaller key, and the tree re-roots onto it.
    net.link(a, b, Cost::UNIT);
    net.run();

    for node in [a, b, c] {
        assert_eq!(net.node(node).root(), a);
    }
    assert_eq!(net.node(b).parent(), Some(a));
    assert_eq!(net.node(c).parent(), Some(b));

    // c can be found from a even though nothing between them ever held its
    // position: the search walks down the summaries and the answer walks back.
    assert_eq!(net.find(a, c), vec![b, c]);
    net.send(a, c, b"welcome");
    assert!(!net.node_mut(c).take_delivered().is_empty());
}

#[test]
fn a_settled_network_is_undisturbed_by_the_passage_of_time() {
    let (mut net, keys) = ring_with_a_tail();
    net.run();
    let before = net.positions(&keys);

    // Long enough that every announcement would have expired many times over
    // had it not been reissued.
    net.advance(Timing::MILLISECONDS.expiry * 10);

    assert_eq!(
        net.positions(&keys),
        before,
        "reissues left every node exactly where it was"
    );
    for node in keys {
        assert_eq!(
            net.node(node).known().count(),
            net.node(node).peers().count(),
            "everyone still knows where its own peers are"
        );
    }
}

#[test]
fn a_stranded_node_is_eventually_forgotten() {
    let (mut net, [a, b, c, d, e]) = ring_with_a_tail();
    net.run();

    // a asks where e is and is told, which is the only reason it holds a
    // position for a node three hops away.
    net.find(a, e);
    assert!(net.node(a).known().any(|known| known == e));

    // e hangs off d alone, so taking that link down strands it.
    net.unlink(d, e);
    net.run();

    // Nothing has told a that e is gone, so it would still send a packet into
    // what is now a dead end. The summaries, though, moved at once: d stopped
    // claiming e the moment the link went.
    assert!(net.node_mut(a).send(e, b"still there?".to_vec()).is_ok());
    assert!(net.find(a, e).is_empty(), "no branch admits e any more");

    net.advance(Timing::MILLISECONDS.expiry);

    for node in [a, b, c, d] {
        assert!(
            !net.node(node).known().any(|known| known == e),
            "{node:?} still remembers e"
        );
    }
    assert_eq!(
        net.node_mut(a).send(e, b"gone".to_vec()),
        Err(SendError::Unknown),
        "the route to nowhere is gone rather than silently dropping packets"
    );
    assert_eq!(net.node(e).root(), e, "and e is now a network of one");
}

#[test]
fn a_node_that_starts_over_rejoins_the_tree() {
    let (mut net, [a, _b, _c, d, e]) = ring_with_a_tail();
    net.run();

    // e leaves and, over the course of the outage, is forgotten. Meanwhile the
    // e that is still running climbs to a much higher sequence number.
    net.unlink(d, e);
    net.advance(Timing::MILLISECONDS.expiry * 4);
    assert!(!net.node(d).known().any(|known| known == e));

    // It comes back as a fresh process would: same key, sequence numbers back
    // at zero. Without expiry that announcement would look like ancient news
    // and every node would go on routing towards where e used to be.
    net.nodes
        .insert(e, Node::new(net.now, signer(e), Timing::MILLISECONDS));
    net.link(d, e, Cost::UNIT);
    net.run();

    assert_eq!(
        net.node(e).root(),
        a,
        "the returning node is back on the tree"
    );
    assert_eq!(net.node(e).parent(), Some(d));

    net.send(a, e, b"welcome back");
    assert_eq!(
        net.node_mut(e).take_delivered(),
        vec![Packet {
            src: a,
            dst: e,
            payload: b"welcome back".to_vec(),
        }]
    );
}
