//! A deterministic simulation of a small network.
//!
//! The simulator is the whole of the "network" here: a queue of messages in
//! flight, a map of nodes to hand them to, and a clock that only moves when the
//! test moves it. Links never reorder or drop, and nothing runs concurrently,
//! so a run is reproducible down to the hop.

use std::collections::{BTreeMap, VecDeque};

use blackwood::{KEY_LEN, Message, Node, Packet, PublicKey, SendError, Timing};

fn key(n: u8) -> PublicKey {
    PublicKey::new([n; KEY_LEN])
}

/// A message in flight, from one node to a linked peer.
struct InFlight {
    to: PublicKey,
    from: PublicKey,
    message: Message,
}

struct Network {
    nodes: BTreeMap<PublicKey, Node>,
    queue: VecDeque<InFlight>,
    /// How many times a packet has been handed to a node, i.e. hops taken.
    hops: usize,
    /// The clock every node shares. Only [`Network::advance`] moves it.
    now: u64,
}

impl Network {
    fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            nodes: keys.into_iter().map(|k| (k, Node::new(0, k))).collect(),
            queue: VecDeque::new(),
            hops: 0,
            now: 0,
        }
    }

    fn node(&self, key: PublicKey) -> &Node {
        self.nodes.get(&key).expect("node is in the network")
    }

    fn node_mut(&mut self, key: PublicKey) -> &mut Node {
        self.nodes.get_mut(&key).expect("node is in the network")
    }

    /// Brings up a bidirectional link between two nodes.
    fn link(&mut self, a: PublicKey, b: PublicKey) {
        let now = self.now;
        for (near, far) in [(a, b), (b, a)] {
            let outbound = self.node_mut(near).add_peer(now, far);
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
        let step = Timing::DEFAULT.refresh;
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

    fn enqueue(&mut self, from: PublicKey, outbound: Vec<blackwood::Envelope>) {
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
            if matches!(in_flight.message, Message::Packet(_)) {
                self.hops += 1;
            }
            let now = self.now;
            let outbound =
                self.node_mut(in_flight.to)
                    .handle(now, in_flight.from, in_flight.message);
            self.enqueue(in_flight.to, outbound);
        }
    }

    /// Where every node believes it sits, for comparing one moment to another.
    fn positions(&self, keys: &[PublicKey]) -> Vec<(PublicKey, Option<PublicKey>, Vec<PublicKey>)> {
        keys.iter()
            .map(|&key| {
                let node = self.node(key);
                (node.root(), node.parent(), node.path().to_vec())
            })
            .collect()
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
/// The `b - d` link gives `d` a shorter path to the root than going through
/// `c`, so the tree that forms is not simply the order the links came up in,
/// and the cycle `b - c - d` gives a wrong implementation somewhere to loop.
fn ring_with_a_tail() -> (Network, [PublicKey; 5]) {
    let keys = [key(1), key(2), key(3), key(4), key(5)];
    let [a, b, c, d, e] = keys;

    let mut net = Network::new(keys);
    net.link(a, b);
    net.link(b, c);
    net.link(c, d);
    net.link(b, d);
    net.link(d, e);
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

    // Each node's path is its parent's path with itself appended, which is the
    // consistency greedy forwarding relies on.
    for node in [b, c, d, e] {
        let path = net.node(node).path();
        let parent = net.node(node).parent().expect("only a is the root");
        let (head, tail) = path.split_at(path.len() - 1);
        assert_eq!(head, net.node(parent).path(), "path disagrees with parent");
        assert_eq!(tail, [node]);
    }

    // One packet, from the root down to the far end of the tail.
    let outbound = net
        .node_mut(a)
        .send(e, b"hello ironwood".to_vec())
        .expect("the route is known once the tree has settled");
    net.enqueue(a, outbound);
    net.run();

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
fn every_node_can_reach_every_other() {
    let (mut net, keys) = ring_with_a_tail();
    net.run();

    for src in keys {
        for dst in keys {
            if src == dst {
                continue;
            }
            let outbound = net
                .node_mut(src)
                .send(dst, vec![src.as_bytes()[0], dst.as_bytes()[0]])
                .unwrap_or_else(|error| panic!("{src:?} has no route to {dst:?}: {error}"));
            net.enqueue(src, outbound);
            net.run();

            assert_eq!(
                net.node_mut(dst).take_delivered(),
                vec![Packet {
                    src,
                    dst,
                    payload: vec![src.as_bytes()[0], dst.as_bytes()[0]],
                }]
            );
        }
    }
}

#[test]
fn a_link_coming_up_late_is_absorbed() {
    let keys = [key(3), key(1), key(2)];
    let [c, a, b] = keys;

    // Bring up a single link. b holds the smaller of the two keys present, so
    // the pair roots on b.
    let mut net = Network::new(keys);
    net.link(c, b);
    net.run();
    assert_eq!(net.node(c).root(), b);
    assert_eq!(net.node(c).parent(), Some(b));

    // a joins, holding a smaller key, and the tree re-roots onto it.
    net.link(a, b);
    net.run();

    for node in [a, b, c] {
        assert_eq!(net.node(node).root(), a);
    }
    assert_eq!(net.node(b).parent(), Some(a));
    assert_eq!(net.node(c).parent(), Some(b));
}

#[test]
fn a_settled_network_is_undisturbed_by_the_passage_of_time() {
    let (mut net, keys) = ring_with_a_tail();
    net.run();
    let before = net.positions(&keys);

    // Long enough that every announcement would have expired many times over
    // had it not been reissued.
    net.advance(Timing::DEFAULT.expiry * 10);

    assert_eq!(
        net.positions(&keys),
        before,
        "reissues left every node exactly where it was"
    );
    for node in keys {
        assert_eq!(
            net.node(node).known().count(),
            keys.len() - 1,
            "everyone still knows where everyone else is"
        );
    }
}

#[test]
fn a_stranded_node_is_eventually_forgotten() {
    let (mut net, [a, b, c, d, e]) = ring_with_a_tail();
    net.run();

    // e hangs off d alone, so taking that link down strands it.
    net.unlink(d, e);
    net.run();

    // Its neighbours reparent at once, but nothing has yet told them e is gone,
    // so they still believe they hold a route to it.
    assert!(net.node(d).known().any(|known| known == e));
    assert!(
        net.node_mut(a).send(e, b"still there?".to_vec()).is_ok(),
        "a would send a packet into the dead end"
    );

    net.advance(Timing::DEFAULT.expiry);

    for node in [a, b, c, d] {
        assert!(
            !net.node(node).known().any(|known| known == e),
            "{node:?} still remembers e"
        );
    }
    assert_eq!(
        net.node_mut(a).send(e, b"gone".to_vec()),
        Err(SendError::NoRoute),
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
    net.advance(Timing::DEFAULT.expiry * 4);
    assert!(!net.node(d).known().any(|known| known == e));

    // It comes back as a fresh process would: same key, sequence numbers back
    // at zero. Without expiry that announcement would look like ancient news
    // and every node would go on routing towards where e used to be.
    net.nodes.insert(e, Node::new(net.now, e));
    net.link(d, e);
    net.run();

    assert_eq!(
        net.node(e).root(),
        a,
        "the returning node is back on the tree"
    );
    assert_eq!(net.node(e).parent(), Some(d));

    let outbound = net
        .node_mut(a)
        .send(e, b"welcome back".to_vec())
        .expect("the route is known again");
    net.enqueue(a, outbound);
    net.run();
    assert_eq!(
        net.node_mut(e).take_delivered(),
        vec![Packet {
            src: a,
            dst: e,
            payload: b"welcome back".to_vec(),
        }]
    );
}
