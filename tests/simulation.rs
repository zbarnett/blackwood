//! A deterministic simulation of a small network.
//!
//! The simulator is the whole of the "network" here: a queue of messages in
//! flight and a map of nodes to hand them to. Links never reorder or drop, and
//! nothing runs concurrently, so a run is reproducible down to the hop.

use std::collections::{BTreeMap, VecDeque};

use blackwood::{KEY_LEN, Message, Node, Packet, PublicKey};

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
}

impl Network {
    fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            nodes: keys.into_iter().map(|k| (k, Node::new(k))).collect(),
            queue: VecDeque::new(),
            hops: 0,
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
        for (near, far) in [(a, b), (b, a)] {
            let outbound = self.node_mut(near).add_peer(far);
            self.enqueue(near, outbound);
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
            let outbound = self
                .node_mut(in_flight.to)
                .handle(in_flight.from, in_flight.message);
            self.enqueue(in_flight.to, outbound);
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
