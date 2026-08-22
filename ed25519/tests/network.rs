//! A network whose nodes sign with real ed25519.
//!
//! The core's own simulation runs on a stand-in signer, where every key is
//! legible and the root is whichever one reads smallest. This one runs on keys
//! nobody chose, to show that the protocol never depended on that — and that a
//! position nobody signed for is refused rather than routed on.

use std::collections::{BTreeMap, VecDeque};

use blackwood_ed25519::Ed25519;
use routing_core::{
    Announcement, Cost, MalformedAnnouncement, Message, Node, Packet, PublicKey, SIGNATURE_LEN,
    Signature, Signer, Timing,
};

/// A message in flight, from one node to a linked peer.
struct InFlight {
    to: PublicKey,
    from: PublicKey,
    message: Message,
}

struct Network {
    nodes: BTreeMap<PublicKey, Node<Ed25519>>,
    queue: VecDeque<InFlight>,
}

impl Network {
    /// A network of `count` nodes, each with a key derived from a seed and so
    /// in no particular order.
    fn new(count: u8) -> (Self, Vec<PublicKey>) {
        let mut net = Self {
            nodes: BTreeMap::new(),
            queue: VecDeque::new(),
        };
        let keys = (1..=count)
            .map(|seed| {
                let signer = Ed25519::from_seed([seed; 32]);
                let key = signer.key();
                net.nodes
                    .insert(key, Node::new(0, signer, Timing::MILLISECONDS));
                key
            })
            .collect();
        (net, keys)
    }

    fn node(&self, key: PublicKey) -> &Node<Ed25519> {
        self.nodes.get(&key).expect("node is in the network")
    }

    fn node_mut(&mut self, key: PublicKey) -> &mut Node<Ed25519> {
        self.nodes.get_mut(&key).expect("node is in the network")
    }

    fn link(&mut self, a: PublicKey, b: PublicKey, cost: Cost) {
        for (near, far) in [(a, b), (b, a)] {
            let outbound = self.node_mut(near).add_peer(0, far, cost);
            self.enqueue(near, outbound);
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

    /// Delivers messages until the network falls quiet. The step limit is
    /// itself an assertion: a network that never settled would spin here.
    fn run(&mut self) {
        for step in 0.. {
            assert!(step < 10_000, "network did not settle");
            let Some(in_flight) = self.queue.pop_front() else {
                return;
            };
            let outbound = self
                .node_mut(in_flight.to)
                .handle(0, in_flight.from, in_flight.message);
            self.enqueue(in_flight.to, outbound);
        }
    }

    /// Asks where `dst` sits on `src`'s behalf, then sends one packet to it.
    fn send(&mut self, src: PublicKey, dst: PublicKey, payload: &[u8]) {
        let lookup = self.node(src).lookup(dst);
        self.enqueue(src, lookup);
        self.run();

        let outbound = self
            .node_mut(src)
            .send(dst, payload.to_vec())
            .unwrap_or_else(|error| panic!("{src:?} cannot reach {dst:?}: {error}"));
        self.enqueue(src, outbound);
        self.run();
    }
}

/// Five nodes in the shape the core's simulation uses, but keyed by ed25519.
///
/// Every link costs five rather than one, so that a node claiming a link cost
/// of one would be claiming something — which is what the forgery test needs.
fn ring_with_a_tail() -> (Network, Vec<PublicKey>) {
    let dear = Cost::new(5).expect("not zero");
    let (mut net, keys) = Network::new(5);
    for (near, far) in [(0, 1), (1, 2), (2, 3), (1, 3), (3, 4)] {
        net.link(keys[near], keys[far], dear);
    }
    net.run();
    (net, keys)
}

#[test]
fn a_network_of_signed_nodes_settles_on_one_root() {
    let (net, keys) = ring_with_a_tail();

    // Nobody chose these keys, so which node ends up as the root is not
    // something this test gets to know in advance — only that they agree, and
    // that they agree on the smallest, which is the rule the tree runs on.
    let smallest = *keys.iter().min().expect("the network is not empty");
    for &key in &keys {
        assert_eq!(
            net.node(key).root(),
            smallest,
            "disagreement about the root"
        );
    }
    assert_eq!(net.node(smallest).parent(), None);

    // Every node's walk is its parent's with one hop more, and the whole of it
    // checks out: each hop signed by the node it names.
    for &key in &keys {
        let announcement = Announcement::new::<Ed25519>(net.node(key).path().to_vec());
        assert!(announcement.is_ok(), "{key:?} holds an unsigned walk");
        if let Some(parent) = net.node(key).parent() {
            let path = net.node(key).path();
            let (head, tail) = path.split_at(path.len() - 1);
            assert_eq!(head, net.node(parent).path());
            assert_eq!(tail[0].key, key);
        }
    }
}

#[test]
fn every_node_can_find_and_reach_every_other() {
    let (mut net, keys) = ring_with_a_tail();

    for &src in &keys {
        for &dst in &keys {
            if src == dst {
                continue;
            }
            net.send(src, dst, b"signed, sealed");
            assert_eq!(
                net.node_mut(dst).take_delivered(),
                vec![Packet {
                    src,
                    dst,
                    payload: b"signed, sealed".to_vec(),
                }],
                "{src:?} could not reach {dst:?}"
            );
        }
    }
}

#[test]
fn a_position_nobody_signed_for_is_refused() {
    let (net, keys) = ring_with_a_tail();
    // The largest key is the one node that certainly is not the root, so it
    // certainly sits below somebody and has a link whose price can be lied
    // about. Which node that is depends on keys nobody chose.
    let victim = *keys.iter().max().expect("the network is not empty");
    assert!(net.node(victim).parent().is_some());

    // Take its genuine announcement and rub out the price of its last link,
    // the cheapest lie available: it would put the author nearer the root than
    // it has any right to be, and pull traffic through it.
    let mut cheaper = net.node(victim).path().to_vec();
    let last = cheaper.len() - 1;
    assert_eq!(cheaper[last].cost, 5, "there is something to lie about");
    cheaper[last].cost = 1;
    assert_eq!(
        Announcement::new::<Ed25519>(cheaper),
        Err(MalformedAnnouncement::BadSignature)
    );

    // And the forgery that matters most, since a search's answer is the one
    // place a node speaks about somebody else: Mallory builds a walk of her
    // own and writes the victim's name on the end of it.
    let mallory = Ed25519::from_seed([200; 32]);
    let mut impersonated = Announcement::root_of(&mallory, 0)
        .extend(&Ed25519::from_seed([201; 32]), Cost::UNIT, 0)
        .expect("distinct keys")
        .path()
        .to_vec();
    impersonated[1].key = victim;
    assert_eq!(
        Announcement::new::<Ed25519>(impersonated),
        Err(MalformedAnnouncement::BadSignature),
        "a hop is only worth what the node it names signed for"
    );
}

/// A signer that is not ed25519 and is not cryptography either: a signature
/// under it is a fixed pattern anybody can write down.
///
/// It exists for the one test below, which needs a walk that is properly signed
/// under *some* scheme and worthless under this network's.
struct OtherScheme(PublicKey);

impl Signer for OtherScheme {
    fn public_key(&self) -> PublicKey {
        self.0
    }

    fn sign(&self, _message: &[u8]) -> Signature {
        Signature::new([0xa5; SIGNATURE_LEN])
    }

    fn verify(_key: PublicKey, _message: &[u8], signature: &Signature) -> bool {
        signature.as_bytes() == &[0xa5; SIGNATURE_LEN]
    }
}

#[test]
fn a_walk_signed_under_another_scheme_does_not_check_out() {
    // The other scheme will happily produce a walk, and every node in an
    // ed25519 network will refuse it. Which algorithm is in use is not a
    // detail the protocol leaves open at runtime.
    let pretender = OtherScheme(Ed25519::from_seed([1; 32]).key());
    let announcement = Announcement::root_of(&pretender, 0);

    assert!(announcement.verify::<OtherScheme>());
    assert!(!announcement.verify::<Ed25519>());
}
