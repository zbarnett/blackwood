//! What a malicious node can and cannot do to a network of honest ones.
//!
//! Every attack here worked before positions were bargains and answers were
//! evidence. What each test now pins down is either that it cannot be built at
//! all, or that the network shrugs it off — and, where something is still
//! open, exactly how far it gets.

use std::collections::{BTreeMap, VecDeque};

use blackwood_ed25519::Ed25519;
use routing_core::{
    Announcement, Consent, Cost, Envelope, Hop, Message, NONCE_LEN, Node, Nonce, PublicKey,
    SIGNATURE_LEN, Signature, Timing,
};

struct InFlight {
    to: PublicKey,
    from: PublicKey,
    message: Message,
}

struct Network {
    nodes: BTreeMap<PublicKey, Node<Ed25519>>,
    queue: VecDeque<InFlight>,
    nonces: u64,
    /// Every answer seen crossing the network, for an attacker to record and
    /// replay later.
    answers: Vec<Message>,
}

impl Network {
    fn new(count: u8) -> (Self, Vec<PublicKey>) {
        let mut net = Self {
            nodes: BTreeMap::new(),
            queue: VecDeque::new(),
            nonces: 0,
            answers: Vec::new(),
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

    fn enqueue(&mut self, from: PublicKey, outbound: Vec<Envelope>) {
        for envelope in outbound {
            self.queue.push_back(InFlight {
                to: envelope.to,
                from,
                message: envelope.message,
            });
        }
    }

    fn run(&mut self) {
        for step in 0.. {
            assert!(step < 50_000, "network did not settle");
            let Some(in_flight) = self.queue.pop_front() else {
                return;
            };
            if matches!(in_flight.message, Message::Found(_)) {
                self.answers.push(in_flight.message.clone());
            }
            let outbound =
                self.node_mut(in_flight.to)
                    .handle(0, in_flight.from, in_flight.message);
            self.enqueue(in_flight.to, outbound);
        }
    }

    fn nonce(&mut self) -> Nonce {
        self.nonces += 1;
        let mut bytes = [0; NONCE_LEN];
        bytes[..8].copy_from_slice(&self.nonces.to_be_bytes());
        Nonce::new(bytes)
    }

    /// Try to get one packet from `src` to `dst`, reporting whether it landed.
    fn try_send(&mut self, src: PublicKey, dst: PublicKey, payload: &[u8]) -> bool {
        let nonce = self.nonce();
        let lookup = self.node_mut(src).lookup(0, dst, nonce);
        self.enqueue(src, lookup);
        self.run();
        let Ok(outbound) = self.node_mut(src).send(dst, payload.to_vec()) else {
            return false;
        };
        self.enqueue(src, outbound);
        self.run();
        !self.node_mut(dst).take_delivered().is_empty()
    }

    fn evictions(&mut self) -> Vec<(PublicKey, routing_core::Fault)> {
        let keys: Vec<_> = self.nodes.keys().copied().collect();
        keys.iter()
            .flat_map(|&key| {
                self.node_mut(key)
                    .take_evicted()
                    .into_iter()
                    .map(move |eviction| (key, eviction.fault))
            })
            .collect()
    }
}

/// A line of `count` honest nodes.
fn line(count: u8) -> (Network, Vec<PublicKey>) {
    let (mut net, keys) = Network::new(count);
    for i in 0..(count as usize - 1) {
        net.link(keys[i], keys[i + 1], Cost::UNIT);
    }
    net.run();
    (net, keys)
}

/// The attacker, and the node it peers with — always the one furthest from the
/// root, since that is where the lie buys the most.
fn attacker_at_the_edge(net: &mut Network, keys: &[PublicKey]) -> (Ed25519, PublicKey) {
    let mallory = Ed25519::from_seed([200; 32]);
    let victim = *keys
        .iter()
        .max_by_key(|&&k| net.node(k).depth())
        .expect("the network is not empty");
    net.nodes.insert(
        mallory.key(),
        Node::new(0, Ed25519::from_seed([200; 32]), Timing::MILLISECONDS),
    );
    net.link(victim, mallory.key(), Cost::UNIT);
    net.run();
    (mallory, victim)
}

#[test]
fn the_splice_that_captured_the_network_cannot_be_built() {
    // The attack that used to work: take the root's own genuine announcement,
    // which any lookup answer hands out, and sign yourself onto the end of it.
    // Every signature above is real. Only the last hop is new, and the
    // attacker is entitled to sign that.
    let (mut net, keys) = line(6);
    let root = net.node(keys[0]).root();
    let (mallory, _) = attacker_at_the_edge(&mut net, &keys);

    let stolen = Announcement::new::<Ed25519>(net.node(root).path().to_vec()).expect("genuine");

    // Nothing she can sign is the root agreeing to carry her.
    assert_eq!(
        stolen.extend(&mallory, &Consent::issue(&mallory, mallory.key()), 1),
        None,
        "her own signature is not the root's"
    );

    // Nor is a consent the root really did issue, to somebody else: it names
    // both ends, so it cannot be handed on.
    let real_but_elsewhere = net
        .node(keys[1])
        .consent_from(root)
        .or_else(|| net.node(keys[0]).consent_from(root));
    if let Some(consent) = real_but_elsewhere {
        assert_eq!(consent.parent(), root);
        assert_ne!(consent.child(), mallory.key());
        assert_eq!(
            stolen.extend(&mallory, &consent, 1),
            None,
            "the root agreed to carry somebody, and it was not her"
        );
    }

    // And the position she is actually offered is one link below the node
    // that agreed to have her, not one of her choosing.
    let hers = net.node(mallory.key()).path();
    assert_eq!(hers.len(), net.node(root).path().len() + 5);
    assert!(hers.len() > 1, "she is welcome somewhere, at the far end");
}

#[test]
fn a_forged_walk_cannot_even_be_named() {
    // The wire seam refuses it too. There is no way into `Announcement` from
    // outside this crate that does not check every hop and every consent, so
    // a forged walk cannot be built, let alone sent.
    let mallory = Ed25519::from_seed([200; 32]);
    let victim = Ed25519::from_seed([1; 32]);

    let mut path = Announcement::root_of(&victim, 0).path().to_vec();
    path.push(Hop {
        key: mallory.key(),
        seq: 1,
        consent: Some(Signature::new([0; SIGNATURE_LEN])),
        signature: Signature::new([0; SIGNATURE_LEN]),
    });
    assert!(Announcement::new::<Ed25519>(path).is_err());

    // Nor can a consent be conjured for a parent that never gave one.
    assert_eq!(
        Consent::new::<Ed25519>(
            victim.key(),
            mallory.key(),
            Signature::new([0; SIGNATURE_LEN]),
        ),
        None,
    );
}

#[test]
fn the_network_stays_whole_with_an_attacker_on_the_edge() {
    // Before, one message from here made two of six nodes unreachable from
    // the root. Now the attacker is just a leaf.
    let (mut net, keys) = line(6);
    let root = net.node(keys[0]).root();
    let (mallory, _) = attacker_at_the_edge(&mut net, &keys);

    for &key in &keys {
        if key == root {
            continue;
        }
        assert!(
            net.try_send(root, key, b"hello"),
            "{key:?} became unreachable"
        );
    }
    assert!(net.try_send(root, mallory.key(), b"hello"), "she is reachable too");
    assert!(net.evictions().is_empty(), "and nobody misbehaved");
}

#[test]
fn a_recorded_answer_is_not_an_answer() {
    // An announcement is as valid a year later as the day it was signed, so
    // an attacker that keeps one can offer it as an answer forever. What it
    // cannot keep is the asker's nonce.
    let (mut net, keys) = line(5);
    let (asker, target) = (keys[0], keys[4]);

    net.answers.clear();
    assert!(net.try_send(asker, target, b"first"), "the honest way round");
    let recorded = net
        .answers
        .iter()
        .rev()
        .find_map(|message| match message {
            // The one that was on its last hop home, so its trail is just
            // the asker and its proof is over the asker's own nonce.
            Message::Found(found) if found.trail == vec![asker] => Some(found.clone()),
            _ => None,
        })
        .expect("an answer came home");
    assert!(recorded.verify::<Ed25519>(), "and it was a good one");

    // Let it go stale, then play it back at the node that once asked.
    net.node_mut(asker).tick(Timing::MILLISECONDS.expiry);
    assert!(
        !net.node(asker).known().any(|known| known == target),
        "the position expired"
    );

    let neighbour = keys[1];
    let mut replay = recorded.clone();
    replay.trail = vec![asker];
    net.node_mut(asker)
        .handle(0, neighbour, Message::Found(replay));

    assert!(
        !net.node(asker).known().any(|known| known == target),
        "a recording answers no question that is still open"
    );

    // Even while a search really is outstanding, it is a different one.
    let nonce = net.nonce();
    net.node_mut(asker).lookup(0, target, nonce);
    let mut replay = recorded;
    replay.trail = vec![asker];
    net.node_mut(asker)
        .handle(0, neighbour, Message::Found(replay));
    assert!(
        !net.node(asker).known().any(|known| known == target),
        "the nonce is the half of an answer that cannot be recorded"
    );
}

#[test]
fn a_peer_can_still_declare_itself_a_tree_neighbour() {
    // Open, and left open on purpose: summaries are unsigned, so a peer that
    // sits below this node legitimately can still claim anything it likes
    // lies beyond it. What consent removed is its ability to sit anywhere it
    // was not invited — not its ability to lie about what it can see.
    let (mut net, keys) = line(6);
    let (mallory, victim) = attacker_at_the_edge(&mut net, &keys);

    assert_eq!(
        net.node(mallory.key()).parent(),
        Some(victim),
        "a real position below a real host"
    );
    assert!(
        net.node(victim).summary_for(mallory.key()).is_some(),
        "and so a tree link, which is what carries summaries"
    );
}

#[test]
fn an_unbounded_path_is_still_expensive_to_refuse() {
    // Open. Every hop of an arriving announcement is checked, and consent
    // doubled the work; nothing bounds how many hops arrive. The repeated-key
    // scan before it is quadratic, which is what the shape below is.
    let bogus = Hop {
        key: PublicKey::new([7; 32]),
        seq: 0,
        consent: Some(Signature::new([0; SIGNATURE_LEN])),
        signature: Signature::new([0; SIGNATURE_LEN]),
    };
    for n in [1_000usize, 10_000] {
        let mut path = vec![Hop {
            consent: None,
            ..bogus
        }];
        path.extend((0..n).map(|i| {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_be_bytes());
            Hop {
                key: PublicKey::new(key),
                ..bogus
            }
        }));
        let started = std::time::Instant::now();
        let refused = Announcement::new::<Ed25519>(path);
        println!("{n} hops: refused in {:?} ({:?})", started.elapsed(), refused.err());
    }
}
