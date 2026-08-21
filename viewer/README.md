# blackwood viewer

A local visualiser for a simulated [`blackwood`](..) network: every node, every
link, and the route a packet takes across them.

The network being shown is entirely in memory. Nodes hand each other messages as
Rust values, exactly as they do in the core's tests; the routing core is used
unmodified and knows nothing about any of this. The one real socket belongs to
the HTTP server that draws the result in a browser.

## Running it

```sh
cd viewer/ui && npm install && npm run build   # once
cargo run -p blackwood-viewer                  # then open http://127.0.0.1:8080
```

`cargo run -p blackwood-viewer -- 9000` listens on another port.

While working on the UI itself, `npm run dev` serves it with hot reload and
forwards `/api` to the Rust viewer, which needs to be running alongside it.

## Controls

Click a node to select it, and a second node for the other end of an action.

| Control | Effect |
| --- | --- |
| Add node | Adds an isolated node |
| Remove node | Removes the first selected node and its links |
| cost | What a new link costs to cross, and what **Re-price** sets one to |
| Link / Unlink | Brings a link between the two selected nodes up or down |
| Re-price | Re-measures the link between them at the cost in the box |
| Send packet | Sends one packet from the first selection to the second and animates its route |
| +1s / +5s | Moves the simulated clock forward, letting nodes reissue and expire announcements |
| Reset | Rebuilds the starting network |

The root is ringed in gold, links to a node's parent are solid, every other link
is dashed, and each carries what it costs to cross. After each change the
simulator runs gossip to quiescence, so what you see is the settled tree.

The network opens with one link priced at 5 and the rest at 1, so the tree that
forms is the cheapest one rather than the shallowest: `4` reaches the root the
long way round, by way of `3`, rather than over its own link to `2`. Select
`2` and `4`, re-price that link to 1, and the tree snaps back — nothing crossed
the network to make it happen, since a link's cost is something each end
measures for itself. The *cost* column is what the walk from a node up to the
root costs, and the log prices each packet the same way.

The clock only moves when you move it, which makes soft state visible. The
*knows* column counts the announcements a node is holding: remove a node and
that count stays put — its neighbours re-parent at once, but the rest of the
network goes on remembering where it sat — then press **+5s** and watch the
counts drop as the stale announcements expire.

## Shape of it

| File | Role |
| --- | --- |
| `src/sim.rs` | Holds the nodes, the queue of messages in flight, and the clock |
| `src/http.rs` | Enough HTTP to talk to a browser |
| `src/main.rs` | Maps requests onto simulator commands |
| `ui/` | Svelte app: the graph, the controls, and the node table |
