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
| Look up | Asks the network where the second node sits, and rings every node the search passed through |
| Send packet | Sends one packet from the first selection to the second and animates its route, looking the destination up first if it has to |
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

No node here knows the network. The *knows* column counts the positions a node
holds, which are its own peers and whoever it has looked up lately — never
everybody. Press **Look up** and watch which nodes the search touches: `6` hangs
off `2` on a branch of its own, so a search from `1` for `5` goes straight past
it, because what `6` told `2` about its side of their link says `5` is not down
there. Hovering a tree link shows how full the summary crossing it is, in bits.

The clock only moves when you move it, which makes soft state visible. Remove a
node and the count stays put — its neighbours re-parent at once, but anyone
holding a looked-up position for it goes on believing — then press **+5s** and
watch the stale positions expire.

## Shape of it

| File | Role |
| --- | --- |
| `src/sim.rs` | Holds the nodes, the queue of messages in flight, and the clock |
| `src/http.rs` | Enough HTTP to talk to a browser |
| `src/main.rs` | Maps requests onto simulator commands |
| `ui/` | Svelte app: the graph, the controls, and the node table |
