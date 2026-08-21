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
| Link / Unlink | Brings a link between the two selected nodes up or down |
| Send packet | Sends one packet from the first selection to the second and animates its route |
| +1s / +5s | Moves the simulated clock forward, letting nodes reissue and expire announcements |
| Reset | Rebuilds the starting network |

The root is ringed in gold, links to a node's parent are solid, and every other
link is dashed. After each change the simulator runs gossip to quiescence, so
what you see is the settled tree.

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
