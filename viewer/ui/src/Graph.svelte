<script>
  // The network drawn as a graph: nodes on a circle, links between them.
  // Tree links (a node and its parent) are solid, every other link is dashed,
  // and each carries the cost of crossing it.
  let { nodes, links, selected, flight, search, summaryBits, onpick } = $props();

  const WIDTH = 760;
  const HEIGHT = 520;

  const positions = $derived.by(() => {
    const at = new Map();
    const count = nodes.length;
    const radius = Math.min(WIDTH, HEIGHT) / 2 - 70;
    nodes.forEach((node, index) => {
      if (count === 1) {
        at.set(node.id, { x: WIDTH / 2, y: HEIGHT / 2 });
        return;
      }
      const angle = -Math.PI / 2 + (2 * Math.PI * index) / count;
      at.set(node.id, {
        x: WIDTH / 2 + radius * Math.cos(angle),
        y: HEIGHT / 2 + radius * Math.sin(angle),
      });
    });
    return at;
  });

  // Links the packet currently in flight is travelling over.
  const lit = $derived.by(() => {
    const edges = new Set();
    const route = flight?.route ?? [];
    for (let i = 0; i + 1 < route.length; i++) {
      const [a, b] = [route[i], route[i + 1]].sort((x, y) => x - y);
      edges.add(`${a}-${b}`);
    }
    return edges;
  });

  // The nodes the last search passed through, ringed until something else
  // happens. What matters is as much which ones are missing as which are not.
  const searched = $derived(new Set(search?.visited ?? []));

  let dot = $state(null);

  $effect(() => {
    const journey = flight;
    const at = positions;
    if (!journey || journey.route.length < 2) {
      dot = null;
      return;
    }

    const points = journey.route.map((id) => at.get(id)).filter(Boolean);
    if (points.length < 2) return;

    const hops = points.length - 1;
    const total = hops * 420;
    const started = performance.now();
    let cancelled = false;

    function frame(now) {
      if (cancelled) return;
      const progress = Math.min(1, (now - started) / total);
      const travelled = progress * hops;
      const leg = Math.min(hops - 1, Math.floor(travelled));
      const within = travelled - leg;
      dot = {
        x: points[leg].x + (points[leg + 1].x - points[leg].x) * within,
        y: points[leg].y + (points[leg + 1].y - points[leg].y) * within,
        delivered: journey.delivered,
      };
      if (progress < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);

    return () => {
      cancelled = true;
    };
  });
</script>

<svg viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="network graph">
  {#each links as link (link.a + '-' + link.b)}
    {@const from = positions.get(link.a)}
    {@const to = positions.get(link.b)}
    {#if from && to}
      <line
        x1={from.x} y1={from.y} x2={to.x} y2={to.y}
        class:tree={link.tree}
        class:lit={lit.has(`${link.a}-${link.b}`)}
      >
        <title>{link.tree
          ? `${link.a}\u2192${link.b} summary ${link.summary[0]}/${summaryBits} bits, ${link.b}\u2192${link.a} ${link.summary[1]}/${summaryBits}`
          : 'not a tree link, so no summary crosses it'}</title>
      </line>
    {/if}
  {/each}

  <!-- Costs go on afterwards so no line is drawn across a label. -->
  {#each links as link (link.a + '-' + link.b)}
    {@const from = positions.get(link.a)}
    {@const to = positions.get(link.b)}
    {#if from && to}
      <text
        class="cost"
        class:tree={link.tree}
        x={(from.x + to.x) / 2}
        y={(from.y + to.y) / 2}
        dy="0.32em"
      >{link.cost}</text>
    {/if}
  {/each}

  {#each nodes as node (node.id)}
    {@const at = positions.get(node.id)}
    {#if at}
      <g
        class="node"
        class:selected={selected.includes(node.id)}
        class:searched={searched.has(node.id)}
        class:root={node.parent === null}
        transform="translate({at.x} {at.y})"
        onclick={() => onpick(node.id)}
        onkeydown={(event) => event.key === 'Enter' && onpick(node.id)}
        role="button"
        tabindex="0"
      >
        <title>path {node.path.join(' → ')}, holds {node.knows} positions</title>
        {#if searched.has(node.id)}<circle class="ring" r="31" />{/if}
        <circle r="25" />
        <text dy="0.35em">{node.id}</text>
        {#if selected[0] === node.id}<text class="tag" dy="-2.4em">from</text>{/if}
        {#if selected[1] === node.id}<text class="tag" dy="-2.4em">to</text>{/if}
      </g>
    {/if}
  {/each}

  {#if dot}
    <circle class="packet" class:dropped={!dot.delivered} cx={dot.x} cy={dot.y} r="8" />
  {/if}
</svg>

<style>
  svg {
    width: 100%;
    height: auto;
    display: block;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
  }

  line {
    stroke: var(--line);
    stroke-width: 2;
    stroke-dasharray: 5 5;
  }

  line.tree {
    stroke: #46506080;
    stroke-width: 3.5;
    stroke-dasharray: none;
  }

  line.lit {
    stroke: var(--accent);
  }

  text.cost {
    fill: var(--dim);
    font: 500 12px ui-monospace, Menlo, monospace;
    /* A halo, so a cost sitting on its own link stays readable. */
    stroke: var(--panel);
    stroke-width: 4;
    paint-order: stroke;
  }

  text.cost.tree { fill: var(--text); }

  .node circle {
    fill: #262b34;
    stroke: #3a414e;
    stroke-width: 2;
  }

  .node circle.ring {
    fill: none;
    stroke: var(--good);
    stroke-width: 2;
    stroke-dasharray: 4 4;
  }

  .node { cursor: pointer; }
  .node:hover circle { stroke: var(--accent); }
  .node.root circle { stroke: var(--root); stroke-width: 3; }
  .node.selected circle { fill: #2f3a4d; stroke: var(--accent); stroke-width: 3; }

  text {
    fill: var(--text);
    text-anchor: middle;
    font: 600 15px ui-monospace, Menlo, monospace;
    user-select: none;
  }

  text.tag {
    fill: var(--accent);
    font-size: 11px;
    font-weight: 500;
  }

  .packet {
    fill: var(--good);
    stroke: #14161a;
    stroke-width: 2;
  }

  .packet.dropped { fill: var(--bad); }
</style>
