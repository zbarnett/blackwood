<script>
  import Graph from './Graph.svelte';
  import { connect } from './transport.js';

  let transport = $state(null);
  let state = $state(null);
  let error = $state(null);
  let selected = $state([]);
  let flight = $state(null);
  let busy = $state(false);

  const from = $derived(selected[0]);
  const to = $derived(selected[1]);
  const nodes = $derived(state?.nodes ?? []);
  const links = $derived(state?.links ?? []);
  const clock = $derived(((state?.now ?? 0) / 1000).toFixed(1));

  async function call(command, params = {}) {
    if (!transport) return null;
    busy = true;
    try {
      const body = await transport.call(command, params);
      state = body.state;
      error = body.ok ? null : body.error;
      return body;
    } catch (failure) {
      error = String(failure);
      return null;
    } finally {
      busy = false;
    }
  }

  function pick(id) {
    if (selected.includes(id)) selected = selected.filter((held) => held !== id);
    else selected = [...selected, id].slice(-2);
  }

  async function send() {
    const body = await call('send', { from, to });
    if (body?.ok) flight = { route: body.route, delivered: body.delivered, at: Date.now() };
  }

  async function removeNode() {
    await call('node/remove', { id: from });
    selected = selected.filter((held) => held !== from);
  }

  // A served network can also change from elsewhere, so keep asking it for a
  // new version. A network running in this page can only change from here.
  $effect(() => {
    if (!transport?.live) return;
    const timer = setInterval(async () => {
      if (busy) return;
      const body = await transport.call('state').catch(() => null);
      if (body && body.state.version !== state?.version) state = body.state;
    }, 700);
    return () => clearInterval(timer);
  });

  connect().then(async (connected) => {
    transport = connected;
    await call('state');
  }, (failure) => {
    error = `could not reach a simulator: ${failure}`;
  });
</script>

<header>
  <h1>blackwood</h1>
  <span class="dim">a simulated network, routed by tree embedding</span>
  <span class="badges">
    {#if transport}
      <span class="badge" title={transport.kind === 'wasm'
        ? 'the Rust simulator is compiled to WebAssembly and running in this page'
        : 'the Rust simulator is running behind a local server'}>
        {transport.kind === 'wasm' ? 'wasm' : 'local server'}
      </span>
    {/if}
    <span class="badge clock" title="the simulated clock — nothing expires or is reissued until you move it">
      t {clock}s
    </span>
  </span>
</header>

<main>
  <section>
    <div class="controls">
      <button onclick={() => call('node/add')}>Add node</button>
      <button disabled={from === undefined} onclick={removeNode}>
        Remove {from ?? 'node'}
      </button>
      <span class="divider"></span>
      <button disabled={to === undefined} onclick={() => call('link/add', { a: from, b: to })}>
        Link
      </button>
      <button disabled={to === undefined} onclick={() => call('link/remove', { a: from, b: to })}>
        Unlink
      </button>
      <span class="divider"></span>
      <button class="primary" disabled={to === undefined} onclick={send}>
        Send packet
      </button>
      <span class="divider"></span>
      <button title="let one second of simulated time pass" onclick={() => call('advance', { by: 1000 })}>
        +1s
      </button>
      <button title="long enough for anything unreissued to expire" onclick={() => call('advance', { by: 5000 })}>
        +5s
      </button>
      <span class="divider"></span>
      <button onclick={() => { selected = []; flight = null; call('reset'); }}>Reset</button>
    </div>

    <p class="hint">
      {#if to !== undefined}
        <code>{from}</code> and <code>{to}</code> selected — actions run from
        <code>{from}</code> to <code>{to}</code>.
      {:else if from !== undefined}
        <code>{from}</code> selected. Pick a second node to link or send.
      {:else}
        Click a node to select it, and a second for the other end.
      {/if}
    </p>

    {#if error}<p class="error">{error}</p>{/if}

    <Graph {nodes} {links} {selected} {flight} onpick={pick} />

    <p class="legend">
      <span class="swatch root"></span> root
      <span class="swatch tree"></span> tree link
      <span class="swatch other"></span> other link
    </p>
  </section>

  <aside>
    <h2>Nodes</h2>
    <table>
      <thead>
        <tr><th>id</th><th>root</th><th>parent</th><th>path</th><th>peers</th><th title="other nodes it holds an announcement for">knows</th></tr>
      </thead>
      <tbody>
        {#each nodes as node (node.id)}
          <tr class:selected={selected.includes(node.id)} onclick={() => pick(node.id)}>
            <td>{node.id}</td>
            <td>{node.root}</td>
            <td>{node.parent ?? '—'}</td>
            <td class="mono">{node.path.join('·')}</td>
            <td class="mono">{node.peers.join(' ') || '—'}</td>
            <td class="mono">{node.knows}</td>
          </tr>
        {/each}
      </tbody>
    </table>

    <h2>Links <span class="dim">{links.length}</span></h2>
    <p class="links mono">
      {#each links as link (link.a + '-' + link.b)}
        <span class="link" class:tree={link.tree}>{link.a}–{link.b}</span>
      {:else}
        <span class="dim">none</span>
      {/each}
    </p>

    <h2>Log</h2>
    <ol class="log mono">
      {#each state?.log ?? [] as line, index (index)}
        <li>{line}</li>
      {/each}
    </ol>

    <p class="caveat">
      Announcements are soft state: a node reissues its own every second and
      forgets any it has not heard again within three. Nothing here moves the
      clock but you. Remove a node and its neighbours re-parent at once, but the
      rest of the network goes on remembering where it sat — press
      <code>+5s</code> to watch that memory expire.
    </p>
  </aside>
</main>

<style>
  header {
    display: flex;
    align-items: baseline;
    gap: 12px;
    padding: 18px 22px 6px;
  }

  h1 { margin: 0; font-size: 17px; letter-spacing: 0.02em; }
  h2 { margin: 18px 0 7px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--dim); }
  .dim { color: var(--dim); font-size: 13px; }

  .badges { margin-left: auto; display: flex; gap: 10px; }

  .badge {
    padding: 2px 9px;
    border: 1px solid var(--line);
    border-radius: 20px;
    color: var(--dim);
    font-family: ui-monospace, Menlo, monospace;
    font-size: 11px;
  }

  .badge.clock { min-width: 58px; text-align: center; }

  main {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: 20px;
    padding: 10px 22px 26px;
    align-items: start;
  }

  @media (max-width: 900px) {
    main { grid-template-columns: minmax(0, 1fr); }
  }

  .controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .controls .primary { border-color: var(--accent); }
  .divider { width: 1px; height: 20px; background: var(--line); }

  .hint { color: var(--dim); font-size: 13px; margin: 10px 0; min-height: 20px; }
  .error { color: var(--bad); margin: 8px 0; }

  .legend { display: flex; align-items: center; gap: 7px; color: var(--dim); font-size: 12px; margin: 10px 2px; }
  .legend .swatch { width: 15px; height: 3px; border-radius: 2px; background: var(--line); margin-left: 12px; }
  .legend .swatch:first-child { margin-left: 0; }
  .legend .swatch.root { background: var(--root); height: 10px; width: 10px; border-radius: 50%; }
  .legend .swatch.tree { background: #465060; height: 4px; }

  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; color: var(--dim); font-weight: 500; padding: 3px 6px; }
  td { padding: 4px 6px; border-top: 1px solid var(--line); }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: #ffffff08; }
  tbody tr.selected { background: #2f3a4d80; }

  .links { display: flex; flex-wrap: wrap; gap: 6px; margin: 0; }
  .link { padding: 2px 7px; border: 1px solid var(--line); border-radius: 20px; color: var(--dim); }
  .link.tree { border-color: #46506080; color: var(--text); }

  .log { list-style: none; padding: 0; margin: 0; max-height: 210px; overflow-y: auto; }
  .log li { padding: 3px 0; border-top: 1px solid var(--line); color: var(--dim); }
  .log li:first-child { color: var(--text); }

  .caveat { color: var(--dim); font-size: 11.5px; line-height: 1.5; margin-top: 18px; border-top: 1px solid var(--line); padding-top: 12px; }
</style>
