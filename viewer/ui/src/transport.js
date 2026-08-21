// Where the simulator lives.
//
// Either way it is the same Rust: served over HTTP by the local viewer binary,
// or compiled to WebAssembly and called directly when the page is static, as it
// is on GitHub Pages. Both answer with identical JSON, so nothing downstream
// needs to know which one it got.

async function overHttp() {
  const response = await fetch('api/state');
  if (!response.ok) throw new Error(`no local viewer (${response.status})`);
  const body = await response.json();
  if (!body?.ok) throw new Error('not a viewer');

  return {
    kind: 'server',
    live: true,
    async call(command, params = {}) {
      const query = new URLSearchParams(params).toString();
      const response = await fetch(`api/${command}${query ? `?${query}` : ''}`, {
        method: command === 'state' ? 'GET' : 'POST',
      });
      return response.json();
    },
  };
}

async function overWasm() {
  const response = await fetch(new URL('blackwood.wasm', document.baseURI));
  if (!response.ok) throw new Error(`no simulator (${response.status})`);
  // Plain instantiate rather than instantiateStreaming, so the MIME type the
  // host happens to serve .wasm with cannot break the page.
  const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {});
  const exports = instance.exports;
  const decoder = new TextDecoder();

  // A command leaves its JSON in the module's memory for us to read back.
  const readBack = () =>
    JSON.parse(
      decoder.decode(new Uint8Array(exports.memory.buffer, exports.out_ptr(), exports.out_len())),
    );

  const commands = {
    state: () => exports.state(),
    'node/add': () => exports.node_add(),
    'node/remove': (p) => exports.node_remove(Number(p.id)),
    'link/add': (p) => exports.link_add(Number(p.a), Number(p.b), Number(p.cost)),
    'link/cost': (p) => exports.link_cost(Number(p.a), Number(p.b), Number(p.cost)),
    'link/remove': (p) => exports.link_remove(Number(p.a), Number(p.b)),
    advance: (p) => exports.advance(Number(p.by)),
    lookup: (p) => exports.lookup(Number(p.from), Number(p.to)),
    forge: (p) => exports.forge(Number(p.id)),
    send: (p) => exports.send(Number(p.from), Number(p.to)),
    reset: () => exports.reset(),
  };

  return {
    kind: 'wasm',
    live: false,
    async call(command, params = {}) {
      const run = commands[command];
      if (!run) return { ok: false, error: `unknown command ${command}` };
      run(params);
      return readBack();
    },
  };
}

/// Prefers a local viewer if one is serving this page, and falls back to
/// running the simulator in the browser.
export async function connect() {
  try {
    return await overHttp();
  } catch {
    return await overWasm();
  }
}
