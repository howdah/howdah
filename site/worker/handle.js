// cfg.howdah.org: the config editor's fetch service, as a pure function of the
// request. `GET /v1/<payload>` decodes the payload the editor produced
// (site/config-editor/editor.js), validates the TOML with the real core (the
// same wasm the page runs), and returns it as text/plain. Nothing is stored
// and nothing about a request is logged.
//
// `handle(request, exports, version)` takes the instantiated wasm exports so
// tests can drive it in Node; index.js supplies them in the Worker.
import H from '../demo/howdah-wasm.js';
import E from '../config-editor/editor.js';

const TEXT = 'text/plain; charset=utf-8';
const PAYLOAD_RE = /^\/v1\/([A-Za-z0-9_.-]+)$/;

const ABOUT = [
  'cfg.howdah.org serves Howdah configuration files built at https://howdah.org/config/.',
  '',
  'GET /v1/<payload> returns the howdah.toml encoded in <payload>, after the',
  'Howdah core itself has re-validated it; a config the extension would reject is',
  'never served. The URL carries the whole file. Nothing is stored or logged.',
  '',
].join('\n');

function text(status, body, headers) {
  return new Response(body, { status, headers: { 'content-type': TEXT, 'cache-control': 'no-store', ...headers } });
}

export async function handle(request, exports, version) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return text(405, 'Method not allowed\n', { allow: 'GET, HEAD' });
  }
  const url = new URL(request.url);
  const head = request.method === 'HEAD';
  if (url.pathname === '/') return text(200, head ? null : ABOUT);
  const m = PAYLOAD_RE.exec(url.pathname);
  if (!m) return text(404, 'Not found\n');
  const payload = m[1];
  if (payload.length > E.PAYLOAD_MAX) return text(413, 'Payload too large: the URL may carry at most ' + E.PAYLOAD_MAX + ' characters.\n');

  let toml;
  try {
    toml = await E.decodePayload(payload);
  } catch (e) {
    const msg = e && e.message || '';
    if (/too long|too large/.test(msg)) return text(413, 'Payload too large.\n');
    return text(422, 'Malformed payload: ' + msg + '\n');
  }
  const v = H.validateConfigWith(exports, toml);
  if (!v.ok) return text(422, 'The Howdah core rejects this config, so it is not served: ' + v.error + '\n');

  return new Response(head ? null : toml, {
    status: 200,
    headers: {
      'content-type': TEXT,
      'content-disposition': 'inline; filename="howdah.toml"',
      'cache-control': 'public, max-age=31536000, immutable',
      'x-howdah-validated': version,
    },
  });
}
