// Install picker: runs the built page's own picker script against a small DOM
// stub and checks the exact commands it prints for each OS / panel choice, and
// that every row of packaging/layouts.tsv (package name + repository) is what
// the picker tells people to install. Builds the site once if
// dist/install/index.html is older than the page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';
import { ensureBuilt, site } from './build-site.mjs';

const out = resolve(site, 'dist/install/index.html');
ensureBuilt(out, ['src/pages/install.astro', 'src/lib/site.ts'].map((p) => resolve(site, p)));
const html = existsSync(out) ? readFileSync(out, 'utf8') : '';
const script = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
  .map((m) => m[1]).find((s) => s.includes('result-steps')) ?? '';

// Run the picker with the given choices; returns the rendered command text and
// which conditional fieldsets / notes are visible.
function pick(choices) {
  const state = { os: 'debian', src_deb: 'sury', xenial: false, minor: '8.1', sapi: 'fpm', panel_os: 'el', ...choices };
  const node = () => ({ hidden: false, innerHTML: '', textContent: '' });
  const nodes = { 'result-steps': node(), 'cgi-note': node(), 'distro-note': node(), 'layout-note': node(), 'docker-note': node() };
  const fieldsets = [...html.matchAll(/<fieldset data-when-os="([^"]+)"/g)]
    .map((m) => ({ when: m[1], hidden: false, getAttribute: () => m[1] }));
  let onChange = null;
  const form = {
    elements: new Proxy({}, { get: (_, k) => (k in state ? { value: state[k], checked: !!state[k] } : undefined) }),
    querySelectorAll: () => fieldsets,
    addEventListener: (_, fn) => { onChange = fn; },
  };
  const document = {
    getElementById: (id) => (id === 'picker' ? form : nodes[id]),
    querySelector: () => null,
    querySelectorAll: () => [],
  };
  vm.runInNewContext(script, { document });
  assert.equal(typeof onChange, 'function', 'picker registered its change handler');
  const text = nodes['result-steps'].innerHTML.replace(/<[^>]+>/g, '\n')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  const shown = fieldsets.filter((f) => !f.hidden).map((f) => f.when);
  return { text, shown, layoutNote: !nodes['layout-note'].hidden, distroNote: !nodes['distro-note'].hidden, dockerNote: !nodes['docker-note'].hidden };
}
const VERSION = readFileSync(resolve(site, 'src/lib/site.ts'), 'utf8').match(/VERSION = '([^']+)'/)[1];
const has = (t, s) => assert.ok(t.includes(s), `missing: ${s}\n--- got:\n${t}`);

test('the install page is built with the picker script', () => {
  assert.ok(existsSync(out), 'dist/install/index.html missing');
  assert.ok(script.length > 0, 'picker script not found');
});

test('the OS step offers cPanel, Plesk, CloudLinux, distribution EL PHP and Docker', () => {
  for (const v of ['debian', 'rhel', 'el', 'cpanel', 'plesk', 'cloudlinux', 'docker', 'other']) {
    assert.match(html, new RegExp(`name="os" value="${v}"`), `os option ${v}`);
  }
  assert.match(html, /name="panel_os" value="el"/);
  assert.match(html, /name="panel_os" value="deb"/);
});

test('cPanel on EL: cPanel yum repo, dnf install, provisioning check', () => {
  const { text, shown, layoutNote } = pick({ os: 'cpanel', minor: '7.4' });
  has(text, 'baseurl=https://pkg.howdah.org/cpanel/yum');
  has(text, 'repo_gpgcheck=1');
  has(text, 'sudo dnf install ea-php74-php-howdah');
  has(text, 'not the EasyApache 4 screen');
  has(text, "only installs cPanel's own PHP packages");
  has(text, 'rpm -q ea-php74-php-howdah');
  has(text, '/opt/cpanel/ea-php74/root/usr/bin/php -m | grep -i howdah');
  has(text, 'sudo /scripts/restartsrv_apache_php_fpm');
  assert.ok(shown.includes('cpanel plesk'), 'server OS question is shown for cPanel');
  assert.ok(layoutNote, 'the new-repository note is shown');
});

test('cPanel on Ubuntu: cPanel apt repo', () => {
  const { text } = pick({ os: 'cpanel', panel_os: 'deb', minor: '8.1' });
  has(text, 'deb [signed-by=/etc/apt/keyrings/howdah.asc] https://pkg.howdah.org/cpanel/apt stable main');
  has(text, 'sudo apt-get install ea-php81-php-howdah');
  has(text, 'dpkg -s ea-php81-php-howdah');
});

test('Plesk: repo per OS family, reread, FPM restart', () => {
  let { text } = pick({ os: 'plesk', minor: '7.4' });
  has(text, 'baseurl=https://pkg.howdah.org/plesk/yum');
  has(text, 'sudo dnf install plesk-php74-howdah');
  has(text, '/opt/plesk/php/7.4/bin/php -m | grep -i howdah');
  has(text, 'sudo plesk bin php_handler --reread');
  has(text, 'sudo systemctl restart plesk-php74-fpm');
  ({ text } = pick({ os: 'plesk', panel_os: 'deb', minor: '7.4' }));
  has(text, 'https://pkg.howdah.org/plesk/apt stable main');
  has(text, 'sudo apt-get install plesk-php74-howdah');
});

test('CloudLinux: yum repo, install, PHP Selector enable, says it is not install-tested', () => {
  const { text, shown } = pick({ os: 'cloudlinux', minor: '7.4' });
  has(text, 'baseurl=https://pkg.howdah.org/cloudlinux/yum');
  has(text, 'sudo yum install alt-php74-howdah');
  has(text, 'sudo cagefsctl --setup-cl-selector');
  has(text, 'sudo selectorctl --version=7.4 --enable-extensions=howdah');
  has(text, 'Not install-tested');
  assert.ok(!shown.includes('cpanel plesk'), 'no server OS question for CloudLinux');
});

test('distribution EL PHP: one repository per minor, php-howdah', () => {
  const { text } = pick({ os: 'el', minor: '8.2' });
  has(text, 'baseurl=https://pkg.howdah.org/el/php8.2/yum');
  has(text, 'sudo dnf install php-howdah');
  has(text, 'php --ri howdah');
  has(text, 'sudo systemctl reload php-fpm');
});

test('Docker: the image, the one-line COPY --from, verify, and the not-yet-published note', () => {
  const img = `ghcr.io/howdah/howdah:${VERSION}-php8.3`;
  let { text, shown, dockerNote, layoutNote } = pick({ os: 'docker', minor: '8.3' });
  has(text, `FROM ${img}`);
  has(text, 'FROM php:8.3-fpm');
  has(text, `COPY --from=${img} /howdah/ /`);
  has(text, `docker run --rm ${img} php --ri howdah`);
  has(text, `${img} howdah-check web http://`);
  has(text, `${VERSION}-php8.3-alpine`);
  has(text, 'Not onto a');
  assert.ok(dockerNote, 'the Docker note (publishing status, build-it-yourself, guide link) is shown');
  assert.ok(!layoutNote, 'the panel repository note is not shown');
  assert.ok(!shown.includes('cpanel plesk') && !shown.includes('debian'), 'no OS-source question for Docker');
  // Apache: no ready image, the COPY --from line onto php:<minor>-apache
  ({ text } = pick({ os: 'docker', minor: '7.4', sapi: 'apache' }));
  has(text, 'FROM php:7.4-apache');
  has(text, `COPY --from=ghcr.io/howdah/howdah:${VERSION}-php7.4 /howdah/ /`);
  assert.ok(!text.includes(`FROM ghcr.io/howdah/howdah:${VERSION}-php7.4\n`), 'no fpm image offered for Apache');
  // 5.4 / 5.5: no image, honest fallback to the tarball
  for (const m of ['5.4', '5.5']) {
    ({ text } = pick({ os: 'docker', minor: m }));
    has(text, `No image for PHP ${m}`);
    assert.ok(!text.includes('ghcr.io/howdah/howdah'), `no image tag offered for ${m}`);
  }
  assert.ok(!pick({ os: 'debian' }).dockerNote, 'the Docker note is hidden for other choices');
  assert.match(html, /href="https:\/\/github.com\/howdah\/howdah\/blob\/main\/docs\/install-docker.md"/);
});

test('existing choices are unchanged', () => {
  let { text, distroNote } = pick({ os: 'debian', minor: '8.1' });
  has(text, 'https://pkg.howdah.org/apt stable main');
  has(text, 'sudo apt-get install php8.1-howdah');
  assert.ok(!distroNote);
  ({ distroNote } = pick({ os: 'debian', src_deb: 'distro' }));
  assert.ok(distroNote, 'distribution-PHP note shown');
  ({ text } = pick({ os: 'rhel', minor: '8.1' }));
  has(text, 'baseurl=https://pkg.howdah.org/yum');
  has(text, 'sudo yum install php81-howdah');
  ({ text } = pick({ os: 'other', minor: '7.4' }));
  has(text, './howdah-check detect');
  has(text, '/usr/local/php74/lib/php.conf.d/90-howdah.ini');
});

test('every packaging/layouts.tsv row is what the picker installs', () => {
  const tsv = readFileSync(resolve(site, '../packaging/layouts.tsv'), 'utf8');
  const osFor = { cpanel: 'cpanel', plesk: 'plesk', cloudlinux: 'cloudlinux', 'stock-rhel': 'el' };
  let rows = 0;
  for (const line of tsv.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const [layout, fmt, , pkg, , , , , , repo] = line.split('\t');
    rows += 1;
    assert.ok(osFor[layout], `layouts.tsv row ${layout} has a picker choice`);
    const sub = (s) => s.replaceAll('@XY@', '74').replaceAll('@MINOR@', '7.4');
    const { text } = pick({ os: osFor[layout], minor: '7.4', panel_os: fmt === 'deb' ? 'deb' : 'el' });
    has(text, `install ${sub(pkg)}`);
    has(text, fmt === 'deb'
      ? `https://pkg.howdah.org/${sub(repo)}/apt stable main`
      : `baseurl=https://pkg.howdah.org/${sub(repo)}/yum`);
  }
  assert.ok(rows >= 6, `layouts.tsv rows: ${rows}`);
});
