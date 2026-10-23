# Howdah: an open-source WAF for PHP — design

**Status:** draft for owner review · 2026-10-22
**Name:** Howdah. A howdah is the armoured seat carried on an elephant's back, and PHP's mascot is an elephant.
**Domain:** howdah.org (being registered by the owner).

Markers: **(owner)** = decided by the project owner. **(Claude's call)** = a default proposed during design that the owner has not explicitly confirmed; the builder may revisit these with a reason.

---

## 1. Why this exists

- Sysadmins running PHP apps on their own servers have few good open-source WAF options. Most PHP-aware protection is paid, subscription-based, or WordPress-only. **(owner)**
- Running *inside* PHP lets us see what a network WAF (ModSecurity, cloud WAFs) cannot: how PHP actually parses the request, and later what the request turns into (SQL, shell commands, includes).
- **PHP2Shell (CVE-2026-109618 / CVE-2026-109619), patched 21 Oct 2026**, shows the gap. As reported by Rapid7, JFrog, Sansec and others:
  - A crafted `multipart/form-data` request exhausts PHP's memory while it parses upload part headers. Hundreds of tiny, empty file parts inside a body under the default 8 MB `post_max_size` can exceed the default 128 MB `memory_limit`. Corrupted state from that, plus request state reused after free on the same worker, gives unauthenticated RCE. CVSS v4 9.2.
  - The vulnerable code is in the session upload-progress handler (`php_session_rfc1867_callback`). It runs before any PHP script, and `session.upload_progress.enabled` is on by default from PHP 5.4 onward.
  - Fixes ship only for 8.2+ (8.5.12, 8.4.27, 8.3.36, 8.2.35). PHP 8.1 and older get no official patch. W3Techs (Aug 2026): PHP 7 = 29.4% and PHP 5 = 8.0% of PHP sites.
  - A WAF written in PHP (`auto_prepend_file`) cannot help: PHP parses uploads into `$_FILES` before any script runs. `opcache.preload` runs once at server start, never per request. Only a compiled extension can step in.
  - **Caveat:** these details come from secondary sources one day old that disagree on the root cause. The builder must verify them against the official advisories (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, php.net) before anything is built or claimed.

## 2. Who it's for

- **Primary:** sysadmins running PHP apps on servers they control (VPS, dedicated, in-house), who can install a PHP extension and edit `php.ini`. **(owner)**
- This explicitly includes people stuck on old PHP and old distros, e.g. PHP 7.3 on Ubuntu 16.04 **(owner)**, or the stock PHP 5.4 on CentOS 7.
- **Control-panel servers are in scope (Claude's call):** cPanel EA-PHP (`/opt/cpanel/ea-phpXY`), Plesk (`/opt/plesk/php/X.Y`) and CloudLinux alt-php (`/opt/alt/phpXY`), when they run PHP via FPM, `mod_php` or CGI. Panel setups that use LiteSpeed LSAPI wait for LSAPI support (§6).
- **Not in scope yet:** shared-hosting customers who can't install extensions, and Windows. **(Claude's call)**

## 3. What it is

A PHP extension written in Rust **(owner)**, loaded with one `extension=` line in `php.ini` **(owner)**, configured with a readable rules/config file next to `php.ini` **(Claude's call)**.

Protection is organised in four layers:

| Layer | What it covers | When |
|---|---|---|
| 1. Request parsing | Upload/multipart bombs (PHP2Shell; CVE-2023-0662 too-many-parts), boundary/parser differentials (CVE-2024-8925), input-variable floods and hash-collision DoS, deeply nested arrays, oversized headers, php-cgi argument injection patterns | 0.1 (critical subset), 1.0 (all) |
| 2. Request inspection | Signature/pattern checks on decoded input: SQLi, XSS, path traversal, command/code injection | After 1.0 |
| 3. Runtime checks | Hooking dangerous sinks: SQL whose structure changed because of request data, `exec`/`system`, `include` of user-controlled paths, `unserialize`/`phar://` object injection, `php://filter` chains (CVE-2024-2961), SSRF, XXE, `mail()` header injection, old-PHP traps (`preg_replace /e`, string `assert()`, `create_function`) | After 1.0 |
| 4. After a breach | Blocking execution of PHP from upload/writable dirs, writing `.php` files, webshell behaviour, unexpected outbound connections | After 1.0 |

Claude proposed this layering with "Layer 1 first, PHP2Shell as the headline". The owner replied "this is fantastic, write up this plan", which is taken here as agreement.

## 4. Release plan (owner)

Two releases. The first is small and fast, because PHP2Shell protection is worth most in the weeks after disclosure, and PHP 5.4–8.1 will never get the official fix.

### 4.1 Release 0.1 — "PHP2Shell shield" (ship first, target: weeks)

Scope:

- **Milestone 0 must pass first** (§12): proof that our hook point stops a PHP2Shell-shaped request before PHP allocates per-part state.
- **PHP versions:** all supported minors, 5.4 → 8.5 (§5.1). These old versions are the point of this release.
- **Platform and SAPIs:** Linux x86_64, NTS. PHP-FPM, Apache `mod_php` (prefork), php-cgi/FastCGI. aarch64 waits for 1.0. **(Claude's call)**
- **Protections:** the *critical* Layer-1 limits only:
  - multipart limits enforced while PHP parses;
  - upload-progress protection;
  - a backport of `max_multipart_body_parts`.
  These block by default (§5.5).
- **Logging:** JSON event logging and the block response (§5.6, §5.7).
- **Delivery:** signed tarballs on GitHub Releases, plus build-from-source. No apt/yum repos yet.
- **Install and verify:**
  - A first version of `howdah-check`: `detect`, plus `web` with the self-test requests (§8). It may be a shell script.
  - Manual install docs for at least PHP 7.3 on Ubuntu 16.04, and PHP 5.4 (stock) on CentOS 7.
- **Website:** a one-page site at howdah.org. It covers:
  - what Howdah is, and the PHP2Shell story;
  - manual install, verify and rollback;
  - the honest coverage table;
  - the GitHub link and security policy.

  It meets the same worldwide quality bar as the full site (§10).

### 4.2 Release 1.0 — first full release

Everything in §5, §8 and §10:
- all Layer-1 protections;
- aarch64;
- apt/yum repos;
- the full `howdah-check`;
- the install picker;
- the WebAssembly demo;
- the full site.

## 5. Goals in detail (1.0 unless marked 0.1)

1. **Runs on PHP 5.4, 5.5, 5.6, 7.0–7.4 and 8.0–8.5** on Linux x86_64 (0.1) and aarch64 (1.0).
   - 5.6 → 8.5 was the owner's original range. On Claude's recommendation the owner lowered the floor to 5.4, because CentOS 7, Amazon Linux 2 (5.4.16) and Ubuntu 14.04 (5.5.9) ship those as stock PHP.
   - 5.4 and 5.5 share PHP 5's internal layout, so they need extra builds, not extra glue.
2. **SAPIs:** PHP-FPM, Apache `mod_php` (prefork), and php-cgi/FastCGI **(Claude's call)**.
3. **Layer 1 protections:**
   - **(0.1) Multipart limits enforced while PHP parses, before per-part state is allocated:** max parts, max files, max part-header count and size, max filename/field-name length, and a memory budget for upload parsing. Must stop PHP2Shell-shaped requests on every supported version, including versions that will never get the official fix.
   - **(0.1) Upload-progress protection:** stop the session upload-progress path from being abused regardless of how `session.upload_progress.enabled` is set.
   - **(0.1) Backport newer PHP safety limits to old versions:** e.g. `max_multipart_body_parts` (8.0.28 / 8.1.16 / 8.2.3+ only), so 5.4–8.0 get it too.
   - **Input shape limits:** variable count, nesting depth, key length, header count and size.
   - **Malformed-request checks:** bad or duplicate boundaries, conflicting `Content-Disposition`, Content-Type tricks known to cause parser differentials.
   - **Known-CVE virtual patches** that can be enforced from inside PHP at request start. Example: php-cgi query strings starting with `-` (CVE-2012-1823 style) can be refused before the script runs.
4. **Honest coverage table (0.1 onward):** for every CVE we name, state per PHP version whether we stop it, partly mitigate it, or can't help. Some bugs (e.g. CVE-2019-11043 in FPM's own request setup) happen before any extension code runs; say so.
5. **Modes:** `off` / `detect` (log only) / `block`, set globally and per rule. Rules come in two classes **(Claude's call)**:
   - **Critical limits** (PHP2Shell shapes, absurd part counts, anything no legitimate request would hit) block out of the box, *even when the global mode is `detect`*. An admin can still set an individual critical rule to `detect`, but only by naming it explicitly.
   - **The global `howdah.mode` governs every other rule.** Those start in `detect`.

   This way the recommended "start in detect" rollout never leaves a server open to PHP2Shell during the first hours.
6. **Block response:** a short, configurable HTTP response (403, or 413 for size limits) carrying a request ID that matches the log line.
7. **Logging:** one JSON line per event, to a file or syslog: timestamp, request ID, rule ID, action, client IP, method, URI, and the reason.
   - Bodies, cookies and auth headers are never logged by default (privacy, GDPR). **(Claude's call)**
8. **Install and verify on old systems:** see §8. This is a requirement, not a doc afterthought. **(owner)**
9. **Marketing website** at howdah.org, served by GitHub Pages: see §10. **(owner)**

## 6. Later (after 1.0)

- Layer 2, then Layer 3, then Layer 4 (order is Claude's call; Layer 3 is where paid tools charge the most and where being inside PHP pays off).
- Thread-safe (ZTS) builds, e.g. FrankenPHP and threaded Apache.
- LiteSpeed LSAPI (which unlocks more cPanel/CloudLinux setups), Alpine/musl builds, and Windows.
- A rules feed so virtual patches can ship faster than releases.

## 7. Non-goals and anti-goals

### Non-goals

- Replacing PHP upgrades. The site and docs say plainly: patch when you can, use Howdah when you can't, or until you can.
- Network-level DDoS protection or rate limiting.
- A SaaS dashboard, accounts, or a hosted control plane.
- WordPress- or framework-specific admin UIs.

### Anti-goals: things that would make this a failure even if it "works"

- **Taking sites down.** False positives that block real users, or a crash in the extension that kills PHP workers. The extension must never become the vulnerability.
- **Overclaiming.** Saying we block something we haven't proven in the lab, on the site or anywhere else.
- **Paywalling protection.** No core protection behind a subscription or "pro" tier. That is the exact problem this project exists to fix. *(Claude's reading of the owner's motivation.)*
- **Phoning home.** No telemetry, update checks or network calls without explicit opt-in.
- **Noticeable slowdown.**

## 8. Install and verify: including old systems

### Requirements

- One binary per PHP **minor** version (5.4, 5.5, 5.6, 7.0, … 8.5). Each must match that version's Zend API number, NTS, non-debug.
- **Build against a glibc 2.17 baseline** so the same binary runs on CentOS 7 (2.17), Ubuntu 14.04 (2.19), Ubuntu 16.04 (2.23), Debian 8+ and everything newer. **(Claude's call)** Rust's standard library supports glibc ≥ 2.17. Kernel ≥ 3.2.
- **Three install paths:**
  1. **(1.0) Package repos** (apt and yum/dnf) at `pkg.howdah.org`, whose packages follow the layouts old-system users actually run:
     - Ondřej Surý's PPA/DPA: `/etc/php/<ver>/{fpm,apache2,cli}/conf.d`, `mods-available`, `phpenmod`.
     - Remi: `/etc/opt/remi/phpXY/php.d`, `/opt/remi/phpXY`.
     - Distro stock packages.
     - The control-panel builds named in §2.

     Repo rules:
     - Not tied to a distro codename, since the binary is the same across distros.
     - Packages depend on the PHP API virtual package (e.g. `phpapi-20180731` for 7.3).
     - Signing uses an RSA key that xenial- and CentOS-7-era `apt`/`rpm` can verify.
     - Repos are **HTTPS-only** (owner decision 2026-10-22, matching the industry norm set by Docker's and Ondřej Surý's own repos). CentOS 7 negotiates TLS 1.2 to the repo host without trouble. Pre-2018 Debian/Ubuntu (16.04 and older) need `apt-transport-https` and `ca-certificates` installed first — a documented one-line prerequisite, exactly what those other third-party repos already require. GPG signatures protect package integrity regardless of transport.
     - HTTPS-only means the package repo can be plain static files on any ordinary HTTPS host (Cloudflare R2, see §10); it no longer needs to serve plain HTTP on port 80.
  2. **(0.1) Signed tarball** of the `.so` plus `.ini`, with SHA-256 checksums and a signature, for manual installs.
  3. **(0.1) Build from source** with `cargo` against the server's own PHP headers (`php-config`).
- **`howdah-check` detection helper:** finds every PHP install on the box. Several PHP versions side by side is normal with Surý, Remi and control panels. For each one it reports: version, API number, NTS/ZTS, `extension_dir`, which SAPIs are present, and whether Howdah is loaded in each. **Read-only by default.**
- **Self-test request (the "EICAR test" for Howdah):** a fixed, harmless request that a built-in rule always flags. It proves Howdah is active in the *web* SAPI, not just the CLI, without sending anything dangerous. A second harmless test sends a multipart request just over the part limit, to show a critical limit blocking.
- **Visible in `php -m`, `php --ri howdah` and `phpinfo()`:** version, mode, rules file loaded, and active limits.
- **Uninstall/rollback in one step:** `phpdismod` (or remove the `.ini`), then restart.

### Worked example: PHP 7.3 on Ubuntu 16.04 (target experience, 1.0)

These commands describe the experience to build. The repo, packages and `howdah-check` don't exist yet. In 0.1, step 2a is replaced by the manual tarball steps in 2b.

```bash
# 1. See what's installed (PHP 7.3 on xenial almost always comes from ppa:ondrej/php)
php7.3 -v
howdah-check detect           # or: php7.3 -i | grep -E 'PHP API|Thread Safety|extension_dir'
#   -> PHP 7.3.33, API 20180731, NTS, /usr/lib/php/20180731, SAPIs: cli fpm

# 2a. Install from the apt repo (HTTPS-only; xenial needs the https transport first)
sudo apt-get install -y apt-transport-https ca-certificates curl
curl -fsSL https://howdah.org/key.asc | sudo apt-key add -
echo "deb https://pkg.howdah.org/apt stable main" | sudo tee /etc/apt/sources.list.d/howdah.list
sudo apt-get update && sudo apt-get install php7.3-howdah

# 2b. ...or manually from the signed tarball
#     verify checksum + signature, then copy howdah.so to /usr/lib/php/20180731/
#     and howdah.ini to /etc/php/7.3/mods-available/

# 3. Enable for FPM and restart. The package ships with howdah.mode=detect:
#    critical limits (PHP2Shell shapes) block immediately, everything else only logs.
sudo phpenmod -v 7.3 -s fpm howdah
sudo systemctl restart php7.3-fpm      # or: sudo service php7.3-fpm restart

# 4. Verify
php7.3 --ri howdah                      # CLI: version, mode, rules loaded
howdah-check web https://your.site/     # sends the harmless self-test requests
#   -> self-test: flagged (detect mode) — request id 7f3c…
#   -> multipart part-limit test: BLOCKED (critical limit, always on) — request id 91ab…
tail -n 2 /var/log/howdah/events.log    # matching JSON lines

# 5. Switch the remaining rules to block mode when the logs look clean
sudo sed -i 's/^howdah.mode=.*/howdah.mode=block/' /etc/php/7.3/mods-available/howdah.ini
sudo systemctl restart php7.3-fpm

# Roll back at any time
sudo phpdismod -v 7.3 -s fpm howdah && sudo systemctl restart php7.3-fpm
```

The docs need equivalent worked examples, at least for:
- CentOS 7 with stock PHP 5.4, and with Remi PHP 5.6 / 7.x
- Debian 9/10 + Surý PHP 7.x
- Ubuntu 20.04/22.04/24.04 + PHP 8.x
- Apache `mod_php` instead of FPM
- cPanel EA-PHP

## 9. Decided: how it's built

- **Language:** Rust **(owner)**. C is acceptable for thin glue where it's genuinely simpler; the owner is comfortable in both.
- **No Rust PHP framework can be the foundation (Claude's call, from research):**
  - `ext-php-rs` supports PHP 8.0+ only.
  - `phper` supports 7.0–8.4, NTS only.
  - Nothing supports PHP 5, because PHP's internal value layout changed completely in 7.0.
- **Shape (Claude's call):**
  - A **pure-Rust core** with no PHP types: multipart/header/input parsing and limits, the rule engine, config loading, and logging. This is where nearly all logic and tests live. It can be fuzzed and compiled to WebAssembly for the website demo (§10).
  - **Thin per-generation glue** (PHP 5.x / 7.x / 8.x) on our own bindings generated from each version's headers. Glue only translates PHP's data to core types and installs hooks. `unsafe` code stays in the glue.
- **Hook point:** install hooks at module startup (MINIT), never per request. Candidate hooks:
  - `php_rfc1867_callback`: exists since 5.4. The session extension chains through it the same way.
  - SAPI POST reading/handler registration.
  - `sapi_module.input_filter`.

  Which combination reliably stops a request *before* PHP allocates per-part state is the first thing to prove (§12, milestone 0).
- **Coexistence:** must chain correctly with other extensions that use the same hooks (session, opcache, Xdebug, Snuffleupagus, Datadog tracer) and must not depend on load order. If it does depend on load order, document it and detect it at startup.
- **Bad config (Claude's call):** if the rules file is invalid, log a loud error and run with built-in safe defaults. Never take PHP down.
- **Testing:**
  - A container lab image per supported PHP minor version, including the control-panel builds where licensing allows.
  - Our own reproducers for every CVE we name, written from advisories. Third-party PoC repos are untrusted: read them, don't run them on shared machines.
  - Fuzzing the core parsers (`cargo-fuzz`).
  - A false-positive corpus of real-world legitimate uploads and forms.
  - Benchmarks in CI.
- **Reproducer disclosure (Claude's call):**
  - Our reproducers only recreate the triggering request shape (e.g. PHP2Shell's memory exhaustion), never an RCE chain.
  - Full public PoCs, including RCE chains, already exist on GitHub, so publishing a DoS-shape test adds little risk. Even so, a reproducer stays out of the public repo until a release protecting against it can be installed.
  - The website demo describes the request's structure (part counts, header sizes). It never offers a copy-pasteable payload.
- **Performance target (Claude's call; builder to confirm by measuring):** no measurable overhead on requests without a body; single-digit-percent at most on large multipart uploads.
- **Project hygiene:** `SECURITY.md` with private reporting via GitHub Security Advisories, and reproducible builds.
- **Signing (Claude's call):**
  - The owner holds the primary GPG key offline.
  - CI signs release tarballs and package repos with a dedicated subkey stored as a CI secret. That subkey can be revoked and rotated without users re-trusting a new primary key.
  - GPG detached signatures plus SHA-256 checksums work on every old system. Sigstore provenance is added on top for newer tooling.
- **License (owner):** dual MIT / Apache-2.0.
- **Builders (Claude's assumption, not confirmed):** the owner working with Claude and agents. No outside contributors are planned for 0.1. Contributor docs arrive with 1.0.

## 10. Marketing website — howdah.org

**Owner's ask:** a GitHub Pages site that shows how Howdah is used, polished for a worldwide audience.

### Content

- **0.1:** a one-page site (§4.1).
- **1.0:**
  - **Home:**
    - Hero: what Howdah is in one sentence, and who it's for.
    - A short "what's a howdah?" note: the armoured seat on PHP's elephant.
    - The PHP2Shell story: why old PHP is exposed and why only an extension can help.
    - The four-layer "how it works" diagram.
    - The version-support matrix (5.4 → 8.5).
    - "Install in a minute."
    - A config example, plus the detect → block workflow.
    - An honest comparison table against Snuffleupagus, OpenRASP, Datadog AppSec, Aikido Zen and ModSecurity + CRS: dated, sourced, factual.
  - **Install picker (Claude's call):**
    - Choose OS + version (Ubuntu 14.04–24.04, Debian 8–13, CentOS/RHEL 7–9, Alma/Rocky, Amazon Linux, cPanel/Plesk/CloudLinux).
    - Choose PHP version and source (distro, Surý, Remi, panel).
    - Choose SAPI (FPM, Apache, CGI).
    - Get the exact install, verify and rollback commands. §8's worked example is the template. This is the main "how you'd use it" showcase.
  - **Coverage page:** the CVE × PHP-version table from §5.4, kept in sync with the test suite.
  - **Docs:** install per platform, config and rule reference, log format, upgrade/uninstall, FAQ, troubleshooting (e.g. "loaded in CLI but not FPM").
  - **Live demo (Claude's call):** the Rust core compiled to WebAssembly. Visitors pick a sample request, including a defanged PHP2Shell-shaped one described by its structure, and see what Howdah would do. It only demonstrates checks whose logic lives in the core.
  - **News/blog:** launch post, and a PHP2Shell explainer.
  - **Community:** GitHub link, contributing guide, code of conduct, security policy.

### Quality bar for "worldwide" (applies to 0.1 and 1.0; Claude's calls)

- English at launch, built with i18n routing so translations drop in without restructuring. RTL-ready layout.
- WCAG 2.2 AA accessibility; light and dark themes.
- No trackers, no cookies, no third-party requests. Fonts are self-hosted, which matters for GDPR in the EU, and means no cookie banner is needed.
- Fast on slow connections and old devices: a strict page-weight budget, and works without JavaScript except the demo and picker.
- Plain-language copy: no fear-mongering, no "unhackable". Every protection claim links to the test that proves it (anti-goal: overclaiming).
- Own visual identity. Don't use the PHP logo or the elePHPant in a way that implies endorsement by the PHP project.
- Visual mockups go to the owner for review before the site is built.

### Tech (Claude's call)

- Astro static site, deployed to GitHub Pages by GitHub Actions from the main repo's `site/` folder, on the custom domain howdah.org from day one.
- Package repos live on `pkg.howdah.org` (HTTPS) so their hosting can change without changing users' sources lists.
- Package repo and signing-key URLs are written permanently into users' apt sources and yum `.repo` files, so they must be final before the first release that uses them.
- **`pkg.howdah.org` hosting (owner decision 2026-10-22): a public Cloudflare R2 bucket on the custom domain `pkg.howdah.org`.** This replaces the earlier plan to self-host on `ashlar-prod` behind its Cloudflare tunnel. There is no server to run or patch, nothing is shared with ashlar-prod, downloads (egress) are free, and Cloudflare's edge absorbs download spikes after a disclosure. R2 is part of Cloudflare's Developer Platform, which is where the CDN terms send large files, so the free-plan bulk-file concern goes away. The repo is static files (apt `dists/` + `pool/`, yum `repodata/` + packages), so no Worker or server code is needed, and the custom domain provides HTTPS. The free tier (10 GB-month storage, 1M writes and 10M reads a month, free egress) covers 1.0 comfortably. Moving to another host later changes only DNS, not users' sources lists. Not needed until 1.0; 0.1 uses GitHub Releases tarballs.
  - Builder notes for 1.0:
    - CI publishes with an R2 API token scoped to this one bucket ("Object Read & Write", S3-compatible API), stored as a CI secret, using `rclone` or `aws s3 sync`. Signing stays in CI (§9): the bucket only ever receives already-signed files, so a leaked token can replace files but can't forge signatures.
    - R2 has no atomic swap. Upload in dependency order: packages first, then index files, then `InRelease`/`Release`/`Release.gpg` and `repomd.xml` last. Don't delete superseded packages in the same publish, so clients mid-update don't hit 404s.
    - Caching: Cloudflare caches some file extensions by default, `.gz` included, which can pair a stale `Packages.gz` with a fresh `InRelease` ("Hash Sum mismatch"). Add cache rules: `pool/` and package files long (version-named, never change); `dists/` and `repodata/` bypass or about a 1-minute TTL.
    - The `pkg` hostname must be public and unchallenged: no Cloudflare Access policy and no bot-fight or challenge rules on it, because `apt`/`yum` can't pass a challenge.
    - Public buckets have no directory listing; apt and yum don't need one.
    - Tooling: `reprepro` or `aptly` for the apt tree, `createrepo_c` for yum.

## 11. What success looks like

- **0.1:** a sysadmin on PHP 7.3 / Ubuntu 16.04 or stock PHP 5.4 / CentOS 7 installs from the tarball and sees "multipart part-limit test: BLOCKED" from their web server, using only the one-page site's instructions.
- **1.0:** the same user goes from nothing to verified in under 10 minutes using the apt/yum repo and the install picker.
- PHP2Shell-shaped and CVE-2023-0662-shaped requests are blocked in the lab on every supported PHP minor version. The coverage table says exactly what is and isn't covered.
- The false-positive corpus passes with zero blocks.
- No crashes under fuzzing and in the lab test runs.
- The benchmark meets the performance target.

## 12. Left to the builder

- **Milestone 0 (do first, before anything else):** a spike proving which hook combination stops a PHP2Shell-shaped request before per-part allocation on 5.4, 5.6, 7.3, 7.4 and 8.x. If no hook point works for some version range, stop and report. That changes what we can promise.
- The exact rules/config file format (TOML suggested), rule IDs, and config directive names (`howdah.*`).
- How bindings are generated and organised per PHP version; repo layout; CI matrix.
- Exact default limits, chosen from measurements and the false-positive corpus.
- `howdah-check` design (language, distribution).
- The apt/yum repo tooling and the CI publish job for `pkg.howdah.org`. Hosting itself is decided: Cloudflare R2 (§10).
- Site information architecture details and copy, within §10.

## 13. Owner actions / setup status

- ✅ **howdah.org** registered (Namecheap, 2026-10-22).
- ✅ **`howdah` GitHub organisation** created; repo at github.com/howdah/howdah (public), private vulnerability reporting enabled.
- ✅ **Release-signing GPG key** created 2026-10-22: RSA 4096 certify-only primary + RSA 4096 signing subkey (expires 2028-10-21), UID `Howdah release signing <security@howdah.org>`.
  - **Primary fingerprint:** `11521035C600F63831F825512087B8720997807B`
  - Public key: `howdah-signing-public.asc` → will be published at `howdah.org/key.asc` and shipped with releases.
  - Owner backs up the master secret + revocation certificate offline. At CI setup (Task 13), only the signing subkey goes to CI and the primary secret is removed from online keyrings.
- ⬜ **Cloudflare R2 for `pkg.howdah.org`** (needed before 1.0, not 0.1):
  - Move howdah.org's nameservers from Namecheap to Cloudflare (free plan), in the same Cloudflare account that will own the bucket; R2 custom domains require that. Keep the GitHub Pages records for `howdah.org`/`www` as "DNS only" (grey cloud) so GitHub can still issue its certificate. Checked 2026-10-22: howdah.org still uses Namecheap's nameservers.
  - Create the R2 bucket (e.g. `howdah-pkg`) and connect the custom domain `pkg.howdah.org`. R2 may ask for a payment method before enabling, even on the free tier.
  - Create an R2 API token scoped to that bucket with Object Read & Write, for CI (§10 builder notes).
- Optional: add howdah.dev as a redirect to howdah.org (howdah.dev looked free on 2026-10-22).
