# Go-live: publishing the apt + yum repos to pkg.howdah.org

Everything is built and validated, but nothing real has been published. These are
the owner-only steps. Do them in order.

## 1. Create the `pkg-publish` Environment and put the secrets in it

The `publish` job declares `environment: pkg-publish`. That Environment is what
makes the owner gate enforced rather than conventional, so create it first:
Repo -> Settings -> Environments -> New environment -> `pkg-publish`, then set:

- **Required reviewers**: add yourself (a human approves every run of the
  publish job, dry runs included).
- **Deployment branches**: restrict to `main` (selected branches).
- **Environment secrets**: add the secrets below, and `HOWDAH_GPG_SIGNING_KEY`,
  to this Environment rather than repo-wide, so only an approved run on `main`
  can read them. (If `release.yml` still needs the GPG key repo-wide, keep it
  there too.)

Create an R2 API token scoped to the one package bucket with **Object Read & Write**
(Cloudflare dashboard -> R2 -> Manage API tokens), then add:

| Secret | Value |
|---|---|
| `HOWDAH_R2_ACCESS_KEY_ID` | token Access Key ID |
| `HOWDAH_R2_SECRET_ACCESS_KEY` | token Secret Access Key |
| `HOWDAH_R2_ENDPOINT` | `https://<account-id>.r2.cloudflarestorage.com` |
| `HOWDAH_R2_BUCKET` | the bucket name (the dev proof used `howdah-pkg`) |

`HOWDAH_GPG_SIGNING_KEY` (the passphraseless signing subkey) already exists for
`release.yml` and is reused as is. The token is bucket-scoped, so it cannot list
buckets (`rclone lsd` returns 403); that is expected.

## 2. Confirm https://howdah.org/key.asc serves the public signing key

```sh
curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint
```

It must contain the primary key and the signing subkey
`9A104FB0A073065B2C2631FC1E8D725D31BD5DC9` (same key as
`packaging/howdah-release-signing.asc`). Every user config points here, so get
this right before publishing.

## 3. Cloudflare cache rules (dashboard: howdah.org -> Caching -> Cache Rules)

The workflow also stamps matching `Cache-Control` headers on each object. Rules
(host `pkg.howdah.org`):

| Match | Setting |
|---|---|
| path starts with `/apt/pool/` or ends with `.rpm` | Eligible for cache; Edge TTL 1 year (or respect origin); Browser TTL respect origin. These are version-named and immutable. |
| path starts with `/apt/dists/` or `/yum/repodata/` | Bypass cache (or Edge TTL 5 minutes max, Browser TTL 5 minutes). These change on every publish. |
| everything else | defaults |

Also: the `pkg` host must be public and unchallenged. Do not put a WAF
challenge, Bot Fight Mode, or "Under Attack" on `pkg.howdah.org`; apt and yum
cannot solve it. Keep the custom domain connected to the bucket with public
access on. If you ever republish a mutable path and need it instantly, purge
`/apt/dists/*` and `/yum/repodata/*` from the Cloudflare cache.

## 4. Dry run, then publish

Actions -> `publish-repos` -> Run workflow.

1. First run with **publish unchecked**. It builds 14 PHP minors x deb/rpm, signs
   with the real subkey, verifies the signatures against the committed public key,
   and dry-runs the upload (prints what it would copy; writes nothing).
2. If green, run again with **publish checked**. Upload order is packages,
   then indexes, then `Release`/`Release.gpg`/`InRelease` and
   `repomd.xml`/`repomd.xml.asc` last. No object is ever deleted. Republishing
   a package file with changed bytes is refused (`--immutable`): bump the
   revision (`HOWDAH_DEB_REV` / `HOWDAH_RPM_REL`) or version instead.

### Re-publishing the same version (e.g. architecture backfill)

To add packages that failed to build the first time (for example an `aarch64`
cell that has since been fixed) **without** bumping the version, run the
workflow with **both `publish` and `overwrite` checked**. `overwrite` drops the
`--immutable` guard so the full, freshly rebuilt set replaces what is there;
because every run rebuilds all packages, the pool and the regenerated index stay
consistent. The rebuilt package bytes differ from the originals, so the pool
objects are long-cached — **afterwards, purge the Cloudflare cache** (Caching →
Purge Everything, or the `/apt/pool/*` and `*.rpm` paths) so the edge serves the
new bytes that the new index references. Verify with a fresh-container install
(step 5) once the cache is purged.

**The index keeps every published version.** Before assembling the repos, the
`publish` job seeds the build from the existing R2 pool (`rclone copy` of
`apt/pool` and `yum/*.rpm` into a seed dir, resiliently — the first publish has
nothing to seed). `build-apt-repo.sh` (apt-ftparchive) and `build-yum-repo.sh`
(createrepo_c) then index the union of the seeded pool and the newly built
packages, so earlier versions stay in the apt `Packages` and yum `repodata`
indexes and users can still `apt install pkg=<oldver>` / roll back through the
repo. The seeded objects are copied byte-for-byte and only the new packages are
signed, so re-uploading them is a no-op under `publish-r2.sh --immutable`. A
deliberate same-version re-publish (architecture backfill) still uses
`overwrite` (see above), since those package bytes are rebuilt and differ.

The arm64/aarch64 jobs are best-effort: a failed cell only drops that
architecture for that minor.

## 5. Verify against the live URL

Fresh containers, following `docs/install-repos.md` exactly:

```sh
docker run --rm -it debian:bookworm bash
#   apt-get update && apt-get install -y curl ca-certificates gnupg
#   (add the PHP source you test with, e.g. packages.sury.org, install php7.4-cli)
#   <follow the "Modern apt" snippet>; apt-get update; apt-get install php7.4-howdah
#   php -m | grep -i howdah

docker run --rm -it almalinux:9 bash
#   <follow the yum snippet, with Remi's php74 installed>; dnf install php74-howdah
#   /opt/remi/php74/root/usr/bin/php -m | grep -i howdah

docker run --rm -it ubuntu:16.04 bash    # xenial: also prove end to end (not yet done)
```

Quick sanity without installing:

```sh
curl -fsSI https://pkg.howdah.org/apt/dists/stable/InRelease
curl -fsSI https://pkg.howdah.org/yum/repodata/repomd.xml.asc
```

## Rollback of a bad publish

The workflow never deletes objects, so old package files stay in R2 and remain
listed in the index (every publish re-seeds from the pool). To retract, delete the
affected `Release`/`InRelease`/`repomd.xml` objects (or overwrite them with the
previous signed copies) in the R2 dashboard, then purge the Cloudflare cache for
`/apt/dists/*` and `/yum/repodata/*`.
