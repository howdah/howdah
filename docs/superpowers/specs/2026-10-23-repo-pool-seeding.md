# Repo pool-seeding: keep every published version in the apt/yum index

## Problem
`packaging/repo/publish-r2.sh` never deletes, so every version's packages stay in R2.
But the apt/yum **indexes** are regenerated from only the packages built in the
current run (`build-apt-repo.sh` / `build-yum-repo.sh`), so after a 2nd release the
prior version drops out of the index (apt `Packages`, yum `repodata`) even though the
`.deb`/`.rpm` objects remain in the pool. `GO-LIVE.md` flags this as the required
follow-up before the second release. v1.1.0 is that release.

## Root cause (verified)
- apt: `reprepro` keeps only the newest version per package, and bookworm's reprepro
  rejects a `Limit` field (`Unknown header 'Limit'`). It cannot keep multiple versions.
  **`apt-ftparchive packages <pool>` lists EVERY `.deb` present (all versions)** — verified.
- yum: `createrepo_c` already indexes every `.rpm` in the directory (multi-version works)
  — the only gap is that old rpms aren't present at index time.

## Fix: seed the build from the existing R2 pool, index the union
Both builds take an optional **seed** (the existing published pool, downloaded from R2).
The index is generated over seed ∪ new. Only the NEW packages are signed and the old
objects are byte-identical to R2, so re-upload is a no-op under `publish-r2.sh --immutable`.

### 1. `packaging/repo/build-apt-repo.sh` — replace reprepro with apt-ftparchive
- New optional env `HOWDAH_APT_SEED`: a dir containing an existing `pool/` subtree
  (as downloaded from R2, i.e. `pool/main/p/<pkg>/<pkg>_<ver>_<arch>.deb`). Empty/unset
  ⇒ first publish, seed is empty.
- Assemble `OUT/apt/pool` = copy of the seed pool (preserve paths) + the new `.deb`s from
  `DEB_DIR`, each placed at `pool/main/p/<pkg>/<pkg>_<ver>_<arch>.deb` (same convention
  reprepro used — the validators depend on this path). Derive `<pkg>` from the deb's
  `Package:` control field; prefix letter is its first char (always `p` for `php*`).
- Generate, in the `debian:bookworm` container, with `apt-utils` + `gnupg`:
  - per-arch `dists/stable/main/binary-amd64/Packages` and `…/binary-arm64/Packages`
    (filter the pool by architecture), plus `.gz`, via `apt-ftparchive`.
  - per-arch `dists/stable/main/binary-<arch>/Release` (small: Archive/Component/Arch).
  - top `dists/stable/Release` via `apt-ftparchive release` with these settings so it
    matches the current one: `Origin=Howdah`, `Label=Howdah`, `Suite=stable`,
    `Codename=stable`, `Architectures=amd64 arm64`, `Components=main`,
    `Description=Howdah - defensive WAF for PHP`. It MUST contain `MD5Sum` AND `SHA256`
    sections (xenial apt needs SHA256).
  - Sign with `HOWDAH_GPG_KEYID` in `HOWDAH_GNUPGHOME` (as today), SHA256 digest:
    `InRelease` (clearsign, `gpg --clearsign`) and `Release.gpg` (detached `--detach-sign --armor`? match current — current Release.gpg is binary detached; keep whatever apt on xenial accepts — detached armored is fine).
- Output tree identical in shape to the current one (so `publish-r2.sh` and the
  validators are unchanged): `apt/dists/stable/{InRelease,Release,Release.gpg,main/binary-{amd64,arm64}/{Packages,Packages.gz,Release}}` + `apt/pool/main/...`.
- No reprepro `conf`/`db` in the output. Handle an empty seed (just the new debs).

### 2. `packaging/repo/build-yum-repo.sh` — seed + sign only new
- New optional env `HOWDAH_YUM_SEED`: a dir of existing (already-signed) `*.rpm`.
- Copy seed rpms AND new rpms (`RPM_DIR`) into `OUT/yum`. **Sign ONLY the new rpms**
  (the ones from `RPM_DIR`) with `rpmsign`; do NOT re-sign the seeded ones — re-signing
  rewrites the signature header (non-deterministic bytes) and would break
  `publish-r2.sh --immutable` on re-upload. `createrepo_c` over the whole dir; sign repomd.
- Invariant to assert in the test: a seeded rpm's sha256 is identical before and after.

### 3. `.github/workflows/publish-repos.yml` — download the seed before assembling
In the `publish` job, BEFORE the apt/yum build steps (rclone is already installed and R2
env is already set for the upload step — reuse it), download the existing pool into a seed
dir, resiliently (first publish: bucket paths may not exist → empty seed, do not fail):
```
rclone copy "R2:$HOWDAH_R2_BUCKET/apt/pool" "$SEED/apt/pool" || true   # (plus --config/-v as the upload step uses)
rclone copy "R2:$HOWDAH_R2_BUCKET/yum" "$SEED/yum" --include '*.rpm' || true
```
Pass `HOWDAH_APT_SEED=$SEED/apt/pool` to the apt build step and `HOWDAH_YUM_SEED=$SEED/yum`
to the yum build step. (The rclone remote `R2` is configured via the same `RCLONE_CONFIG_R2_*`
env the upload step uses; set those on the seeding step too.)

### 4. `packaging/repo/GO-LIVE.md`
Remove the "Known limitation: the index reflects only the latest publish" / "Required
follow-up before the second release" block (now implemented). Add a short note that each
publish seeds from the existing pool so the index keeps all prior versions, and that a
same-version re-publish (arch backfill) still uses `overwrite`.

## Test gate (MUST pass, with output shown)
Use the throwaway key (`gen-throwaway-key.sh`) and the existing container validators.

**A. Multi-version index + signing (fast, fabricated fixtures — no real howdah needed):**
- Build two minimal `.deb`s for the same package name at versions `1.0.0-1` and `1.1.0-1`
  (both amd64 + arm64), and two `.rpm`s likewise. Put the `1.0.0` ones in a SEED dir and
  the `1.1.0` ones in the build input.
- Run `build-apt-repo.sh` with `HOWDAH_APT_SEED=<seed>` and `build-yum-repo.sh` with
  `HOWDAH_YUM_SEED=<seed>`.
- Assert the apt `Packages` (amd64) lists BOTH `1.0.0-1` and `1.1.0-1`; assert the yum
  `repodata` (primary) lists both. Assert a seeded rpm's sha256 is unchanged.

**B. Real client install + tamper (one real built package per manager):**
- Build ONE real minor: `packaging/deb/build-deb.sh 8.3 amd64` and
  `packaging/rpm/build-rpm.sh 8.3 x86_64` (this is the current 1.1.0 version).
- Seed with the fabricated OLD-version deb/rpm of the SAME package name (`php8.3-howdah`
  `1.0.0-1`) so the repo holds two versions, build the repos, then:
  - `packaging/repo/validate.sh apt debian:bookworm 8.3 ok` — install succeeds, howdah loads.
  - `packaging/repo/validate.sh apt debian:bookworm 8.3 tamper` — all tamper variants REFUSED.
  - `packaging/repo/validate.sh yum el9 8.3 ok` and `… tamper` likewise (use the right php
    package name for Remi; if the real rpm install is impractical in the container, at least
    prove `dnf` accepts the signed repo metadata and lists both versions, and keep the
    tamper-refused check).
- If a real install step is infeasible in the sandbox, say so explicitly and show the
  furthest you got (signed `apt-get update` verifying + `apt-cache policy` showing both
  versions is the minimum acceptable evidence for the format being correct).

Never fake a validator result. Report exactly what ran and its output.
