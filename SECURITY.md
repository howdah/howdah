# Security policy

Howdah is a defensive tool, so we take reports about it seriously.

## Reporting a vulnerability

Please report privately through GitHub's private vulnerability reporting: open
the **Security** tab of this repository and choose **Report a vulnerability**.
Please do not open a public issue or pull request for a suspected
vulnerability.

Useful things to include: the Howdah version, PHP version and SAPI, your
configuration, and what you expected to happen versus what did. A bypass of a
rule, a crash or hang in the extension, or a way to make Howdah itself consume
excess memory are all in scope.

**Please do not include working exploits or payloads, in public or in your
private report, unless we ask.** Howdah's own reproducers deliberately
reproduce only the harmless request *shape* (part counts and sizes), never
payloads or exploit code. A description of the shape that gets past a rule is
enough for us to reproduce and fix it.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.5.x | Yes. Current release; fixes ship here first. |
| 1.4.x and earlier | No. Upgrade to the latest 1.5.x release. |

Fixes land on `main` and ship in the next patch release of the current minor
line. Releases and packages are available from the GitHub releases page and
the signed apt/yum repositories at `https://pkg.howdah.org`.

## What to expect

This is a small open-source project, but we commit to the following:

- **Acknowledgement** within 3 business days of your report.
- **A fix or a mitigation plan** within 14 days for High and Critical reports.
  Lower severities are handled on a best-effort basis and we will tell you
  where they stand.
- **Coordinated disclosure:** we ask that you keep the report private for up to
  90 days from the date you reported it. If we ship a fix sooner, we publish
  the advisory then; if a fix needs longer, we will agree an extension with you
  rather than let the deadline pass silently.
- We keep you updated while we investigate, and credit you in the advisory if
  you want that.

## Verifying releases

Release checksums (`SHA256SUMS`) and the apt/yum repositories are signed with
the project key, published at `https://howdah.org/key.asc`. The primary key
fingerprint is `1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B`. Check it
before trusting the key:

```sh
curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint
```

Then, for a downloaded tarball `$T`:

```sh
gpg --import howdah-release-signing.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify "$T" -R howdah/howdah     # build provenance (releases after 1.4.0)
```

Releases after 1.4.0 also carry SLSA build provenance and a CycloneDX SBOM,
attested through Sigstore by the release workflow, with the bundles attached
for offline checks with `cosign`. The packages on `pkg.howdah.org` carry build
provenance too.

**Independent verification.** The release tarballs are reproducible: the
same tag gives byte-identical tarballs on any machine with Docker. To check a
release without trusting GitHub, our CI or us, rebuild one PHP minor from the
tag and compare it with the signed checksum:

```sh
packaging/verify-reproducible.sh v1.5.0 7.4
```

[docs/verify.md](docs/verify.md) has every step, what each check proves, what
is pinned in the build, and the known residual causes of a mismatch.

Howdah has had no third-party security audit yet.
[docs/security-audit-brief.md](docs/security-audit-brief.md) is the scope and
threat model we would hand an auditor.

## Scope

Howdah is a PHP extension with four layers. **Layer 1** enforces request
limits (multipart floods, input-variable floods, nesting depth, header
sizes); its critical limits block in the default `detect` mode. **Layer 2**
inspects decoded input values and only logs. **Layer 3** hardens dangerous
sinks (command execution, `unserialize`, `include`/`eval`, `phar://`, SSRF)
and only logs unless a sink is explicitly armed. **Layer 4** (after-breach
behaviour: PHP run from upload directories, unexpected binaries, unexpected
outbound hosts, `.php` writes) is log-first and inert until an operator sets its
lists; it only sees what PHP itself does. The exact, lab-verified
coverage per PHP version is in [docs/coverage.md](docs/coverage.md), including
what is not covered.

In scope: a bypass of a documented protection, a crash or hang in the
extension, excess memory use caused by Howdah itself, a way to make Howdah log
request bodies, cookies, `Authorization` headers, matched values or sink
arguments (it must not), and flaws in the package repositories, signing,
build provenance or the reproducible build (a release that does not rebuild to
its signed checksum is a bug).

Out of scope: gaps already listed as limitations in docs/coverage.md, and
Howdah is not a replacement for patching PHP or your application. A
vulnerability in PHP itself should go to the PHP project.
