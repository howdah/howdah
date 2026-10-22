# Howdah

**An open-source web application firewall for PHP, built as a native extension.**

Howdah is a *defensive* firewall. It loads into PHP itself and inspects
requests before PHP processes them, so it can stop abuse that a network-level
WAF never sees — starting with abusive `multipart/form-data` uploads that
exhaust worker memory (the PHP2Shell / CVE-2026-109618 shape, CVE-2023-0662).

It is aimed at sysadmins running PHP on their own servers, including those
stuck on older PHP that will never get an official fix. The first release
targets **PHP 5.4 through 8.5** on Linux.

> **Status: pre-release, under active development.** Nothing here is ready to
> install on a production server yet. The first release (0.1, "PHP2Shell
> shield") is being built against the plan in
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## What it is not

- Not a replacement for upgrading PHP. Patch when you can; use Howdah when you
  can't, or until you can.
- Not a hacking tool. Howdah only recognizes and blocks abusive input.

## Design & plan

- [Design document](docs/superpowers/specs/2026-10-22-howdah-design.md)
- [0.1 implementation plan](docs/superpowers/plans/2026-10-22-howdah-0.1-php2shell-shield.md)

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.

## Security

Please report vulnerabilities privately via GitHub's "Report a vulnerability"
button on the Security tab, not in public issues.
