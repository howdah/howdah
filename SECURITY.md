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
| 0.1 (pre-release) | Yes. This is the only line, and it is not yet released. |

Until a stable release exists, fixes land on the main branch and in the next
pre-release.

## What to expect

We will acknowledge a report, keep you updated while we investigate, and credit
you in the advisory if you want that. This is a small open-source project, so
we cannot promise fixed response times.

## Scope reminder

Howdah 0.1 only covers abusive multipart upload floods. It is not a
replacement for patching PHP. A vulnerability in PHP itself should go to the PHP
project.
