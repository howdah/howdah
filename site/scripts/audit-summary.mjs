// Summarise an `npm audit --json` report (read from stdin) for the CI `deps`
// job in .github/workflows/ci.yml:
//   - Markdown to $GITHUB_STEP_SUMMARY (stdout when unset): vulnerable
//     packages by severity, then every advisory, most severe first, linked,
//     with the fix npm offers;
//   - one ::warning:: annotation with the counts and the top advisory ids, so
//     the findings show on the PR without turning the job red.
// Exit 0 whether or not there are findings: the annotation and the summary
// carry them, and a non-zero exit would add an error annotation to every PR.
// Exit 2 when the input is not an npm audit report (for example the registry
// could not be reached), which is a real error.
//
//   npm audit --omit=dev --json | node scripts/audit-summary.mjs
import { appendFileSync, readFileSync } from 'node:fs';

const ORDER = ['critical', 'high', 'moderate', 'low', 'info'];
const rank = (s) => (ORDER.includes(s) ? ORDER.indexOf(s) : ORDER.length);
// One Markdown table cell: no pipes, no newlines, and no raw < > (a title such
// as "...</script> tag..." must not be read as HTML by the summary renderer).
const cell = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();

const raw = readFileSync(0, 'utf8');
let report;
try {
  report = JSON.parse(raw);
} catch {
  report = null;
}
const meta = report?.metadata?.vulnerabilities;
if (!meta || typeof meta.total !== 'number') {
  const why = report?.error?.code ?? (report ? 'no metadata.vulnerabilities' : 'not JSON');
  console.log(`::error title=npm audit::npm audit did not produce a report (${why})`);
  process.stdout.write(raw.slice(0, 2000));
  process.exit(2);
}

const counts = ORDER.filter((s) => meta[s] > 0).map((s) => `${meta[s]} ${s}`).join(', ');

// Every advisory once (several packages can point at the same one).
const advisories = new Map();
for (const [pkg, entry] of Object.entries(report.vulnerabilities ?? {})) {
  const fix = entry.fixAvailable;
  const fixText = fix && typeof fix === 'object'
    ? `${fix.name}@${fix.version}${fix.isSemVerMajor ? ' (major version)' : ''}`
    : fix ? 'yes' : 'none';
  for (const via of entry.via ?? []) {
    if (typeof via !== 'object' || !via.url || advisories.has(via.url)) continue;
    advisories.set(via.url, {
      id: via.url.split('/').pop(),
      url: via.url,
      pkg: via.name ?? pkg,
      severity: via.severity,
      range: via.range,
      title: via.title,
      fix: fixText,
    });
  }
}
const sorted = [...advisories.values()].sort((a, b) => rank(a.severity) - rank(b.severity));

const lines = ['### npm audit (site/, production dependencies)', ''];
if (meta.total === 0) {
  lines.push('No known vulnerabilities.');
} else {
  lines.push(`${meta.total} vulnerable packages: ${counts}. ${sorted.length} advisories:`, '');
  lines.push('| Severity | Package | Advisory | Affected | Title | Fix |', '| --- | --- | --- | --- | --- | --- |');
  for (const a of sorted) {
    lines.push(`| ${a.severity} | ${cell(a.pkg)} | [${a.id}](${a.url}) | ${cell(a.range)} | ${cell(a.title)} | ${cell(a.fix)} |`);
  }
}
const md = lines.join('\n') + '\n';
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
else process.stdout.write(md);

if (meta.total === 0) process.exit(0);
const top = sorted.slice(0, 5).map((a) => a.id).join(', ');
console.log(`::warning title=npm audit::${meta.total} vulnerable packages (${counts}) in the site's production dependencies. Most severe: ${top}. Details in the job summary.`);
