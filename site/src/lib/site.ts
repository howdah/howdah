// Shared site constants and the single nav model. Every page and component
// imports from here so URLs, the version, and the nav stay in one place.

export const REPO = 'https://github.com/howdah/howdah';
export const RELEASES = `${REPO}/releases`;
export const PKG = 'https://pkg.howdah.org';
export const VERSION = '1.2.0';

// Signing key primary fingerprint, grouped for readability (compare against gpg).
export const KEY_FPR = '1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B';

export interface NavItem {
  href: string;
  label: string;
}

// Primary navigation, in order. `href` values are site-absolute so the active
// link can be matched against the current path.
export const NAV: NavItem[] = [
  { href: '/', label: 'Home' },
  { href: '/install/', label: 'Install' },
  { href: '/coverage/', label: 'Coverage' },
  { href: '/demo/', label: 'Demo' },
  { href: '/docs/', label: 'Docs' },
  { href: '/blog/', label: 'Blog' },
  { href: '/community/', label: 'Community' },
];

// True when `current` is the nav entry for `href` (exact for home, prefix
// otherwise), so parent sections stay highlighted on their sub-pages.
export function isActive(href: string, current: string): boolean {
  const norm = (p: string) => (p.endsWith('/') ? p : `${p}/`);
  const c = norm(current);
  if (href === '/') return c === '/';
  return c === norm(href) || c.startsWith(norm(href));
}
