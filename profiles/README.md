# Application profiles

Starting points for a `howdah.toml` on a vanilla install of a common legacy
PHP application. Each file is a complete, loadable config in `detect` mode
whose `[[exceptions]]` entries and commented allowlist suggestions cover the
application's own known behaviours, with the source file and line each one
was verified against. See `docs/exceptions.md` for how exceptions work.

**Nothing here is applied automatically.** Copy the file, replace the docroot
placeholder (`/var/www/html`) with the path PHP reports for your install
(`php -r 'echo __FILE__;'` from the docroot, or `__FILE__` in any script),
read every entry, delete the ones you do not need, and keep the `reason`
lines: they are your decision record.

| File | Application | Verified against |
|---|---|---|
| `wordpress.toml` | WordPress 4.9 / 5.9 / 6.8 / 7.1 | wordpress.org release archives |
| `drupal7.toml` | Drupal 7.103 (end of life 2025-01-05) | drupal.org tarball |
| `magento1.toml` | Magento 1.9.4.5 and OpenMage LTS | OpenMage mirror and repository |
| `magento2.toml` | Magento 2.4 | magento/magento2 2.4-develop and Adobe docs |
| `joomla.toml` | Joomla 3.10 and 4.4 | joomla-cms release tags |
| `prestashop16.toml` | PrestaShop 1.6.1 | PrestaShop 1.6.1.x tag and 1.6 docs |

What the profiles do **not** cover: plugins, modules, themes and extensions
(each adds behaviours of its own), custom code, and anything a hosting panel
adds to the tree. An entry that could not be verified in the application's
own source is commented out and says so.

Every profile loads with the extension's own parser; `cargo test -p
howdah-core --test profiles` checks that each parses, that every exception has
a reason, and that none of them arms a block.
