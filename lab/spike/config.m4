dnl config.m4 for the throwaway milestone-0 spike extension (probe.c).
dnl Not part of the shipped Howdah extension.

PHP_ARG_ENABLE(probe, whether to enable probe support,
[  --enable-probe          Enable probe support (milestone-0 spike)])

if test "$PHP_PROBE" != "no"; then
  PHP_NEW_EXTENSION(probe, probe.c, $ext_shared)
fi
