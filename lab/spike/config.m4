dnl config.m4 for the throwaway spike extensions (probe.c, input_probe.c).
dnl Not part of the shipped Howdah extension.

PHP_ARG_ENABLE(probe, whether to enable probe support,
[  --enable-probe          Enable probe support (milestone-0 spike)])

if test "$PHP_PROBE" != "no"; then
  PHP_NEW_EXTENSION(probe, probe.c, $ext_shared)
fi

dnl Input-hook spike (input_probe.c), 1.0 Layer-1 protections.
PHP_ARG_ENABLE(input-probe, whether to enable input_probe support,
[  --enable-input-probe    Enable input_probe support (input-hook spike)])

if test "$PHP_INPUT_PROBE" != "no"; then
  PHP_NEW_EXTENSION(input_probe, input_probe.c, $ext_shared)
fi
