#!/bin/sh
# Build howdah-sys for one PHP generation inside a dev image (see dev.Dockerfile)
# and list the key symbols that landed in the generated bindings.
#   usage: lab/images/check-sys.sh <image> <phpN-feature>
#   e.g.   lab/images/check-sys.sh howdah-dev-php7.3 php7
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
docker run --rm -v "$root":/src:ro -w /src -e CARGO_TARGET_DIR=/tmp/t "$1" sh -c "
  cargo build -p howdah-sys --features $2 2>&1 | tail -5
  f=\$(ls /tmp/t/debug/build/howdah-sys-*/out/bindings.rs | head -1)
  echo \"bindings: \$(wc -c < \$f) bytes\"
  grep -aoE 'pub (static mut|static|const|struct|type|fn) (php_rfc1867_callback|MULTIPART_EVENT_[A-Z_]+|_?zend_module_entry|zend_module_entry|_?sapi_module_struct|sapi_module_struct|sapi_module|ZEND_MODULE_API_NO|PHP_VERSION_ID)\b' \$f | sort -u
"
