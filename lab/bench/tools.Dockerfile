# Benchmark tools image: the load generator (wrk) and the FastCGI front end
# (nginx) used by lab/bench/run.sh. One image for every PHP version, so the
# client and the web server are identical across the PHP images under test.
#
# It never runs PHP itself. run.sh starts it twice per PHP image, each time
# sharing the PHP container's network namespace (`--network container:...`), so
# traffic goes over loopback with no Docker bridge in the path:
#   - nginx, listening on 127.0.0.1:8080 and passing *.php to php-fpm on :9000
#   - wrk, driving 127.0.0.1:8080 (php-fpm) or 127.0.0.1:80 (Apache mod_php)
#
#   docker build -f lab/bench/tools.Dockerfile -t howdah-bench-tools lab/bench
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx wrk ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["wrk", "--version"]
