-- wrk script for lab/bench/run.sh. The request shape comes from the
-- environment so one script serves every workload:
--   BENCH_METHOD  GET or POST (default GET)
--   BENCH_BODY    path of a request body file (optional)
--   BENCH_CTYPE   Content-Type of that body (optional)
-- At the end it prints one machine-readable line, "BENCHJSON {...}", with the
-- request count, errors and latency percentiles in microseconds.
local method = os.getenv("BENCH_METHOD") or "GET"
local body = os.getenv("BENCH_BODY") or ""
local ctype = os.getenv("BENCH_CTYPE") or ""

wrk.method = method
if body ~= "" then
  local f = assert(io.open(body, "rb"))
  wrk.body = f:read("*a")
  f:close()
end
if ctype ~= "" then
  wrk.headers["Content-Type"] = ctype
end

done = function(summary, latency, requests)
  local e = summary.errors
  io.write(string.format(
    'BENCHJSON {"requests":%d,"duration_us":%d,"bytes":%d,' ..
    '"errors":{"connect":%d,"read":%d,"write":%d,"status":%d,"timeout":%d},' ..
    '"latency_us":{"min":%d,"mean":%.2f,"stdev":%.2f,"p50":%d,"p90":%d,"p99":%d,"max":%d}}\n',
    summary.requests, summary.duration, summary.bytes,
    e.connect, e.read, e.write, e.status, e.timeout,
    latency.min, latency.mean, latency.stdev,
    latency:percentile(50), latency:percentile(90), latency:percentile(99), latency.max))
end
