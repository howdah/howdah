GoTestWAF v0.5.8 payloads, PHP 8.3.36 (php-fpm behind nginx), Howdah 1.3.0 at shipped defaults (Layer 2 in detect mode), run 2026-10-24T17:27:57Z.
"Flagged" = Howdah logged a Layer 2 event (sql_injection, path_traversal or command_injection) for that request.
"In scope" = the raw payload arrives where Layer 2 looks: plain or URL-encoded in the query string, urlencoded form or URL path, or plain in a multipart field.

| Payload class | GoTestWAF test cases | Flagged, all requests | Flagged, in scope |
|---|---|---|---|
| SQL injection | 7 | 1/65 (1.5%) | 1/23 (4.3%) |
| Path traversal / LFI | 3 | 5/30 (16.7%) | 5/12 (41.7%) |
| Command injection / RCE | 11 | 13/62 (21%) | 13/27 (48.1%) |
| Not a Layer 2 class (XSS, LDAP, NoSQL, SSTI, XXE, ...) | 22 | 7/517 (1.4%) | 7/195 (3.6%) |
| Benign (GoTestWAF false-pos set): false positives | 1 | 0/141 (0%) | 0/94 (0%) |

Per GoTestWAF test case:

| Test set | Test case | Layer 2 class | Sent | Reached PHP | Flagged | In scope flagged |
|---|---|---|---|---|---|---|
| community | community-128kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-128kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-128kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-16kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-16kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-16kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-32kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-32kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-32kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-64kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-64kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-64kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-8kb-rce | command_injection | 1 | 1 | 1/1 (100%) | 1/1 (100%) |
| community | community-8kb-sqli | sql_injection | 1 | 1 | 1/1 (100%) | 1/1 (100%) |
| community | community-8kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-lfi-multipart | path_traversal | 2 | 2 | 0/2 (0%) | 0/2 (0%) |
| community | community-lfi | path_traversal | 8 | 8 | 2/8 (25%) | 2/4 (50%) |
| community | community-rce-rawrequests | command_injection | 3 | 3 | 1/3 (33.3%) | 1/3 (33.3%) |
| community | community-rce | command_injection | 4 | 4 | 2/4 (50%) | 2/2 (100%) |
| community | community-sqli | sql_injection | 12 | 12 | 0/12 (0%) | 0/6 (0%) |
| community | community-user-agent | - | 9 | 9 | 0/9 (0%) | 0/0 (n/a) |
| community | community-xss | - | 104 | 104 | 4/104 (3.8%) | 4/52 (7.7%) |
| community | community-xxe | - | 2 | 2 | 0/2 (0%) | 0/0 (n/a) |
| false-pos | texts | benign | 141 | 141 | 0/141 (0%) | 0/94 (0%) |
| owasp | crlf | - | 7 | 7 | 0/7 (0%) | 0/7 (0%) |
| owasp | ldap-injection | - | 24 | 24 | 0/24 (0%) | 0/6 (0%) |
| owasp | mail-injection | - | 24 | 24 | 0/24 (0%) | 0/9 (0%) |
| owasp | nosql-injection | - | 50 | 50 | 0/50 (0%) | 0/15 (0%) |
| owasp | path-traversal | path_traversal | 20 | 20 | 3/20 (15%) | 3/6 (50%) |
| owasp | rce-urlparam | command_injection | 9 | 9 | 2/9 (22.2%) | 2/6 (33.3%) |
| owasp | rce-urlpath | command_injection | 3 | 3 | 3/3 (100%) | 3/3 (100%) |
| owasp | rce | command_injection | 6 | 6 | 0/6 (0%) | 0/0 (n/a) |
| owasp | shell-injection | command_injection | 32 | 32 | 4/32 (12.5%) | 4/8 (50%) |
| owasp | sql-injection | sql_injection | 48 | 48 | 0/48 (0%) | 0/12 (0%) |
| owasp | ss-include | - | 24 | 24 | 3/24 (12.5%) | 3/9 (33.3%) |
| owasp | sst-injection | - | 24 | 24 | 0/24 (0%) | 0/9 (0%) |
| owasp | xml-injection | - | 7 | 7 | 0/7 (0%) | 0/0 (n/a) |
| owasp | xss-scripting | - | 224 | 223 | 0/223 (0%) | 0/83 (0%) |
| owasp-api | graphql-post | - | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |
| owasp-api | graphql | - | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |
| owasp-api | grpc | - | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |
| owasp-api | non-crud | - | 2 | 2 | 0/2 (0%) | 0/0 (n/a) |
| owasp-api | rest | - | 7 | 7 | 0/7 (0%) | 0/0 (n/a) |
| owasp-api | soap | - | 5 | 5 | 0/5 (0%) | 0/0 (n/a) |

Layer 2 classes only, by where the payload was placed (all encodings):

| Placement | Flagged |
|---|---|
| JSON body | 0/29 (0%) |
| URL path | 4/15 (26.7%) |
| headers | 0/11 (0%) |
| multipart form | 0/31 (0%) |
| query string | 6/29 (20.7%) |
| urlencoded form | 9/42 (21.4%) |

Layer 2 classes only, by GoTestWAF encoder (all placements):

| Encoder | Flagged |
|---|---|
| Base64Flat | 0/50 (0%) |
| Plain | 1/11 (9.1%) |
| URL | 18/96 (18.8%) |
