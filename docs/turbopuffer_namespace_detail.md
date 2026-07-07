# turbopuffer: Namespace Detail

Pick a namespace to see its size, freshness, encryption, and — most importantly — whether tenant isolation is *enforceable*: every required ACL attribute must exist and be filterable, or query-time filters silently cannot apply.

The schema table marks which attributes are search-amplified (BM25/regex/glob/fuzzy) — flags you don't want on sensitive fields.
