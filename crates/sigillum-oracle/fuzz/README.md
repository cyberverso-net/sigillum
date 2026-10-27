# Fuzz targets of sigillum-oracle

The target `summary` feeds arbitrary text to the reader of `summary.json`, `Summary::parse`, and to the comparisons. A summary that parses is read for its result, compared with an expected indication, and must contain its own members and be identical to itself. The two halves of the text are then read as two JSON values, and every difference that `identical` and `differences` report between them must name, by its pointer, the values that it reports. It needs the nightly toolchain and `cargo-fuzz`:

```
cargo +nightly fuzz run summary corpus/summary seeds/summary -- -dict=summary.dict -max_total_time=600
```

`seeds/summary` holds the summaries of the seeds of the target `dss_output` of `sigillum-testpki`, which `tools/dss-oracle` wrote for the corpus, and `pair`, two JSON values of the same length that differ in members whose names need escaping in a pointer. `summary.dict` holds the members and values of `summary.json` and the syntax of JSON and of pointers.
