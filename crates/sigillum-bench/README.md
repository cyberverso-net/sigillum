# sigillum-bench

Benchmarks for sigillum, used to record performance baselines for goal G4 of the [charter](../../docs/project/charter.md). The crate is not published.

The benchmarks use [criterion](https://crates.io/crates/criterion) and live in `benches/`. Until sigillum has signing and parsing code, `benches/placeholders.rs` measures a single pass over inputs of 1 MB and 20 MB (1 MB being 1,000,000 bytes, as in the [measurement protocol](../../docs/project/measurements.md)), under the group names `signing` and `parsing`. The names are provisional; each placeholder is replaced by the real operation as it is implemented.

## Running the benchmarks

```
cargo bench -p sigillum-bench
```

Criterion writes its results under `criterion/` in the Cargo target directory, by default `target/criterion/`. A benchmark name can be given to run a subset, for example `cargo bench -p sigillum-bench -- signing`.

## Recording a baseline

A baseline is a named set of results kept for later comparison.

1. Run the benchmarks on the machine whose results are to be recorded, with no other load, and save them under a name that identifies the machine and the commit:

   ```
   cargo bench -p sigillum-bench -- --save-baseline <name>
   ```

2. Record the machine, operating system, Rust version and commit with the baseline name, wherever the figures are reported, for example in the pull request that reports them.
3. To compare a later change with the baseline, run on the same machine:

   ```
   cargo bench -p sigillum-bench -- --baseline <name>
   ```

   Criterion reports, for each benchmark, whether performance changed beyond its noise threshold. The comparison fails if a selected benchmark has no result saved under that name, for example after a placeholder is renamed; `--baseline-lenient` skips such benchmarks instead.

Baselines stay in the target directory and are not committed, because results depend on the machine. The figures that set or check the G4 targets are recorded in the [measurement protocol](../../docs/project/measurements.md), not here.

## Running in continuous integration

The "Benchmarks" workflow runs the benchmarks on demand, from the Actions tab or with `gh workflow run benchmarks.yml`. It saves a baseline under the name given when it is started and keeps `target/criterion/` as an artefact for 30 days. Shared runners are noisy and vary between runs, so these results confirm that the benchmarks run and give indicative figures only; they are not compared with each other or used as reference figures.
