# Contributing

Install runtimes and analysers, then install the Git hooks:

```sh
mise install
mise run hooks # runs lefthook install
```

Use a **disposable** PostgreSQL or MySQL database. Tests drop/recreate `ogiri_sessions` and `ogiri_subject_locks`; never use a valuable database. Keep the existing test environment variables:

```sh
export OGIRI_TEST_DATABASE=postgresql # or mysql
export OGIRI_TEST_JDBC_URL=jdbc:postgresql://localhost:5432/ogiri_test
export OGIRI_TEST_JDBC_USER=ogiri
export OGIRI_TEST_JDBC_PASSWORD=ogiri
mise run check       # fast repository + platform gates; target under 120 seconds
mise run check:full  # database/consumer tests, SBOM/OSV, release rehearsal and parity
mise run fix        # formatters and safe lint fixes
```

The Java fast check is `mvn verify` and needs the database. The Python suite in `contracts/conformance/` tests the Spring application's HTTP protocol and compatibility with the pinned Rails reference. `check:full` also uses `psql`/`mysql` and `unzip` for the packaged-schema rehearsal. CI provides isolated database services; never run suites concurrently against the same schema.

Pre-commit runs `mise run check:staged`: gitleaks, workflow/shell checks, whitespace and Java formatting against staged snapshots. It never formats unstaged files. Pre-push runs `mise run check`. Gitleaks scans the checkout's complete reachable history; `.github/.gitleaksignore` records only exact historical documentation/test-fixture fingerprints with reasons. New secret findings fail the gate.

Spring build commands live in `scripts/platform/java.sh`; HTTP conformance commands live in `scripts/platform/parity.sh`. Keep task names and CI routing aligned with these scripts. The conformance runner owns its service startup and teardown.

The standalone Spring example resolves freshly built POMs/JARs from `target/java/consumer-cache`, using the shared Maven cache only as a read-only dependency repository. No gate runs `mvn install`. CI retains Java 17/25 and PostgreSQL/MySQL, selects expensive jobs by changed paths, and always reports `quality-gates`. Scheduled/manual runs, PRs marked ready for review and the `full-ci` label select every lane.

Each test needs a material contract, stable seam, independent oracle, plausible wrong implementation and coverage gap. Preserve real SQL/concurrency tests. Do not add getter tests, private call-order mocks, sleeps-as-clocks or coverage quotas. Mock external faults only when real failures cannot be induced reliably. A smaller implementation that transfers shared security work to every consumer is not a simplification.

Keep ordinary guidance here, in README/Javadoc or SECURITY. Reports/temporary mutation evidence belong in CI/PR artifacts, not a permanent audit archive. Make coherent logical commits and non-force pushes.

## Performance and dependencies

After tests create the disposable schema, run the storage benchmark explicitly:

```sh
mise run check:java:benchmark
```

It seeds 10,000 rows, warms the path, then measures one and eight concurrent readers through Hikari. Output is `ogiri/target/benchmark-<database>.json`. This measures local storage authentication, not password login, account-directory latency, HTTP or production capacity. It has no pass/fail latency threshold. It uses the disposable test variables and removes only its benchmark realm's rows.

Generate a resolved runtime SBOM for scanning with the official OSV scanner:

```sh
mise run check:java:sbom
```

Do not suppress a vulnerability to make CI green. Distinguish database errors/unavailable advisory services from a completed clean scan. New database claims require the same behavioural tests, not H2 compatibility mode.
