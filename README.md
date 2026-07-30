# npm-audit

A small Rust CLI that wraps `npm audit --json` and renders the results as a
readable, colored, severity-sorted report instead of raw JSON.

_Built while learning Rust, with Claude Code as a pair-programming assistant._

## Why

`npm audit`'s default output is fine but its `--json` output is what you
actually want to build on — except it's unreadable directly. This tool
shells out to `npm audit --json` (plus `npm outdated --json` and `npm ls
--json` for extra context), deserializes the (fairly messy) output into
typed Rust structs, and prints something a human can scan in a few seconds:
severity first, the exact fix command, installed/latest versions, the
dependency chain that pulled the vulnerable package in, and advisory links.

## Install / run

Requires Rust (2024 edition) and `npm` on your `PATH`.

```bash
git clone https://github.com/MatthieuELIE/npm-audit.git
cd npm-audit
cargo build --release
```

Run it from inside any npm project:

```bash
./target/release/npm-audit
# or during development
cargo run -- --severity high
```

## Usage

```
npm-audit [OPTIONS]

Options:
  -s, --severity <SEVERITY>  Only show vulnerabilities at or above this level
                              [possible values: info, low, moderate, high, critical]
  -h, --help                 Print help
  -V, --version               Print version
```

Example output:

```
[CRITICAL] lodash (>= 4.0.0) [direct]
Fix: npm install lodash@4.17.21 (major bump)
Outdated: installed: 4.0.0, latest: 4.17.21
Advisory: Prototype Pollution in lodash (>= 4.0.0)
  https://github.com/advisories/GHSA-xxxx-xxxx-xxxx

Found 🔴 1 Critical, (Total: 1)!
```

Transitive dependencies also get their pull-in path(s):

```
[HIGH] semver (< 6.3.1) [indirect]
Fix: no fix available
Path: react-scripts → resolve-url-loader → semver
Advisory: ReDoS in semver (< 6.3.1)
  https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
```

## Technical notes

- **Errors** — `anyhow::Context` wraps every fallible step (`npm audit`
  failing to run, malformed JSON) with a message that says what actually
  went wrong, instead of a bare `serde_json` error.
- **Severity is a real type** — `Severity` derives `Ord`/`PartialOrd` in
  declared order (`Info < Low < Moderate < High < Critical`), so filtering
  and sorting by severity is just `>=` and `.sort_by()`, not string
  comparisons. It also doubles as a `clap::ValueEnum`, so `--severity` gets
  validation and `--help` text for free.
- **`npm audit`'s JSON isn't uniform** — `fixAvailable` is either `false` or
  an object describing the fix, and `via` entries are either advisory objects
  or plain strings. Both are modeled as `#[serde(untagged)]` enums
  (`FixAvailable`, `Via`) rather than pre-processing the JSON by hand.
- **`is_direct: bool` → `DependencyType` enum** — a `From<bool>` impl paired
  with `#[serde(from = "bool")]` converts npm's boolean straight into a
  named `Direct`/`Indirect` enum at deserialization time, so the rest of the
  codebase never touches a bare bool.
- **No JSON string round-tripping** — `serde_json::from_slice` deserializes
  the command's stdout bytes directly into `AuditReport`, skipping an
  intermediate `String`/`Value` step.
- **Dependency chains come from `npm ls`, not `npm audit`** — `npm audit`'s
  own `nodes`/`effects` fields reflect physical install location (hoisted by
  npm), not the logical require chain, so they're usually a flat, useless
  path even for indirect dependencies. One `npm ls --all --json` call per run
  walks the real installed tree instead, and reports every path for a
  package pulled in more than once (diamond dependencies).
- **`npm outdated`/`npm ls` failures degrade gracefully** — a missing
  `node_modules`, desynced lockfile, or non-zero exit from either command
  just means that run's extra context (installed/latest version, dependency
  path) is omitted, with a warning on stderr. The audit results themselves
  never depend on either succeeding.

## Stack

`clap` (derive) for args, `serde`/`serde_json` for deserialization, `anyhow`
for error context, `colored` for terminal output.

## License

[MIT](LICENSE)
