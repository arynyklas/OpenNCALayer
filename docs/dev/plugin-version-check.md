# `cargo xtask plugin-version-check`

For anyone who changes a plugin port in `plugins/`. It tells you when you changed a port but forgot to raise its version.

## Why it exists

A plugin release is decided by the plugin's version. `cargo xtask plugin pending` only compares that version with the `beta` index. So if you change a port's code but keep its version, one of two things happens: the release skips the port, or its package no longer matches what the index says. This check catches that.

## What it does

It compares your working tree with the last release tag named `plugins-*` that is reachable from `HEAD` (found with `git describe --tags --match 'plugins-*'`).

For every port that already existed at that tag, the check reports the port, and exits with status 1, when both of these are true:
- `plugin.toml` still has the version it had at the tag;
- at least one of `plugins/<port>/plugin.toml`, `plugins/<port>/Cargo.toml` or `plugins/<port>/src/` differs from the tag.

Fix it by raising the port's version in `Cargo.toml` and `plugin.toml`.

These are not errors:
- a changed `registry.toml`;
- a port that is new since the tag;
- a change in the shared crates.

Whether the versions in `Cargo.toml` and `plugin.toml` agree is checked by `plugin pack`, not by this command.

## When there is no tag

Without a `plugins-*` tag in your checkout, the command prints `NOTICE: no tag matching plugins-* ...` and exits with status 0. A shallow clone without tags therefore checks nothing.

## Where it runs

- In CI: the `test` job in `.github/workflows/ci.yml` checks out the full history with tags (`fetch-depth: 0`) and runs the check on Linux, after the plugin operations lint.
- Locally: run it before you bump versions for a release. The release steps are in [`release.md`](release.md), section 7а.
