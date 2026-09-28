# Contributing

Currently a single-maintainer research repository. The review rules below apply
to the maintainer's own work too — the point of writing them down is that
self-review is the easiest kind to skip.

## Ground rules

**No unreviewed pushes to `main`.** Everything goes through a PR, including
maintainer commits. Branch protection enforces this; see `docs/repo-setup.md`.

**Conventional commits.** PR titles follow the [Conventional Commits][cc] spec:
`feat(filter): ...`, `fix(policy): ...`, `docs: ...`, `test: ...`,
`chore(deps): ...`. This matches rust-libp2p's own convention, which matters if
any of this is ever upstreamed.

**Squash merge.** One logical change per PR, one commit on `main`.

**CI is self-service.** `make all` runs what CI runs. Fix it before requesting
review, not after.

## Review checklist

Every PR, including your own:

- [ ] `make all` passes locally
- [ ] New behaviour has a test; new *measurement* behaviour has a test that
      would fail if the measurement were wrong, not just if it crashed
- [ ] Public items have doc comments explaining *why*, not restating the
      signature
- [ ] Anything depending on rust-libp2p internals says so in a comment, with
      the version it was verified against
- [ ] `CHANGELOG.md` updated for user-facing changes
- [ ] No result number is quoted anywhere without a committed file in
      `docs/results/` behind it

## Measurement changes are held to a higher bar

A bug in the filter produces a wrong defence. A bug in the measurement produces
a wrong *belief* about the defence, which is worse and much harder to notice.

If a PR changes how anything in `src/metrics.rs` or `src/testbed.rs` is
computed:

- state in the PR description what the number was before and after
- explain why the new value is more correct, not just different
- if it changes a result already published, say so explicitly and update
  `CHANGELOG.md` under a `Corrected` heading

Changing `docs/methodology.md` after results exist requires a stated reason in
the changelog. The document is pre-registered on purpose.

## Dependencies

`libp2p` is pinned to a minor version and the code depends on documented *and
undocumented* behaviour of `libp2p-kad`. Bumping it is a reviewed change, not a
dependabot auto-merge — see `.github/dependabot.yml`, which deliberately
excludes it.

Do not add `libp2p-identity` as a direct dependency. See the note in
`Cargo.toml`.

[cc]: https://www.conventionalcommits.org/en/v1.0.0/
