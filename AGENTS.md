# fakessh maintenance rules

## Ownership boundary

- Fix application behavior in the first-party root packages and `modules/`.
- `third/` contains synchronized upstream code plus maintained local feature
  patches. Do not repair, refactor, reformat, or add tests there as part of an
  ordinary application fix. Changes to vendored code require an explicitly
  authorized upstream synchronization or local-patch task.
- Documentation changes to `third/AGENTS.md` may maintain these rules without
  changing vendored source, fixtures, or `third/ssh/commit.txt`.
- Record vendored findings in [docs/security-review.md](docs/security-review.md)
  instead of silently implementing a new downstream patch. First-party
  mitigations do not prove a vendored defect is fixed.

## Every upstream synchronization

Read `third/AGENTS.md` and the upstream finding register in
`docs/security-review.md`. Recheck **every** tracked finding, including findings
previously marked fixed, against the target revision and the merged local
patches. Record the checked version/date, status, source or regression evidence,
and remaining action. If evidence is unavailable, record that explicitly;
never infer a fix from a version bump or a passing general test suite.

## Verification

Use the relevant regression tests, then `go test ./...`, `go vet ./...`, and
`go test -tags "no_gitserver no_fakeshell" ./...` for integrated changes. Run
race checks for concurrency changes where supported. Unix identity changes,
process groups, and FIFO behavior need Unix execution evidence; cross-compiling
their tests is useful but is not a runtime pass. Do not install missing tools
or change Git state without the user's authorization.
