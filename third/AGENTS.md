# third — Vendored Upstream Code

This directory holds vendored copies of upstream Go packages, with local
patches applied on top. Each vendored package tracks a specific upstream
commit recorded in its `commit.txt`.

Current contents:

- `ssh/` — vendored from `golang.org/x/crypto/ssh` (upstream repo
  `github.com/golang/crypto`). Current version recorded in
  `ssh/commit.txt`.

## ssh

### What is vendored

The entire `ssh/` directory of `golang.org/x/crypto`, plus two packages
that upstream keeps under `crypto/internal/` but that `ssh` depends on:

- `ssh/internal/poly1305/` — vendored from `internal/poly1305/`
- `ssh/internal/testenv/` — vendored from `internal/testenv/`

These two are placed under `ssh/internal/` so they resolve locally
instead of pulling the external `golang.org/x/crypto` module.

### Local patches

Three categories of local modifications are layered on top of upstream.
They must be re-applied (or confirmed intact) every time the vendored
copy is updated.

#### 1. Import path rewrite

All imports under `golang.org/x/crypto/ssh...` and the two vendored
`golang.org/x/crypto/internal/{poly1305,testenv}` are rewritten to the
local module path:

| Upstream import | Local import |
|---|---|
| `golang.org/x/crypto/ssh` | `github.com/hugefiver/fakessh/third/ssh` |
| `golang.org/x/crypto/ssh/<sub>` | `github.com/hugefiver/fakessh/third/ssh/<sub>` |
| `golang.org/x/crypto/internal/poly1305` | `github.com/hugefiver/fakessh/third/ssh/internal/poly1305` |
| `golang.org/x/crypto/internal/testenv` | `github.com/hugefiver/fakessh/third/ssh/internal/testenv` |

This rewrite covers both import statements and comments that reference
the package path.

Imports of other `golang.org/x/crypto/*` sub-packages that are **not**
vendored here (e.g. `chacha20`, `curve25519`, `blowfish`, `cryptobyte`,
`sha3`) are left untouched; they resolve through the module graph
normally.

One exception: `ssh/internal/poly1305/_asm/sum_amd64_asm.go` contains
`Package("golang.org/x/crypto/internal/poly1305")` as a code-generation
target string. This is **not** rewritten — it identifies the upstream
package the assembly is generated for.

#### 2. poly1305 vendored as ssh/internal/poly1305

`cipher.go` and `cipher_test.go` import the vendored copy instead of
the upstream internal package:

```go
"github.com/hugefiver/fakessh/third/ssh/internal/poly1305"
// upstream original: "golang.org/x/crypto/internal/poly1305"
```

This is part of the import path rewrite (rule 1) and is covered by the
same substitution.

#### 3. fakessh functional patches

`server.go` and `transport.go` carry custom features not present
upstream:

- `ServerConfig.AsOpenSSH bool` — switches to an OpenSSH-compatible
  version exchange (`exchangeVersionsOpenSSH`).
- `ServerConfig.CheckClientVersion func(version []byte) bool` — custom
  callback to validate the client version string.
- `exchangeVersionsOpenSSH` / `readVersionOpenSSH` / `errInvalidChar` in
  `transport.go` — stricter version-line parsing mirroring OpenSSH.
- Version precheck logic in `serverHandshake` (major/minor, version
  format validation).

These patches live in `server.go` and `transport.go` only. They must be
preserved across upgrades. When the upstream diff touches these files,
merge manually and keep the local additions.

### commit.txt

`ssh/commit.txt` records the upstream version this copy is synced to:

```
<full commit hash>
<commit date in UTC, format: %a %b %e %H:%M:%S %Y +TZ>
tag: v<semver>
```

No trailing newline. Update this file whenever you sync a new version.

### How to update

Prerequisites: `git`, `go`.

1. **Check the current version.**

   ```powershell
   Get-Content third/ssh/commit.txt
   ```

   The last line `tag: v0.X.0` is the currently synced version.

2. **Find the target version.** The latest tag is what `go.mod` already
   requires (dependabot bumps it). Confirm:

   ```powershell
   Select-String -Path go.mod -Pattern 'golang.org/x/crypto'
   ```

3. **Clone the upstream repo and fetch both tags.**

   ```powershell
   $tmp = "$env:TEMP\opencode\crypto-upstream"
   git clone --depth 1 --branch v0.54.0 https://github.com/golang/crypto.git $tmp
   git -C $tmp fetch --depth 1 origin tag v0.53.0   # the OLD tag from commit.txt
   ```

   Replace the tag names with the old (from `commit.txt`) and new
   (target) versions.

4. **Generate the upstream diff for the ssh/ directory.**

   ```powershell
   git -C $tmp diff v0.53.0 v0.54.0 -- ssh/ > "$env:TEMP\opencode\upgrade.patch"
   ```

   This produces a patch containing **only** upstream changes between
   the two versions, with path prefixes `a/ssh/` and `b/ssh/`.

5. **Rewrite path prefixes** from `ssh/` to `third/ssh/` so the patch
   applies to the local tree:

   ```powershell
   $p = Get-Content "$env:TEMP\opencode\upgrade.patch" -Raw
   $p = $p -replace 'a/ssh/', 'a/third/ssh/' -replace 'b/ssh/', 'b/third/ssh/'
   Set-Content -Path "$env:TEMP\opencode\upgrade-renamed.patch" -Value $p -NoNewline
   ```

6. **Dry-run the patch.**

   ```powershell
   git apply --check --verbose "$env:TEMP\opencode\upgrade-renamed.patch"
   ```

   If a hunk fails because its context line references
   `golang.org/x/crypto/ssh` (which has been rewritten to the local
   path), edit that context line in the patch file to match the local
   import path `github.com/hugefiver/fakessh/third/ssh`, then re-check.
   Re-run `--check` until all files pass.

   If a hunk fails inside `server.go` or `transport.go`, the local
   functional patch is in the way — merge that hunk manually and keep
   the local additions intact.

7. **Apply the patch.**

   ```powershell
   git apply --verbose "$env:TEMP\opencode\upgrade-renamed.patch"
   ```

8. **Update `third/ssh/commit.txt`** with the new version's commit
   metadata:

   ```powershell
   git -C $tmp log -1 --format="%H%n%cd" v0.54.0
   ```

   Write the output followed by `tag: v0.54.0` as the third line. No
   trailing newline.

9. **Verify.**

   ```powershell
   go build ./...
   go test ./third/ssh/...
   ```

   Both must pass. The full test suite under `third/ssh/` exercises
   `ssh`, `agent`, `bcrypt_pbkdf`, `poly1305`, `knownhosts`, and `test`.

10. **Clean up.** Remove the temporary clone and patch files.

### Why not `go mod replace`?

A commented-out `replace` directive exists in `go.mod`:

```
// replace golang.org/x/crypto => ./third/crypto
```

The project intentionally vendors only `ssh/` (and its two internal
deps) rather than the whole `crypto` module, and rewrites import paths
so the vendored copy is used directly without a `replace` directive.
Keep it this way unless the vendoring strategy changes.
